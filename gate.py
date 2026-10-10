# /// script
# requires-python = ">=3.11"
# dependencies = ["aiohttp>=3.9", "pystray>=0.19", "pillow>=10"]
# ///
"""Approval gate between cloud Claude and this laptop, with one backend per thing it guards.

    claude.ai --> cloudflared --> mcp-windows.louietyj.me --> :9340  --> windows-mcp       (mcp_windows.py)
                              --> browser.louietyj.me     --> :19870 --> pinchtab bridge   (pinchtab_windows.py)

A backend's own credential (the connector bearer, the browser gate key) only lets
a caller ask. Doing anything needs a grant, and only Louie's click in the approval
dialog creates one. Grants live only in memory, are scoped to their backend and
lapse when idle or at a cap; the tray icon and its window list and revoke them.

The gate supervises its children (windows-mcp, the pinchtab bridge, and with
--tunnel `cloudflared tunnel run`) in a kill-on-close job object, so they die
with it.
"""
import argparse
import asyncio
import collections
import ctypes
import ctypes.wintypes as wt
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import pathlib
import queue
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import pystray
from PIL import Image, ImageDraw

DATA = pathlib.Path(os.environ["LOCALAPPDATA"]) / "mcp-windows-gate"
DATA.mkdir(parents=True, exist_ok=True)
AUDIT = DATA / "audit.jsonl"

log = logging.getLogger("gate")


# --------------------------------------------------------------------------- grants

@dataclasses.dataclass
class Grant:
    id: str
    backend: str
    purpose: str
    origin: str  # the caller's IP, or the agent name it gave
    idle: int
    cap: int
    created: float
    last_used: float
    code: str = ""
    calls: int = 0

    @property
    def short(self):
        return self.id[:7] + "…"


class Grants:
    def __init__(self):
        self.lock = threading.Lock()
        self.live: dict[str, Grant] = {}
        self.paused = False
        self.on_change = lambda: None

    def _changed(self):
        # The tray redraw must never fail a request that is granting or using access.
        try:
            self.on_change()
        except Exception:
            log.exception("tray refresh failed")

    def _expiry(self, g, now):
        if now - g.created > g.cap:
            return f"grant {g.short} hit its {g.cap // 60} min cap"
        if now - g.last_used > g.idle:
            return f"grant {g.short} lapsed after {g.idle // 60} min idle"
        return None

    def use(self, gid, backend):
        """Return (grant, None) if gid is live for backend, else (None, reason)."""
        if not gid:
            return None, "no grant"
        if self.paused:
            return None, "Louie has paused the gate"
        now = time.time()
        with self.lock:
            g = next((g for k, g in self.live.items() if hmac.compare_digest(k, gid)), None)
            if g is None or g.backend != backend:
                return None, "unknown or revoked grant"
            why = self._expiry(g, now)
            if why:
                del self.live[g.id]
            else:
                g.last_used = now
                g.calls += 1
        if why:
            audit(backend=g.backend, event="grant_expired", purpose=g.purpose, why=why)
            self._changed()
            return None, why
        return g, None

    def create(self, backend, purpose, origin, idle, cap, code=""):
        now = time.time()
        g = Grant("g_" + secrets.token_urlsafe(18), backend, purpose, origin, idle, cap, now, now, code)
        with self.lock:
            self.live[g.id] = g
        self._changed()
        return g

    def revoke(self, gid=None, backend=None, why="revoked"):
        """Revoke one grant, a backend's, or (no arguments) every one."""
        with self.lock:
            doomed = [g for k, g in self.live.items()
                      if (gid is None or k == gid) and (backend is None or g.backend == backend)]
            for g in doomed:
                del self.live[g.id]
        for g in doomed:
            audit(backend=g.backend, event="grant_" + why, purpose=g.purpose)
        self._changed()
        return len(doomed)

    def sweep(self):
        now = time.time()
        with self.lock:
            dead = [(g, self._expiry(g, now)) for g in self.live.values() if self._expiry(g, now)]
            for g, _ in dead:
                del self.live[g.id]
        for g, why in dead:
            audit(backend=g.backend, event="grant_expired", purpose=g.purpose, why=why)
        if dead:
            self._changed()

    def snapshot(self, backend=None):
        with self.lock:
            gs = [dataclasses.replace(g) for g in self.live.values() if backend is None or g.backend == backend]
        return sorted(gs, key=lambda g: g.created)


def fingerprint(gid):
    return hashlib.sha256(gid.encode()).hexdigest()[:8] if gid else None


# The window's activity list; audit.jsonl keeps everything.
RECENT: collections.deque = collections.deque(maxlen=300)


def audit(**rec):
    rec = {"t": time.strftime("%Y-%m-%d %H:%M:%S"), **rec}
    RECENT.appendleft(rec)
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def ago(t):
    m = int((time.time() - t) // 60)
    return f"{m} min" if m else "<1 min"


def activity_row(rec, core):
    detail = rec.get("tool") or " ".join(x for x in (rec.get("method"), rec.get("path")) if x) or rec.get("purpose") or ""
    if rec.get("args"):
        detail += "  " + rec["args"]
    result = rec.get("decision") or rec.get("status") or rec.get("error") or rec.get("why") or ""
    return rec.get("t", ""), core.label(rec.get("backend", "")), rec.get("event", ""), detail[:300], str(result)


def load_secret(name):
    """A per-backend credential, generated once and kept in DATA."""
    path = DATA / name
    if not path.exists():
        path.write_text(secrets.token_urlsafe(32), encoding="ascii")
    return path.read_text(encoding="ascii").strip()


# --------------------------------------------------------------------------- children

class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BasicLimit(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wt.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wt.DWORD),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", wt.DWORD), ("SchedulingClass", wt.DWORD),
    ]


class _ExtendedLimit(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimit), ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class KillOnCloseJob:
    """Children assigned here die when the gate exits, however it exits."""

    def __init__(self):
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wt.HANDLE
        k32.OpenProcess.restype = wt.HANDLE
        self.k32 = k32
        self.job = k32.CreateJobObjectW(None, None)
        info = _ExtendedLimit()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        k32.SetInformationJobObject(wt.HANDLE(self.job), 9, ctypes.byref(info), ctypes.sizeof(info))

    def add(self, pid):
        h = self.k32.OpenProcess(0x0101, False, pid)  # PROCESS_SET_QUOTA | PROCESS_TERMINATE
        if h:
            self.k32.AssignProcessToJobObject(wt.HANDLE(self.job), wt.HANDLE(h))
            self.k32.CloseHandle(wt.HANDLE(h))


PIDFILE = DATA / "gate.pid"


def _creation_time(k32, handle):
    times = [wt.FILETIME() for _ in range(4)]
    if not k32.GetProcessTimes(wt.HANDLE(handle), *(ctypes.byref(t) for t in times)):
        return None
    return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime


def replace_previous():
    """Terminate the previous gate (a task stop kills only the uvw launcher), then record ourselves.

    The pid file pairs PID with creation time, so a recycled PID never matches.
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wt.HANDLE
    try:
        pid, created = (int(x) for x in PIDFILE.read_text().split())
    except (OSError, ValueError):
        pid = None
    if pid and pid != os.getpid():
        h = k32.OpenProcess(0x1001, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE
        if h:
            if _creation_time(k32, h) == created:
                log.info("terminating previous gate (pid %s)", pid)
                k32.TerminateProcess(wt.HANDLE(h), 1)
                k32.WaitForSingleObject(wt.HANDLE(h), 5000)
            k32.CloseHandle(wt.HANDLE(h))
    me = k32.OpenProcess(0x1000, False, os.getpid())
    PIDFILE.write_text(f"{os.getpid()} {_creation_time(k32, me)}")
    k32.CloseHandle(wt.HANDLE(me))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def supervise(name, argv, job):
    """Run argv forever, restarting it if it dies."""
    logf = (DATA / f"{name}.log").open("ab")
    while True:
        log.info("starting %s", name)
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=logf, stderr=logf, creationflags=subprocess.CREATE_NO_WINDOW)
        job.add(proc.pid)
        rc = await proc.wait()
        log.warning("%s exited with %s; restarting in 3 s", name, rc)
        await asyncio.sleep(3)


# --------------------------------------------------------------------------- UI

@dataclasses.dataclass
class DialogReq:
    heading: str
    purpose: str
    origin: str
    note: str
    code: str
    hold: int
    loop: asyncio.AbstractEventLoop
    fut: asyncio.Future
    win: tk.Toplevel | None = None


class UI:
    """Tk on the main thread; everything else posts to it through self.q."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.q: queue.Queue = queue.Queue()
        self.root.after(100, self._pump)
        self.window = None

    def post(self, *cmd):
        self.q.put(cmd)

    def _pump(self):
        try:
            while True:
                cmd, *rest = self.q.get_nowait()
                getattr(self, "_do_" + cmd)(*rest)
        except queue.Empty:
            pass
        self.root.after(100, self._pump)

    async def ask(self, heading, purpose, origin, note, hold, code=""):
        """True (allowed), False (denied) or None (unanswered within hold seconds)."""
        loop = asyncio.get_running_loop()
        req = DialogReq(heading, purpose, origin, note, code, hold, loop, loop.create_future())
        self.post("dialog", req)
        try:
            return await asyncio.wait_for(asyncio.shield(req.fut), hold)
        except asyncio.TimeoutError:
            return None
        finally:
            if not req.fut.done():
                self.post("close", req)

    def _decide(self, req, value):
        def set_():
            if not req.fut.done():
                req.fut.set_result(value)
        req.loop.call_soon_threadsafe(set_)
        self._do_close(req)

    def _do_close(self, req):
        if req.win is not None:
            req.win.destroy()
            req.win = None

    def _do_dialog(self, req):
        w = tk.Toplevel(self.root)
        req.win = w
        w.title("Gate: grant access?")
        w.attributes("-topmost", True)
        w.resizable(False, False)
        w.protocol("WM_DELETE_WINDOW", lambda: self._decide(req, False))
        w.bind("<Escape>", lambda e: self._decide(req, False))

        pad = {"padx": 14, "pady": (10, 0), "anchor": "w"}
        tk.Label(w, text=req.heading, font=("Segoe UI", 13, "bold")).pack(**pad)
        tk.Label(w, text=f"from {req.origin} at {time.strftime('%H:%M:%S')}",
                 font=("Segoe UI", 9), fg="#555").pack(padx=14, anchor="w")
        txt = tk.Text(w, width=72, height=min(8, 2 + len(req.purpose) // 70),
                      font=("Segoe UI", 10), wrap="word", relief="solid", borderwidth=1)
        txt.insert("1.0", req.purpose[:2000])
        txt.configure(state="disabled")
        txt.pack(padx=14, pady=8, fill="x")
        if req.code:
            tk.Label(w, text=f"Code  {req.code}", font=("Consolas", 18, "bold")).pack(padx=14, anchor="w")
            tk.Label(w, text="It must match the code Claude wrote in the chat.",
                     font=("Segoe UI", 9), fg="#555").pack(padx=14, anchor="w")
        tk.Label(w, text=req.note + " Only allow a request you just made.",
                 font=("Segoe UI", 9), wraplength=520, justify="left").pack(padx=14, pady=(8, 0), anchor="w")

        row = tk.Frame(w)
        row.pack(fill="x", padx=14, pady=12)
        left = tk.Label(row, font=("Segoe UI", 9), fg="#555")
        left.pack(side="left")
        deny = tk.Button(row, text="Deny", width=10, command=lambda: self._decide(req, False))
        deny.pack(side="right")
        tk.Button(row, text="Allow", width=10, command=lambda: self._decide(req, True)).pack(side="right", padx=8)

        deadline = time.monotonic() + req.hold

        def tick():
            if req.win is None:
                return
            remaining = int(deadline - time.monotonic())
            if remaining <= 0:
                self._do_close(req)
                return
            left.configure(text=f"Auto-deny in {remaining} s")
            w.after(1000, tick)
        tick()
        w.update_idletasks()
        x = (w.winfo_screenwidth() - w.winfo_width()) // 2
        y = (w.winfo_screenheight() - w.winfo_height()) // 3
        w.geometry(f"+{x}+{y}")
        w.lift()
        w.focus_force()
        # Space activates the focused button: a keystroke meant for another window
        # as this one grabs focus must deny, never allow.
        deny.focus_set()
        w.bell()

    def _do_copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _do_window(self, core):
        """The status window: what has access, what it did, and buttons to stop it."""
        if self.window is not None and self.window.winfo_exists():
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()
            return
        w = self.window = tk.Toplevel(self.root)
        w.title("Gate")
        w.geometry("1000x620")
        w.minsize(760, 440)
        pad = {"padx": 12, "anchor": "w"}

        header = tk.Label(w, font=("Segoe UI", 12, "bold"))
        header.pack(pady=(10, 2), **pad)
        status_rows = []
        for b in core.backends:
            row = tk.Frame(w)
            row.pack(fill="x", padx=12, pady=1)
            label = tk.Label(row, font=("Segoe UI", 9), anchor="w")
            label.pack(side="left")
            buttons = []
            for text, action, enabled in b.actions():
                btn = ttk.Button(row, text=text, command=action)
                btn.pack(side="right", padx=2)
                buttons.append((btn, enabled))
            status_rows.append((b, label, buttons))

        tk.Label(w, text="Live grants", font=("Segoe UI", 10, "bold")).pack(pady=(10, 2), **pad)
        cols = {"backend": 90, "origin": 120, "code": 55, "purpose": 420, "age": 70, "idle": 70, "calls": 55}
        grants_tv = ttk.Treeview(w, columns=list(cols), show="headings", height=6)
        for c, width in cols.items():
            grants_tv.heading(c, text=c.capitalize())
            grants_tv.column(c, width=width, stretch=c == "purpose")
        grants_tv.pack(fill="x", padx=12)

        row = tk.Frame(w)
        row.pack(fill="x", padx=12, pady=6)
        ttk.Button(row, text="Revoke selected",
                   command=lambda: [core.grants.revoke(gid) for gid in grants_tv.selection()]).pack(side="left")
        ttk.Button(row, text="Revoke all", command=lambda: core.grants.revoke()).pack(side="left", padx=6)
        paused = tk.BooleanVar(value=core.grants.paused)
        ttk.Checkbutton(row, text="Pause: refuse every request and call", variable=paused,
                        command=lambda: core.set_paused(paused.get())).pack(side="left", padx=12)

        tk.Label(w, text="Activity", font=("Segoe UI", 10, "bold")).pack(pady=(8, 2), **pad)
        acols = {"time": 140, "backend": 90, "event": 110, "detail": 520, "result": 110}
        act_tv = ttk.Treeview(w, columns=list(acols), show="headings")
        for c, width in acols.items():
            act_tv.heading(c, text=c.capitalize())
            act_tv.column(c, width=width, stretch=c == "detail")
        act_tv.pack(fill="both", expand=True, padx=12)

        foot = tk.Frame(w)
        foot.pack(fill="x", padx=12, pady=8)
        for b in core.backends:
            for text, value in b.copies():
                ttk.Button(foot, text=text, command=lambda v=value: self._do_copy(v)).pack(side="left", padx=(0, 6))
        ttk.Button(foot, text="Open data folder", command=lambda: os.startfile(DATA)).pack(side="right")
        ttk.Button(foot, text="Open audit log", command=lambda: os.startfile(AUDIT)).pack(side="right", padx=6)

        shown = {"activity": None}

        def refresh():
            if not w.winfo_exists():
                return
            gs = core.grants.snapshot()
            header.configure(text="Paused: every request and call is refused" if core.grants.paused
                             else f"{len(gs)} live grant(s)", fg="#c0392b" if core.grants.paused else "black")
            paused.set(core.grants.paused)
            for b, label, buttons in status_rows:
                label.configure(text=f"{b.label}: {b.status()}")
                for btn, enabled in buttons:
                    btn.state(["!disabled"] if enabled() else ["disabled"])
            selected = set(grants_tv.selection())
            grants_tv.delete(*grants_tv.get_children())
            for g in gs:
                grants_tv.insert("", "end", iid=g.id, values=(
                    core.label(g.backend), g.origin, g.code, g.purpose, ago(g.created), ago(g.last_used), g.calls))
            grants_tv.selection_set([g.id for g in gs if g.id in selected])
            head = RECENT[0] if RECENT else None
            if head is not shown["activity"]:
                shown["activity"] = head
                act_tv.delete(*act_tv.get_children())
                for rec in list(RECENT)[:150]:
                    act_tv.insert("", "end", values=activity_row(rec, core))
            w.after(1500, refresh)
        refresh()

    def _do_quit(self):
        self.root.quit()


def tray_image(color):
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((4, 4, 60, 60), radius=12, fill=color)
    d.text((22, 16), "G", fill="white", font_size=30)
    return img


IDLE, LIVE, PAUSED_C = "#7a7a7a", "#2e9d4f", "#c0392b"


def build_tray(core, on_quit):
    grants, ui = core.grants, core.ui

    # pystray passes (icon, item) to as many parameters as an action has, defaults
    # included, so values are bound with factories, never `v=value` defaults.
    def revoker(gid):
        return lambda: grants.revoke(gid)

    def copier(value):
        return lambda: ui.post("copy", value)

    def items():
        gs = grants.snapshot()
        yield pystray.MenuItem("Open window", lambda: ui.post("window", core), default=True)
        yield pystray.Menu.SEPARATOR
        yield pystray.MenuItem("Paused: every request is refused" if grants.paused
                               else f"{len(gs)} live grant(s)", None, enabled=False)
        for g in gs:
            purpose = g.purpose if len(g.purpose) <= 40 else g.purpose[:39] + "…"
            label = f"{core.label(g.backend)}: {purpose}  ·  idle {ago(g.last_used)}  ·  age {ago(g.created)}"
            yield pystray.MenuItem(label, pystray.Menu(pystray.MenuItem("Revoke", revoker(g.id))))
        yield pystray.MenuItem("Revoke all", lambda: grants.revoke(), enabled=bool(gs))
        yield pystray.MenuItem("Pause (refuse every request and call)",
                               lambda: core.set_paused(not grants.paused), checked=lambda item: grants.paused)
        yield pystray.Menu.SEPARATOR
        for b in core.backends:
            yield pystray.MenuItem(f"{b.label}: {b.status()}", None, enabled=False)
            for text, action, enabled in b.actions():
                yield pystray.MenuItem(text, action, enabled=enabled())
        yield pystray.Menu.SEPARATOR
        for b in core.backends:
            for text, value in b.copies():
                yield pystray.MenuItem(text, copier(value))
        yield pystray.MenuItem("Open audit log", lambda: os.startfile(AUDIT) if AUDIT.exists() else None)
        yield pystray.MenuItem("Open data folder", lambda: os.startfile(DATA))
        yield pystray.MenuItem("Quit", lambda: on_quit())

    icon = pystray.Icon("windows-gate", tray_image(IDLE), "Gate", pystray.Menu(items))

    def refresh():
        n = len(grants.snapshot())
        icon.icon = tray_image(PAUSED_C if grants.paused else LIVE if n else IDLE)
        icon.title = f"Gate: {'paused' if grants.paused else f'{n} live grant(s)'}"
        icon.update_menu()

    return icon, refresh


# --------------------------------------------------------------------------- core

class Core:
    """What every backend shares: grants, the dialog, the job object, the loop.

    A backend has `name`, `label`, `hostname`, `port`, and `run(stop)`, `shutdown()`,
    `status()`, `actions()` -> [(text, callable, enabled())], `copies()` ->
    [(text, value)], and optionally `grants_changed()` and `paused_changed(paused)`,
    which may be called from any thread.
    """

    def __init__(self, args, grants, ui, job):
        self.args, self.grants, self.ui, self.job = args, grants, ui, job
        self.backends = []
        self.loop: asyncio.AbstractEventLoop | None = None
        self.refresh_tray = lambda: None
        grants.on_change = self._grants_changed

    def label(self, name):
        return next((b.label for b in self.backends if b.name == name), name)

    def call(self, coro):
        """Run a coroutine on the gate's loop, from the Tk or tray thread."""
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def _grants_changed(self):
        self.refresh_tray()
        for b in self.backends:
            getattr(b, "grants_changed", lambda: None)()

    def set_paused(self, paused):
        self.grants.paused = paused
        audit(event="paused" if paused else "resumed")
        for b in self.backends:
            getattr(b, "paused_changed", lambda p: None)(paused)
        self._grants_changed()

    def write_tunnel_config(self):
        lines = [f"tunnel: {self.args.tunnel}", "ingress:"]
        for b in self.backends:
            lines += [f"  - hostname: {b.hostname}", f"    service: http://127.0.0.1:{b.port}"]
        lines.append("  - service: http_status:404")
        path = DATA / "cloudflared.yml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    async def run(self, stop):
        self.loop = asyncio.get_running_loop()
        tasks = [asyncio.ensure_future(b.run(stop)) for b in self.backends]
        if self.args.tunnel:
            cf = shutil.which("cloudflared") or "cloudflared"
            tasks.append(asyncio.ensure_future(supervise("cloudflared", [
                cf, "tunnel", "--no-autoupdate", "--config", str(self.write_tunnel_config()),
                "run", self.args.tunnel], self.job)))

        async def sweeper():
            while True:
                await asyncio.sleep(20)
                self.grants.sweep()
        tasks.append(asyncio.ensure_future(sweeper()))

        await stop.wait()
        for b in self.backends:
            await b.shutdown()
        for t in tasks:
            t.cancel()


# --------------------------------------------------------------------------- main

def main():
    # The backends `from gate import ...`; without this they would load a second
    # copy of this file, with its own activity list.
    sys.modules["gate"] = sys.modules[__name__]
    import mcp_windows
    import pinchtab_windows

    ap = argparse.ArgumentParser()
    ap.add_argument("--tunnel", default="", help="named cloudflared tunnel to run (empty: none)")
    ap.add_argument("--no-replace", dest="replace", action="store_false",
                    help="don't terminate a previously started gate (for a side-by-side test copy)")
    ap.add_argument("--only", choices=["mcp-windows", "pinchtab"], help="run one backend (testing)")
    mcp_windows.add_args(ap)
    pinchtab_windows.add_args(ap)
    args = ap.parse_args()

    logging.basicConfig(filename=DATA / "gate.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.replace:
        replace_previous()
    modules = [m for m in (mcp_windows, pinchtab_windows) if args.only in (None, m.NAME)]
    for port in (m.port(args) for m in modules):
        for _ in range(50):
            with socket.socket() as s:
                try:
                    s.bind(("127.0.0.1", port))
                    break
                except OSError:
                    time.sleep(0.1)
        else:
            tk.Tk().withdraw()
            messagebox.showerror("Gate", f"Port {port} is in use by something other than a previous gate.")
            return

    core = Core(args, Grants(), UI(), KillOnCloseJob())
    core.backends = [m.Backend(core) for m in modules]

    loop = asyncio.new_event_loop()
    stop = asyncio.Event()

    def quit_all():
        def stop_soon():
            stop.set()
        loop.call_soon_threadsafe(stop_soon)
        time.sleep(2)  # let the backends detach (the bridge clears its tab titles)
        icon.stop()
        core.ui.post("quit")

    icon, core.refresh_tray = build_tray(core, quit_all)

    def run_loop():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(core.run(stop))
        except Exception:
            log.exception("gate crashed")
            core.ui.post("quit")

    threading.Thread(target=run_loop, daemon=True).start()
    threading.Thread(target=icon.run, daemon=True).start()
    core.ui.root.mainloop()
    loop.call_soon_threadsafe(stop.set)


if __name__ == "__main__":
    main()


