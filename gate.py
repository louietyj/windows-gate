# /// script
# requires-python = ">=3.11"
# dependencies = ["aiohttp>=3.9", "pystray>=0.19", "pillow>=10"]
# ///
"""Approval gate in front of windows-mcp, for use as a claude.ai custom connector.

    claude.ai --Bearer--> cloudflared --> gate (127.0.0.1:9340) --> windows-mcp (loopback, own key)

claude.ai's MCP client is stateless (no initialize, no Mcp-Session-Id), so the
gate makes its own per-conversation binding: an injected RequestGrant tool pops
a Windows dialog with the model's stated purpose, and on Allow returns a grant
ID that every other tool requires as `_grant`. Calls without a live grant fail
at once without prompting. Grants live only in memory and lapse after 15 min
idle or 1 h total; the tray icon lists them and revokes them.

The gate also supervises its children: windows-mcp (on a random loopback port
with a per-run key) and, if --tunnel is given, `cloudflared tunnel run`. Both
sit in a kill-on-close job object, so they die with the gate.
"""
import argparse
import asyncio
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
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import tkinter as tk
from tkinter import messagebox

import aiohttp
import pystray
from aiohttp import web
from PIL import Image, ImageDraw

DATA = pathlib.Path(os.environ["LOCALAPPDATA"]) / "mcp-windows-gate"
DATA.mkdir(parents=True, exist_ok=True)
AUDIT = DATA / "audit.jsonl"
BEARER_FILE = DATA / "bearer.txt"

REQUEST_TOOL = "RequestGrant"
RELEASE_TOOL = "ReleaseGrant"
GRANT_PROP = {
    "type": "string",
    "description": (
        "Required. The grant ID that RequestGrant returned in this conversation. "
        "Call RequestGrant first if you have none or it has lapsed."
    ),
}
REQUEST_DEF = {
    "name": REQUEST_TOOL,
    "title": "Request grant",
    "description": (
        "Call this before using any other tool on this server. It asks Louie to approve "
        "on his laptop and returns a grant ID that every other tool requires as `_grant`. "
        "One grant covers the whole task: reuse it until a call says it has lapsed "
        "(15 min without a call, or 1 h total)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"purpose": {
            "type": "string",
            "description": "One line on what you're about to do on Louie's computer. It's shown in his approval dialog.",
        }},
        "required": ["purpose"],
    },
}
RELEASE_DEF = {
    "name": RELEASE_TOOL,
    "title": "Release grant",
    "description": "End this conversation's grant once the task is done, so it can't be used again.",
    "inputSchema": {"type": "object", "properties": {"_grant": GRANT_PROP}, "required": ["_grant"]},
}

log = logging.getLogger("gate")


# --------------------------------------------------------------------------- grants

@dataclasses.dataclass
class Grant:
    id: str
    created: float
    last_used: float
    purpose: str

    @property
    def short(self):
        return self.id[:7] + "…"


class Grants:
    def __init__(self, idle, cap):
        self.idle, self.cap = idle, cap
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
        if now - g.created > self.cap:
            return f"grant {g.short} hit its {self.cap // 60} min cap"
        if now - g.last_used > self.idle:
            return f"grant {g.short} lapsed after {self.idle // 60} min idle"
        return None

    def use(self, gid):
        """Return (grant, None) if gid is live, else (None, reason)."""
        if not gid:
            return None, "no grant"
        now = time.time()
        with self.lock:
            g = next((g for k, g in self.live.items() if hmac.compare_digest(k, gid)), None)
            if g is None:
                return None, "unknown or revoked grant"
            why = self._expiry(g, now)
            if why:
                del self.live[g.id]
            else:
                g.last_used = now
        if why:
            self._changed()
            return None, why
        return g, None

    def create(self, purpose):
        now = time.time()
        g = Grant("g_" + secrets.token_urlsafe(18), now, now, purpose)
        with self.lock:
            self.live[g.id] = g
        self._changed()
        return g

    def revoke(self, gid=None):
        with self.lock:
            if gid is None:
                n = len(self.live)
                self.live.clear()
            else:
                n = 1 if self.live.pop(gid, None) else 0
        self._changed()
        return n

    def sweep(self):
        now = time.time()
        with self.lock:
            dead = [k for k, g in self.live.items() if self._expiry(g, now)]
            for k in dead:
                del self.live[k]
        if dead:
            self._changed()

    def snapshot(self):
        with self.lock:
            return sorted(self.live.values(), key=lambda g: g.created)


def fingerprint(gid):
    return hashlib.sha256(gid.encode()).hexdigest()[:8] if gid else None


def audit(**rec):
    rec = {"t": time.strftime("%Y-%m-%d %H:%M:%S"), **rec}
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


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


# --------------------------------------------------------------------------- MCP plumbing

@dataclasses.dataclass
class Upstream:
    status: int
    ctype: str
    body: bytes
    session: str | None = None


def map_messages(up, fn):
    """Apply fn to each JSON-RPC message in a JSON or buffered-SSE response body."""
    if up.ctype.startswith("application/json"):
        try:
            msg = json.loads(up.body)
        except ValueError:
            return up
        msgs = [fn(m) for m in msg] if isinstance(msg, list) else fn(msg)
        return dataclasses.replace(up, body=json.dumps(msgs).encode())
    if up.ctype.startswith("text/event-stream"):
        out = []
        for event in re.split(r"\r?\n\r?\n", up.body.decode("utf-8")):
            if not event.strip():
                continue
            lines = event.splitlines()
            data = "\n".join(l[5:].lstrip(" ") for l in lines if l.startswith("data:"))
            try:
                msg = json.loads(data)
            except ValueError:
                out.append(event)
                continue
            rest = [l for l in lines if not l.startswith("data:")]
            out.append("\n".join(rest + ["data: " + json.dumps(fn(msg))]))
        return dataclasses.replace(up, body=("\n\n".join(out) + "\n\n").encode())
    return up


def patch_tools_list(msg):
    tools = (msg.get("result") or {}).get("tools")
    if isinstance(tools, list):
        for t in tools:
            schema = t.setdefault("inputSchema", {"type": "object"})
            schema.setdefault("properties", {})["_grant"] = GRANT_PROP
            required = schema.setdefault("required", [])
            if "_grant" not in required:
                required.append("_grant")
        tools[:0] = [REQUEST_DEF]
        tools.append(RELEASE_DEF)
    return msg


def rpc_result(rpc_id, text, is_error=False):
    # Protocol 2026-07-28 requires resultType; windows-mcp's own results carry "complete".
    return web.json_response({
        "jsonrpc": "2.0", "id": rpc_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": is_error, "resultType": "complete"},
    })


GRANTED = (
    "Louie approved. Grant: {gid}\n"
    "Pass \"_grant\": \"{gid}\" in the arguments of every call to this server's tools for "
    "the rest of this task. It lapses after {idle} min without a call or {cap} min total. "
    "Call ReleaseGrant with it when the task is done."
)
NO_GRANT = (
    "No valid grant ({why}), so this call did not run. Call RequestGrant with a one-line "
    "purpose, then retry with the grant ID it returns as \"_grant\"."
)
DENIED = "Louie denied the grant on his laptop. Do not ask again unless he tells you to."
PAUSED = "The mcp-windows gate is paused on Louie's laptop: every call is refused until he unpauses it."
TIMED_OUT = (
    "Approval timed out: Louie didn't answer the prompt on his laptop within {hold} s, so he "
    "may be away from it. Tell him, and retry only when he says he's there."
)


class Gate:
    def __init__(self, args, grants, ui):
        self.args, self.grants, self.ui = args, grants, ui
        self.bearer = load_bearer()
        self.inner_key = secrets.token_urlsafe(32)
        self.inner_port = free_port()
        self.http: aiohttp.ClientSession | None = None

    @property
    def upstream_url(self):
        return f"http://127.0.0.1:{self.inner_port}/mcp"

    async def forward(self, request, body):
        headers = {k: v for k, v in request.headers.items() if k.lower() in (
            "content-type", "accept", "mcp-protocol-version", "mcp-method", "mcp-name",
            "mcp-session-id", "last-event-id")}
        headers["Authorization"] = f"Bearer {self.inner_key}"
        try:
            async with self.http.post(self.upstream_url, data=body, headers=headers) as r:
                return Upstream(r.status, r.headers.get("Content-Type", "application/json"),
                                await r.read(), r.headers.get("Mcp-Session-Id"))
        except aiohttp.ClientError as e:
            log.error("upstream: %s", e)
            return None

    @staticmethod
    def respond(up):
        headers = {"Content-Type": up.ctype}
        if up.session:
            headers["Mcp-Session-Id"] = up.session
        return web.Response(status=up.status, body=up.body, headers=headers)

    async def handle(self, request):
        ip = request.headers.get("Cf-Connecting-Ip") or request.remote
        auth = request.headers.get("Authorization", "")
        if not (auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].strip(), self.bearer)):
            audit(event="auth_fail", ip=ip, path=request.path)
            return web.Response(status=401, headers={"WWW-Authenticate": 'Bearer realm="mcp-windows-gate"'})
        if request.method != "POST":
            return web.Response(status=405)

        body = await request.read()
        try:
            msg = json.loads(body)
        except ValueError:
            msg = None
        if isinstance(msg, list) and any(isinstance(m, dict) and m.get("method") == "tools/call" for m in msg):
            return web.json_response({"jsonrpc": "2.0", "id": None,
                                      "error": {"code": -32600, "message": "batched tools/call is not supported"}})
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            return await self.handle_call(request, msg, ip)

        up = await self.forward(request, body)
        if up is None:
            return web.Response(status=502, text="windows-mcp is not reachable")
        if isinstance(msg, dict) and msg.get("method") == "tools/list":
            up = map_messages(up, patch_tools_list)
        return self.respond(up)

    async def handle_call(self, request, msg, ip):
        rpc_id = msg.get("id")
        params = dict(msg.get("params") or {})
        tool = params.get("name")
        args = dict(params.get("arguments") or {})
        gid = args.pop("_grant", None)
        rec = {"event": "call", "ip": ip, "tool": tool, "args": json.dumps(args)[:300], "grant": fingerprint(gid)}

        if tool == RELEASE_TOOL:
            n = self.grants.revoke(gid) if gid else 0
            audit(**rec, decision="released" if n else "release_unknown")
            return rpc_result(rpc_id, "Grant released." if n else "That grant was already gone.")

        if tool == REQUEST_TOOL:
            return await self.request_grant(rpc_id, args.get("purpose") or "(no purpose given)", ip, rec)

        grant, why = self.grants.use(gid)
        if grant is None:
            audit(**rec, decision="no_grant", why=why)
            return rpc_result(rpc_id, NO_GRANT.format(why=why), is_error=True)

        params["arguments"] = args
        up = await self.forward(request, json.dumps({**msg, "params": params}).encode())
        if up is None:
            audit(**rec, error="upstream unreachable")
            return rpc_result(rpc_id, "windows-mcp is not reachable on Louie's laptop.", is_error=True)
        audit(**rec, decision="granted", status=up.status)
        return self.respond(up)

    async def request_grant(self, rpc_id, purpose, ip, rec):
        if self.grants.paused:
            audit(**rec, decision="paused")
            return rpc_result(rpc_id, PAUSED, is_error=True)
        t0 = time.monotonic()
        ok = await self.ui.ask(purpose, ip, self.args.hold)
        rec["waited_s"] = round(time.monotonic() - t0, 1)
        if ok is None:
            audit(**rec, decision="timeout")
            return rpc_result(rpc_id, TIMED_OUT.format(hold=self.args.hold), is_error=True)
        if not ok:
            audit(**rec, decision="denied")
            return rpc_result(rpc_id, DENIED, is_error=True)
        g = self.grants.create(purpose)
        audit(**rec, decision="approved", new_grant=fingerprint(g.id))
        return rpc_result(rpc_id, GRANTED.format(gid=g.id, idle=self.args.idle // 60, cap=self.args.cap // 60))

    async def run(self, job, stop):
        self.http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, sock_connect=5))
        app = web.Application(client_max_size=64 * 1024 * 1024)
        app.router.add_route("*", "/mcp", self.handle)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", self.args.port).start()
        log.info("gate on 127.0.0.1:%s -> windows-mcp on :%s", self.args.port, self.inner_port)

        uvx = shutil.which("uvx") or "uvx"
        tasks = [asyncio.ensure_future(supervise("windows-mcp", [
            uvx, "windows-mcp", "serve", "--transport", "streamable-http", "--host", "127.0.0.1",
            "--port", str(self.inner_port), "--auth-key", self.inner_key], job))]
        if self.args.tunnel:
            cf = shutil.which("cloudflared") or "cloudflared"
            tasks.append(asyncio.ensure_future(supervise("cloudflared", [
                cf, "tunnel", "--no-autoupdate", "run", "--url", f"http://127.0.0.1:{self.args.port}",
                self.args.tunnel], job)))

        async def sweeper():
            while True:
                await asyncio.sleep(20)
                self.grants.sweep()
        tasks.append(asyncio.ensure_future(sweeper()))

        await stop.wait()
        for t in tasks:
            t.cancel()
        await self.http.close()
        await runner.cleanup()


def load_bearer():
    if not BEARER_FILE.exists():
        BEARER_FILE.write_text(secrets.token_urlsafe(32), encoding="ascii")
    return BEARER_FILE.read_text(encoding="ascii").strip()


# --------------------------------------------------------------------------- UI

@dataclasses.dataclass
class DialogReq:
    purpose: str
    ip: str
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

    async def ask(self, purpose, ip, hold):
        loop = asyncio.get_running_loop()
        req = DialogReq(purpose, ip, hold, loop, loop.create_future())
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
        w.title("mcp-windows: grant access?")
        w.attributes("-topmost", True)
        w.resizable(False, False)
        w.protocol("WM_DELETE_WINDOW", lambda: self._decide(req, False))
        w.bind("<Escape>", lambda e: self._decide(req, False))

        pad = {"padx": 14, "pady": (10, 0), "anchor": "w"}
        tk.Label(w, text="Claude wants control of this PC", font=("Segoe UI", 13, "bold")).pack(**pad)
        tk.Label(w, text=f"from {req.ip} at {time.strftime('%H:%M:%S')}",
                 font=("Segoe UI", 9), fg="#555").pack(padx=14, anchor="w")
        txt = tk.Text(w, width=72, height=min(8, 2 + len(req.purpose) // 70),
                      font=("Segoe UI", 10), wrap="word", relief="solid", borderwidth=1)
        txt.insert("1.0", req.purpose[:2000])
        txt.configure(state="disabled")
        txt.pack(padx=14, pady=8, fill="x")
        tk.Label(w, text="Allow opens a grant for that conversation: every windows-mcp tool, "
                         "including PowerShell, for 15 min idle or 1 h max. "
                         "Only allow a request you just made.",
                 font=("Segoe UI", 9), wraplength=520, justify="left").pack(padx=14, anchor="w")

        row = tk.Frame(w)
        row.pack(fill="x", padx=14, pady=12)
        left = tk.Label(row, font=("Segoe UI", 9), fg="#555")
        left.pack(side="left")
        tk.Button(row, text="Deny", width=10, command=lambda: self._decide(req, False)).pack(side="right")
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
        w.bell()

    def _do_copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _do_quit(self):
        self.root.quit()


def tray_image(color):
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((4, 4, 60, 60), radius=12, fill=color)
    d.text((22, 16), "W", fill="white", font_size=30)
    return img


IDLE, LIVE, PAUSED_C = "#7a7a7a", "#2e9d4f", "#c0392b"


def build_tray(grants, ui, gate, on_quit):
    def ago(t):
        m = int((time.time() - t) // 60)
        return f"{m} min" if m else "<1 min"

    def revoker(gid):
        # pystray rejects actions with more than two parameters, so no gid=g.id default.
        return lambda: grants.revoke(gid)

    def items():
        gs = grants.snapshot()
        yield pystray.MenuItem(f"{len(gs)} live grant(s)", None, enabled=False)
        for g in gs:
            purpose = g.purpose if len(g.purpose) <= 40 else g.purpose[:39] + "…"
            label = f"{g.short}  {purpose}  ·  idle {ago(g.last_used)}  ·  age {ago(g.created)}"
            yield pystray.MenuItem(label, pystray.Menu(pystray.MenuItem("Revoke", revoker(g.id))))
        yield pystray.Menu.SEPARATOR
        yield pystray.MenuItem("Revoke all", lambda: grants.revoke(), enabled=bool(gs))
        yield pystray.MenuItem("Pause (refuse every call)", toggle_pause, checked=lambda item: grants.paused)
        yield pystray.Menu.SEPARATOR
        yield pystray.MenuItem("Copy connector bearer token", lambda: ui.post("copy", gate.bearer))
        yield pystray.MenuItem("Open audit log", lambda: os.startfile(AUDIT) if AUDIT.exists() else None)
        yield pystray.MenuItem("Open data folder", lambda: os.startfile(DATA))
        yield pystray.MenuItem("Quit", lambda: on_quit())

    def toggle_pause():
        grants.paused = not grants.paused
        refresh()

    icon = pystray.Icon("mcp-windows-gate", tray_image(IDLE), "mcp-windows gate", pystray.Menu(items))

    def refresh():
        n = len(grants.snapshot())
        icon.icon = tray_image(PAUSED_C if grants.paused else LIVE if n else IDLE)
        icon.title = f"mcp-windows gate: {'paused' if grants.paused else f'{n} live grant(s)'}"
        icon.update_menu()

    return icon, refresh


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9340)
    ap.add_argument("--tunnel", default="", help="named cloudflared tunnel to run (empty: none)")
    ap.add_argument("--hold", type=int, default=140, help="seconds to hold a call while asking (claude.ai gives up at 180)")
    ap.add_argument("--idle", type=int, default=15 * 60)
    ap.add_argument("--cap", type=int, default=60 * 60)
    ap.add_argument("--no-replace", dest="replace", action="store_false",
                    help="don't terminate a previously started gate (for a side-by-side test copy)")
    args = ap.parse_args()

    logging.basicConfig(filename=DATA / "gate.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.replace:
        replace_previous()
    for _ in range(50):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", args.port))
                break
            except OSError:
                time.sleep(0.1)
    else:
        tk.Tk().withdraw()
        messagebox.showerror("mcp-windows gate", f"Port {args.port} is in use by something other than a previous gate.")
        return

    grants = Grants(args.idle, args.cap)
    ui = UI()
    gate = Gate(args, grants, ui)
    job = KillOnCloseJob()

    loop = asyncio.new_event_loop()
    stop = asyncio.Event()

    def quit_all():
        loop.call_soon_threadsafe(stop.set)
        icon.stop()
        ui.post("quit")

    icon, refresh = build_tray(grants, ui, gate, quit_all)
    grants.on_change = refresh

    def run_loop():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(gate.run(job, stop))
        except Exception:
            log.exception("gate crashed")
            ui.post("quit")

    threading.Thread(target=run_loop, daemon=True).start()
    threading.Thread(target=icon.run, daemon=True).start()
    ui.root.mainloop()
    loop.call_soon_threadsafe(stop.set)


if __name__ == "__main__":
    main()
