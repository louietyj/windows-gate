"""The pinchtab backend: cloud Claude driving Louie's real Chrome (the headless-browser
skill's pinchtab-windows tier).

The sandbox asks for a grant (POST /grant, then polls GET /grant/<id>), Louie approves
it in the dialog, and the sandbox then drives a pinchtab bridge attached to his
Chrome with that grant as its Bearer token, which this backend swaps for the
bridge's own token. Only pinchtab's HTTP API crosses the tunnel: carrying CDP
itself costs a ~120 ms round trip per message, and pinchtab sends 12-40 per command.

    127.0.0.1:19870  this HTTP front (grants, proxy, /active-tab, /gate/status)
    127.0.0.1:19871  /json/version shim for Chrome's chrome://inspect debugging mode
    127.0.0.1:19877  pinchtab bridge, from the first grant until an hour after the last
"""
import asyncio
import dataclasses
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import time
import urllib.request
from pathlib import Path

import aiohttp
from aiohttp import web

from gate import DATA, audit, load_secret

NAME = "pinchtab"
PROTOCOL = 1
GATE_PORT = 19870
SHIM_PORT = 19871
BRIDGE_PORT = 19877
IDLE_TTL = 30 * 60
ABSOLUTE_TTL = 4 * 60 * 60
# Chrome asks "Allow remote debugging?" on every attach, so the bridge stays attached
# between grants, and detaches only after this long with no live grant.
BRIDGE_LINGER = 60 * 60
# Covers Louie answering Chrome's own prompt after the bridge starts.
ATTACH_TIMEOUT = 120
DIALOG_TIMEOUT = 120
POLL_MAX = 55  # Cloudflare drops proxied requests at 100 s
COOLDOWN_AFTER_DENY = 30
MIN_REQUEST_GAP = 5
RELEASE_API = "https://api.github.com/repos/louietyj/pinchtab/releases/latest"
RELEASE_ASSET = "pinchtab-windows-amd64.exe"
UPDATE_EVERY = 24 * 60 * 60

STATE = DATA / "pinchtab"
STATE.mkdir(exist_ok=True)
DTAP = Path(os.environ["LOCALAPPDATA"]) / "Google/Chrome/User Data/DevToolsActivePort"

# They'd stop or restart the bridge behind the gate's back (see Bridge.stop).
BLOCKED = re.compile(r"^/(shutdown|ensure-chrome|browser/restart)(/|$)")
# Undoes the bridge's "[PinchTab :port]" title prefix (bridge/attach_indicator.go).
CLEAR_INDICATOR = """(() => {
  const s = globalThis.__pinchtabAttachIndicators;
  if (s) { s.disposed = true; if (s.observer) s.observer.disconnect(); delete globalThis.__pinchtabAttachIndicators; }
  document.title = document.title.replace(/^\\[PinchTab :\\d+(?:,:\\d+)*\\]\\s*/, "");
})()"""
# Request headers that belong to the hop from the cloud, not to the bridge.
DROP_REQUEST = {"host", "authorization", "cookie", "content-length", "connection", "x-gate-key"}
# Bodies pass through still encoded (auto_decompress=False), so Content-Encoding stays.
DROP_RESPONSE = {"content-length", "transfer-encoding", "connection"}

log = logging.getLogger("gate.pinchtab")


def add_args(ap):
    ap.add_argument("--browser-host", default="browser.louietyj.me")
    ap.add_argument("--pinchtab-bin", help="use this pinchtab.exe instead of the latest release (dev)")


def port(args):
    return GATE_PORT


# --- pinchtab binary ---------------------------------------------------------

class Binary:
    """The fork's Windows build from releases/latest, cached per tag. The sandbox's
    setup.sh installs the Linux build of the same release, so both ends agree."""

    def __init__(self, override):
        self.override = Path(override) if override else None
        self.dir = STATE / "bin"

    def path(self):
        if self.override:
            return self.override
        tags = sorted((p for p in self.dir.glob("*/pinchtab.exe")), key=lambda p: p.stat().st_mtime)
        return tags[-1] if tags else None

    def update(self):
        if self.override:
            return
        try:
            with urllib.request.urlopen(RELEASE_API, timeout=20) as r:
                release = json.load(r)
            tag = release["tag_name"]
            target = self.dir / tag / "pinchtab.exe"
            if target.exists():
                return
            url = next((a["browser_download_url"] for a in release["assets"] if a["name"] == RELEASE_ASSET), None)
            if not url:
                log.warning("release %s has no %s", tag, RELEASE_ASSET)
                return
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(".part")
            urllib.request.urlretrieve(url, tmp)
            tmp.replace(target)
            log.info("downloaded pinchtab %s", tag)
        except Exception as e:  # offline, rate-limited: keep the cached build
            log.warning("pinchtab update check failed: %s", e)


# --- /json/version shim ------------------------------------------------------

class JsonShim:
    """Chrome debugging enabled from chrome://inspect 404s /json/*, which pinchtab
    needs to attach: answer it here and splice the rest to Chrome. DevToolsActivePort
    is re-read per connection, so a Chrome restart needs nothing."""

    @staticmethod
    def endpoint():
        port, path = DTAP.read_text().split()[:2]
        return int(port), path

    async def handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
            path = head.split(b"\r\n", 1)[0].split(b" ")[1].decode()
            port, ws_path = self.endpoint()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, IndexError, OSError, ValueError):
            writer.close()
            return
        if path.startswith("/json"):
            payload = [] if path.startswith("/json/list") or path == "/json" else {
                "Browser": "Chrome", "Protocol-Version": "1.3",
                "webSocketDebuggerUrl": f"ws://127.0.0.1:{SHIM_PORT}{ws_path}"}
            body = json.dumps(payload).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
            await writer.drain()
            writer.close()
            return
        try:
            up_reader, up_writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            writer.close()
            return
        up_writer.write(head)
        await up_writer.drain()
        await asyncio.gather(self.pipe(reader, up_writer), self.pipe(up_reader, writer))

    @staticmethod
    async def pipe(reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()


# --- bridge ------------------------------------------------------------------

class Bridge:
    def __init__(self, binary, job):
        self.binary, self.job = binary, job
        self.proc = None
        self.token = None
        self.version = None
        self.lock = asyncio.Lock()
        self.url = f"http://127.0.0.1:{BRIDGE_PORT}"

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def write_config(self):
        """Guards down, as in Louie's local tier; own port and stateDir, apart from it."""
        cfg_dir = STATE / "bridge"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        self.token = secrets.token_hex(24)
        guards = ["allowEvaluate", "allowMacro", "allowScreencast", "allowDownload", "allowCookies",
                  "allowNetworkIntercept", "allowUpload", "allowClipboard", "allowStateExport", "allowFileScheme"]
        cfg = {
            "server": {"port": str(BRIDGE_PORT), "bind": "127.0.0.1", "token": self.token, "stateDir": str(cfg_dir)},
            # The default 20-tab cap evicts the least recently used tab, which here
            # would be one of Louie's: refuse new tabs instead, and only at 500.
            "instanceDefaults": {"captureAllowActivation": True, "maxTabs": 500, "tabEvictionPolicy": "reject"},
            "security": {**{g: True for g in guards}, "allowedDomains": ["*"],
                         "attach": {"enabled": True}, "idpi": {"enabled": False}},
            "multiInstance": {"instancePortStart": BRIDGE_PORT + 1, "instancePortEnd": BRIDGE_PORT + 21},
        }
        path = cfg_dir / "config.json"
        path.write_text(json.dumps(cfg, indent=1))
        return path

    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    async def ensure(self, http):
        """Start the bridge if needed and force its attach, so Chrome's prompt comes
        now rather than on the agent's first command."""
        async with self.lock:
            if not self.alive():
                await self.start(http)
            async with http.get(f"{self.url}/tabs", headers=self.headers(),
                                timeout=aiohttp.ClientTimeout(total=90)) as r:
                if r.status != 200:
                    raise RuntimeError(f"bridge could not reach Chrome (HTTP {r.status}): {(await r.text())[:300]}")

    async def start(self, http):
        exe = self.binary.path()
        if not exe or not exe.exists():
            raise RuntimeError("no pinchtab.exe yet: the release has no Windows build, and --pinchtab-bin is not set")
        if not DTAP.exists():
            raise RuntimeError("Chrome remote debugging is off: enable it in chrome://inspect")
        cfg = self.write_config()
        _, ws_path = JsonShim.endpoint()
        logf = open(STATE / "bridge.log", "ab")
        self.proc = subprocess.Popen(
            [str(exe), "bridge", "--cdp-attach", f"ws://127.0.0.1:{SHIM_PORT}{ws_path}", "--port", str(BRIDGE_PORT)],
            env={**os.environ, "PINCHTAB_CONFIG": str(cfg)}, stdout=logf, stderr=logf,
            stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        self.job.add(self.proc.pid)
        # /health answers 503 until the attach lands, which waits on Chrome's prompt.
        deadline = time.monotonic() + ATTACH_TIMEOUT
        while time.monotonic() < deadline:
            await asyncio.sleep(0.5)
            if not self.alive():
                raise RuntimeError(f"bridge exited at startup (code {self.proc.returncode}); see {STATE / 'bridge.log'}")
            try:
                async with http.get(f"{self.url}/health", headers=self.headers(),
                                    timeout=aiohttp.ClientTimeout(total=2)) as r:
                    if r.status == 200:
                        self.version = (await r.json()).get("version", "unknown")
                        log.info("bridge up: %s (pid %d, %s)", exe, self.proc.pid, self.version)
                        return
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        self.kill()
        raise RuntimeError(f"Chrome did not accept the bridge within {ATTACH_TIMEOUT} s "
                           "(was its 'Allow remote debugging?' prompt answered?)")

    async def stop(self, http):
        """Kill it, never POST /shutdown: before the fork's fix, Cleanup closed every
        tab it had attached, and so Louie's Chrome (README.md). A kill only drops the
        connection, with it the title-prefix script, after stripping the prefix."""
        async with self.lock:
            if not self.alive():
                return
            await self.clear_indicators(http)
            self.kill()
            log.info("bridge stopped")

    def kill(self):
        if self.proc is not None:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(self.proc.pid)], capture_output=True)
            self.proc = None

    async def clear_indicators(self, http):
        """Strip the "[PinchTab :port]" title prefix; a tab that navigates while the
        bridge is attached gets it back, truthfully."""
        try:
            async with http.get(f"{self.url}/tabs", headers=self.headers(),
                                timeout=aiohttp.ClientTimeout(total=5)) as r:
                tabs = (await r.json()).get("tabs", [])
            await asyncio.gather(*(self.evaluate(http, t["id"], CLEAR_INDICATOR) for t in tabs))
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            pass

    async def evaluate(self, http, tab_id, expression):
        try:
            async with http.post(f"{self.url}/evaluate", headers=self.headers(),
                                 json={"tabId": tab_id, "expression": expression},
                                 timeout=aiohttp.ClientTimeout(total=5)) as r:
                return (await r.json()).get("result")
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None


# --- backend -----------------------------------------------------------------

@dataclasses.dataclass
class Request:
    id: str
    purpose: str
    code: str
    agent: str
    ip: str
    state: str = "pending"  # pending | approved | denied | error
    result: dict = dataclasses.field(default_factory=dict)
    done: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    finished: float = 0.0


def ip_of(request):
    return request.headers.get("Cf-Connecting-Ip") or request.remote


class Backend:
    name = NAME
    label = "Chrome"

    def __init__(self, core):
        self.core, self.grants, self.ui = core, core.grants, core.ui
        self.hostname, self.port = core.args.browser_host, GATE_PORT
        self.key = load_secret("browser-key.txt")
        self.binary = Binary(core.args.pinchtab_bin)
        self.bridge = Bridge(self.binary, core.job)
        self.requests: dict[str, Request] = {}
        self.idle_since = time.time()
        self.had_grants = False
        self.last_request = 0.0
        self.cooldown_until = 0.0
        self.loop = self.http = self.runner = self.shim = None
        self.tasks = []

    # --- tray and window

    def status(self):
        if not self.bridge.alive():
            return "not attached"
        if self.grants.snapshot(NAME):
            return f"attached (pinchtab {self.bridge.version})"
        left = max(0, int((self.idle_since + BRIDGE_LINGER - time.time()) // 60))
        return f"attached, no grants: detaches in {left} min"

    def actions(self):
        return [("Detach from Chrome", lambda: self.core.call(self.detach("louie")), self.bridge.alive)]

    def copies(self):
        return [("Copy browser gate key", self.key)]

    # --- core hooks, called from any thread

    def grants_changed(self):
        live = bool(self.grants.snapshot(NAME))
        if self.had_grants and not live and self.loop:
            asyncio.run_coroutine_threadsafe(self.after_last_grant(), self.loop)
        self.had_grants = live

    def paused_changed(self, paused):
        if paused and self.loop:
            asyncio.run_coroutine_threadsafe(self.detach("paused"), self.loop)

    async def after_last_grant(self):
        """The bridge lingers, so the next grant needs no second Chrome prompt."""
        self.idle_since = time.time()
        await self.bridge.clear_indicators(self.http)

    async def detach(self, why):
        self.grants.revoke(backend=NAME)
        if self.bridge.alive():
            audit(backend=NAME, event="bridge_detached", why=why)
        await self.bridge.stop(self.http)
        self.core.refresh_tray()

    # --- grant flow

    async def check_key(self, request, handler):
        if not hmac.compare_digest(request.headers.get("X-Gate-Key", ""), self.key):
            audit(backend=NAME, event="auth_fail", ip=ip_of(request), path=request.path)
            return web.json_response({"code": "bad_key", "message": "missing or wrong X-Gate-Key"}, status=401)
        return await handler(request)

    def pending(self):
        return any(r.state == "pending" for r in self.requests.values())

    async def post_grant(self, request):
        try:
            body = await request.json()
        except ValueError:
            return web.json_response({"code": "bad_request"}, status=400)
        purpose = str(body.get("purpose", "")).strip()[:200]
        code = str(body.get("code", "")).strip().upper()
        agent = re.sub(r"[^A-Za-z0-9_.-]", "", str(body.get("agent", "claude")))[:40] or "claude"
        if not purpose or not re.fullmatch(r"[A-Z0-9]{4}", code):
            return web.json_response({"code": "bad_request", "message": "need a purpose and a 4-character code"}, status=400)
        if self.grants.paused:
            return web.json_response({"code": "paused", "message": "Louie has paused the gate"}, status=403)
        if self.pending():
            return web.json_response({"code": "busy", "message": "another request is waiting for approval"}, status=409)
        now = time.time()
        wait = max(self.cooldown_until - now, self.last_request + MIN_REQUEST_GAP - now)
        if wait > 0:
            return web.json_response({"code": "rate_limited", "retry_after": round(wait)}, status=429)
        self.last_request = now
        req = Request(id=secrets.token_hex(8), purpose=purpose, code=code, agent=agent, ip=ip_of(request))
        self.requests[req.id] = req
        audit(backend=NAME, event="grant_requested", request=req.id, agent=agent, ip=req.ip, purpose=purpose, code=code)
        asyncio.ensure_future(self.decide(req))
        return web.json_response({"request_id": req.id})

    async def decide(self, req):
        note = (f"Allow lets that conversation drive your Chrome, logged in as you, until it is "
                f"{IDLE_TTL // 60} min idle or {ABSOLUTE_TTL // 3600} h old. If Chrome then asks to "
                "allow remote debugging, click Allow there too.")
        try:
            ok = await self.ui.ask("Claude wants to drive your Chrome", req.purpose,
                                   f"{req.agent} ({req.ip})", note, DIALOG_TIMEOUT, req.code)
            if not ok:
                req.state = "denied"
                self.cooldown_until = time.time() + COOLDOWN_AFTER_DENY
            else:
                await self.bridge.ensure(self.http)
                g = self.grants.create(NAME, req.purpose, req.agent, IDLE_TTL, ABSOLUTE_TTL, req.code)
                req.state = "approved"
                req.result = {"token": g.id, "idle_ttl": IDLE_TTL, "absolute_ttl": ABSOLUTE_TTL,
                              "bridge_version": self.bridge.version}
        except Exception as e:
            log.exception("grant %s failed", req.id)
            req.state = "error"
            req.result = {"message": str(e)}
            if not self.grants.snapshot(NAME):
                await self.bridge.stop(self.http)
        req.finished = time.time()
        req.done.set()
        audit(backend=NAME, event="grant_" + req.state, request=req.id, agent=req.agent,
              **({"why": req.result["message"]} if req.state == "error" else {}))

    async def get_grant(self, request):
        req = self.requests.get(request.match_info["id"])
        if not req:
            return web.json_response({"code": "unknown_request"}, status=404)
        wait = min(float(request.query.get("wait", "0") or 0), POLL_MAX)
        if req.state == "pending" and wait > 0:
            try:
                await asyncio.wait_for(req.done.wait(), wait)
            except asyncio.TimeoutError:
                pass
        return web.json_response({"state": req.state, "protocol": PROTOCOL, **req.result})

    async def delete_grant(self, request):
        auth = request.headers.get("Authorization", "")
        n = self.grants.revoke(auth[7:], backend=NAME, why="released") if auth.startswith("Bearer ") else 0
        return web.json_response({"released": bool(n)})

    def require_grant(self, request):
        auth = request.headers.get("Authorization", "")
        grant, why = self.grants.use(auth[7:] if auth.startswith("Bearer ") else "", NAME)
        if grant:
            return grant, None
        code = "grant_expired" if ("lapsed" in why or "cap" in why) else "grant_required"
        return None, web.json_response(
            {"code": code, "message": f"{why}: run `pinchtab-windows grant \"<purpose>\"`"}, status=401)

    # --- authenticated routes

    async def active_tab(self, request):
        _, denied = self.require_grant(request)
        if denied:
            return denied
        await self.bridge.ensure(self.http)
        async with self.http.get(f"{self.bridge.url}/tabs", headers=self.bridge.headers()) as r:
            tabs = [t for t in (await r.json()).get("tabs", []) if t.get("type", "page") == "page"]
        expr = "({visible: document.visibilityState === 'visible', focused: document.hasFocus()})"

        async def probe(tab):
            res = await self.bridge.evaluate(self.http, tab["id"], expr) or {}
            return {"id": tab["id"], "title": tab.get("title", ""), "url": tab.get("url", ""),
                    "visible": bool(res.get("visible")), "focused": bool(res.get("focused"))}

        rows = await asyncio.gather(*(probe(t) for t in tabs))
        rows.sort(key=lambda t: (not t["focused"], not t["visible"]))
        return web.json_response({"tabs": rows})

    async def proxy(self, request):
        path = request.rel_url.path
        if BLOCKED.match(path):
            return web.json_response({"code": "blocked", "message": f"{path} is not available through the gate"}, status=403)
        grant, denied = self.require_grant(request)
        if denied:
            return denied
        t0 = time.monotonic()
        if not self.bridge.alive():
            await self.bridge.ensure(self.http)
        headers = {k: v for k, v in request.headers.items() if k.lower() not in DROP_REQUEST}
        headers.update(self.bridge.headers())
        body = await request.read()
        status = 502
        try:
            async with self.http.request(request.method, f"{self.bridge.url}{request.rel_url}", headers=headers,
                                         data=body or None, allow_redirects=False,
                                         timeout=aiohttp.ClientTimeout(total=None, sock_read=300)) as up:
                status = up.status
                resp = web.StreamResponse(status=up.status, headers={
                    k: v for k, v in up.headers.items() if k.lower() not in DROP_RESPONSE})
                await resp.prepare(request)
                async for chunk in up.content.iter_any():
                    await resp.write(chunk)
                await resp.write_eof()
                return resp
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            return web.json_response({"code": "bridge_unreachable", "message": str(e)}, status=502)
        finally:
            audit(backend=NAME, event="call", grant=grant.short, agent=grant.origin, method=request.method,
                  path=str(request.rel_url)[:300], status=status, ms=round((time.monotonic() - t0) * 1000))

    async def gate_status(self, request):
        return web.json_response({"protocol": PROTOCOL, "paused": self.grants.paused,
                                  "grants": len(self.grants.snapshot(NAME))})

    # --- lifecycle

    async def reaper(self):
        while True:
            await asyncio.sleep(30)
            now = time.time()
            for rid, req in list(self.requests.items()):
                if req.state != "pending" and now - req.finished > 600:
                    del self.requests[rid]
            if not self.grants.snapshot(NAME) and self.bridge.alive() and now - self.idle_since > BRIDGE_LINGER:
                audit(backend=NAME, event="bridge_detached", why="idle")
                await self.bridge.stop(self.http)
                self.core.refresh_tray()

    async def updater(self):
        while True:
            await asyncio.to_thread(self.binary.update)
            await asyncio.sleep(UPDATE_EVERY)

    async def run(self, stop):
        self.loop = asyncio.get_running_loop()
        self.http = aiohttp.ClientSession(auto_decompress=False)
        @web.middleware
        async def key_middleware(request, handler):
            return await self.check_key(request, handler)

        app = web.Application(client_max_size=64 * 1024 * 1024, middlewares=[key_middleware])
        app.router.add_get("/gate/status", self.gate_status)
        app.router.add_post("/grant", self.post_grant)
        app.router.add_get("/grant/{id}", self.get_grant)
        app.router.add_delete("/grant", self.delete_grant)
        app.router.add_get("/active-tab", self.active_tab)
        app.router.add_route("*", "/{tail:.*}", self.proxy)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner, "127.0.0.1", GATE_PORT).start()
        self.shim = await asyncio.start_server(JsonShim().handle, "127.0.0.1", SHIM_PORT)
        self.tasks = [asyncio.ensure_future(self.reaper()), asyncio.ensure_future(self.updater())]
        log.info("pinchtab on 127.0.0.1:%d", GATE_PORT)
        await stop.wait()

    async def shutdown(self):
        await self.bridge.stop(self.http)
        for t in self.tasks:
            t.cancel()
        if self.shim:
            self.shim.close()
        if self.http:
            await self.http.close()
        if self.runner:
            await self.runner.cleanup()


