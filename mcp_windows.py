"""The mcp-windows backend: windows-mcp behind the gate, as the claude.ai `mcp-windows` connector.

claude.ai's MCP client is stateless (no initialize, no Mcp-Session-Id), so the
backend makes its own per-conversation binding: an injected RequestGrant tool pops
the approval dialog with the model's stated purpose, and on Allow returns a grant
ID that every other tool requires as `_grant`. Calls without a live grant fail at
once without prompting.
"""
import asyncio
import dataclasses
import hmac
import json
import logging
import re
import secrets
import shutil
import time

import aiohttp
from aiohttp import web

from gate import audit, fingerprint, free_port, load_secret, supervise

NAME = "mcp-windows"
log = logging.getLogger("gate.mcp")


def add_args(ap):
    ap.add_argument("--port", type=int, default=9340)
    ap.add_argument("--mcp-host", default="mcp-windows.louietyj.me")
    ap.add_argument("--hold", type=int, default=140, help="seconds to hold a call while asking (claude.ai gives up at 180)")
    ap.add_argument("--idle", type=int, default=15 * 60)
    ap.add_argument("--cap", type=int, default=60 * 60)


def port(args):
    return args.port


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


class Backend:
    name = NAME
    label = "PC control"

    def __init__(self, core):
        self.args, self.grants, self.ui, self.job = core.args, core.grants, core.ui, core.job
        self.hostname, self.port = self.args.mcp_host, self.args.port
        self.bearer = load_secret("bearer.txt")
        self.inner_key = secrets.token_urlsafe(32)
        self.inner_port = free_port()
        self.http: aiohttp.ClientSession | None = None

    def status(self):
        return f"windows-mcp behind {self.hostname}"

    def actions(self):
        return []

    def copies(self):
        return [("Copy connector bearer token", self.bearer)]

    async def shutdown(self):
        pass

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
            audit(backend=NAME, event="auth_fail", ip=ip, path=request.path)
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
        rec = {"backend": NAME, "event": "call", "ip": ip, "tool": tool, "args": json.dumps(args)[:300],
               "grant": fingerprint(gid)}

        if tool == RELEASE_TOOL:
            n = self.grants.revoke(gid, backend=NAME, why="released") if gid else 0
            audit(**rec, decision="released" if n else "release_unknown")
            return rpc_result(rpc_id, "Grant released." if n else "That grant was already gone.")

        if tool == REQUEST_TOOL:
            return await self.request_grant(rpc_id, args.get("purpose") or "(no purpose given)", ip, rec)

        grant, why = self.grants.use(gid, NAME)
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
        note = (f"Allow opens a grant for that conversation: every windows-mcp tool, including "
                f"PowerShell, for {self.args.idle // 60} min idle or {self.args.cap // 60} min max.")
        ok = await self.ui.ask("Claude wants control of this PC", purpose, ip, note, self.args.hold)
        rec["waited_s"] = round(time.monotonic() - t0, 1)
        if ok is None:
            audit(**rec, decision="timeout")
            return rpc_result(rpc_id, TIMED_OUT.format(hold=self.args.hold), is_error=True)
        if not ok:
            audit(**rec, decision="denied")
            return rpc_result(rpc_id, DENIED, is_error=True)
        g = self.grants.create(NAME, purpose, ip, self.args.idle, self.args.cap)
        audit(**rec, decision="approved", new_grant=fingerprint(g.id))
        return rpc_result(rpc_id, GRANTED.format(gid=g.id, idle=self.args.idle // 60, cap=self.args.cap // 60))

    async def run(self, stop):
        self.http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, sock_connect=5))
        app = web.Application(client_max_size=64 * 1024 * 1024)
        app.router.add_route("*", "/mcp", self.handle)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", self.args.port).start()
        log.info("mcp-windows on 127.0.0.1:%s -> windows-mcp on :%s", self.args.port, self.inner_port)

        uvx = shutil.which("uvx") or "uvx"
        child = asyncio.ensure_future(supervise("windows-mcp", [
            uvx, "windows-mcp", "serve", "--transport", "streamable-http", "--host", "127.0.0.1",
            "--port", str(self.inner_port), "--auth-key", self.inner_key], self.job))

        await stop.wait()
        child.cancel()
        await self.http.close()
        await runner.cleanup()


