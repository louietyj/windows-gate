# mcp-windows-gate

Exposes [windows-mcp](https://github.com/CursorTouch/Windows-MCP) to claude.ai as the `mcp-windows` custom connector, with an approval dialog on Louie's laptop in front of it. It's one script, [`gate.py`](gate.py).

```
claude.ai --Bearer--> mcp-windows.louietyj.me --cloudflared--> gate.py 127.0.0.1:9340 --> windows-mcp (loopback, random port, per-run key)
```

## How access works

The bearer token only lets a caller talk to the gate. Running a tool needs a **grant**, and only Louie's click creates one:

- The gate rewrites `tools/list`. It adds a `RequestGrant(purpose)` tool, gives every windows-mcp tool a **required** `_grant` argument, and adds `ReleaseGrant`. It strips `_grant` before forwarding a call.
- `RequestGrant` pops a topmost Tk dialog showing the stated purpose and the caller IP, and holds the call for up to 140 s. **Allow** returns the grant ID as the whole tool result.
- Any other call without a live grant fails at once with "call RequestGrant first", so dialogs only ever come from explicit requests.
- A grant lapses after 15 min without a call or 1 h total. Grants live only in memory, so a gate restart revokes them all. The tray icon lists them, and offers Revoke, Revoke all and Pause.

A leaked bearer token therefore produces a dialog Louie denies, never a silent call. The grant ID does appear in that conversation's transcript.

## Why it's built this way

Measured against claude.ai (Cowork) on 2026-10-09:

- **No session to bind to.** The client speaks protocol `2026-07-28`, and its first call is `server/discover`, not `initialize`. No `Mcp-Session-Id` is ever sent. The requests' headers and `_meta` carry nothing that identifies the conversation: `claudecode/toolUseId` is per call, and `progressToken` is a small counter. Hence the grant handed to the model, which the model then passes back.
- **Tool calls time out at 180 s**, measured from when the request is sent, after claude.ai's own approval step. Hence `--hold 140`.
- **Text appended to a tool's result gets lost.** An earlier version prompted on the first ungranted call and appended the grant ID to that tool's result. Models missed it whenever the tool declares an `outputSchema`, presumably because claude.ai surfaces only `structuredContent`. That's why the grant comes from a dedicated tool.
- **`resultType` is required.** Every `tools/call` result must include it under `2026-07-28` (windows-mcp sends `"resultType": "complete"`), or claude.ai rejects the result as malformed. Any result the gate builds itself goes through `rpc_result`, which adds it.
- **The routing headers are checked.** windows-mcp rejects a request whose `Mcp-Method` and `Mcp-Name` headers don't match its body, so hand-made test requests must send both.
- **Callers come from `160.79.106.x`** with the user agent `Claude-User`. That range is deliberately **not** allowlisted. It's shared compute, so it would prove nothing about who's calling.

## Decisions (Louie's, don't reopen without asking)

- **Guards down.** Every windows-mcp tool is exposed, including PowerShell, Registry and FileSystem. There's no per-tool approval and no IP allowlist.
- **claude.ai's own per-tool approval is set to "always allow".** The Windows dialog replaces it.
- **`Snapshot` is denied in the connector, not in the gate.** It walks the UI Automation tree of every window it touches, which freezes the laptop. `region` and `display` only narrow *which* windows get walked, and each one is still walked in full (`windows_mcp/desktop/service.py` in 0.8.7). Use `Screenshot` and coordinate clicks instead, and the pinchtab path for anything in Chrome.
- **Stronger binding, if ever wanted.** A sandbox-side client that generates a per-conversation signing key, registers it through the dialog, and signs every request. Connectors can't do this, since they can't run client-side code; it would mean the sandbox's `lmcps` route instead.

## Deployment on this machine

| Piece | Where |
|---|---|
| Scheduled task | `mcp-windows-gate`: at logon, as Louie, interactive. A service can't show dialogs. It runs `uvw run --script C:\Users\louie\mcp-windows-gate\gate.py --tunnel mcp-windows`. |
| Tunnel | Named tunnel `mcp-windows` (`47213dd5-…`), credentials in `~\.cloudflared\47213dd5-….json`, CNAME `mcp-windows.louietyj.me` |
| Connector | claude.ai → `mcp-windows`, URL `https://mcp-windows.louietyj.me/mcp`, bearer from the tray's "Copy connector bearer token" |
| State | `%LOCALAPPDATA%\mcp-windows-gate\`: `bearer.txt`, `audit.jsonl` (grants logged as hash prefixes), `gate.pid`, `gate.log`, `windows-mcp.log`, `cloudflared.log` |

The gate supervises windows-mcp (`uvx windows-mcp serve --transport streamable-http …`) and `cloudflared tunnel run`, restarting either if it dies. Both sit in a kill-on-close job object, so they exit with the gate. Its dependencies are declared inline (PEP 723), so `uv run --script` needs no install step.

## Operating it

- **Restart:** `Stop-ScheduledTask mcp-windows-gate; Start-ScheduledTask mcp-windows-gate`. Stopping kills only the `uvw` launcher and leaves the gate running, so each new gate terminates the previous one itself. It identifies it from `gate.pid`, which stores PID plus creation time, so a recycled PID can't match.
- **Rotate the bearer:** delete `bearer.txt`, restart, then paste the new token into the connector.
- **Test copy beside the live one:** `uv run --script gate.py --port 9341 --hold 10 --no-replace`, with no `--tunnel`.
- **Hand-probe:** POST to `/mcp` with `Authorization: Bearer …`, `Accept: application/json, text/event-stream`, `Mcp-Protocol-Version: 2026-07-28`, `Mcp-Method` (and `Mcp-Name` for calls), and `params._meta` carrying `io.modelcontextprotocol/protocolVersion`, `clientInfo` and `clientCapabilities`. A no-grant call should come back at once with "No valid grant".
- **Debug:** `audit.jsonl` shows each call and its decision. A request handler that throws lands in `gate.log` as aiohttp's "Error handling request", while the client sees a 500.

## Gotchas

- **pystray** rejects a menu action with more than two parameters, and a `gid=g.id` default counts as one. Bind values with a factory (`revoker`).
- **Tk** runs on the main thread. The asyncio server and pystray each run on their own thread and reach Tk through `UI.post`.
- **The tray redraw is wrapped** so that a failure there can't fail the request that created a grant. It once did, which returned a 500 and lost the grant.
