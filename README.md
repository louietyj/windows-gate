# windows-gate

(Formerly mcp-windows-gate. The local folder, the scheduled task and the data directory still carry that name.)

One approval gate on Louie's laptop for everything cloud Claude may do on it, with a backend per thing it guards:

- **PC control** ([`mcp_windows.py`](mcp_windows.py)): [windows-mcp](https://github.com/CursorTouch/Windows-MCP), as claude.ai's `mcp-windows` custom connector.
- **Chrome** ([`pinchtab_windows.py`](pinchtab_windows.py)): a [pinchtab](https://github.com/louietyj/pinchtab) bridge attached to his real Chrome, for the headless-browser skill's `pinchtab-windows` tier.

[`gate.py`](gate.py) is what they share: the grants, the approval dialog, the tray icon and its window, the audit log, and the supervised children (windows-mcp, the bridge, cloudflared).

```
claude.ai connector --Bearer--------> mcp-windows.louietyj.me --cloudflared--> :9340  --> windows-mcp (loopback, random port, per-run key)
sandbox pinchtab-windows --X-Gate-Key--> browser.louietyj.me --+              :19870 --> pinchtab bridge :19877 --> Chrome
```

Each backend has its own listener, credential and grant rules, and a grant works only on the backend that issued it. One tunnel serves both hostnames (`cloudflared.yml`, written at start).

## The tray icon and window

The "G" icon is grey with no grants, green with live ones and red when paused. Its menu, and the window that a double-click opens, list every grant: backend, who asked, the code, the purpose, age, idle time and calls. They also offer:

- **Revoke** one or all.
- **Pause**, which refuses every request *and* every call on a live grant. Pausing also detaches the bridge from Chrome.
- **Detach from Chrome**.
- **Copy** each backend's credential.
- Open the audit log or the data folder.

The window also shows recent activity across both backends.

## How access works (PC control)

The bearer token only lets a caller talk to the gate. Running a tool needs a **grant**, and only Louie's click creates one:

- The gate rewrites `tools/list`. It adds a `RequestGrant(purpose)` tool, gives every windows-mcp tool a **required** `_grant` argument, and adds `ReleaseGrant`. It strips `_grant` before forwarding a call.
- `RequestGrant` pops a topmost Tk dialog showing the stated purpose and the caller IP, and holds the call for up to 140 s. **Allow** returns the grant ID as the whole tool result.
- Any other call without a live grant fails at once with "call RequestGrant first", so dialogs only ever come from explicit requests.
- A grant lapses after 15 min without a call or 1 h total. Grants live only in memory, so a gate restart revokes them all. The tray icon lists them, and offers Revoke, Revoke all and Pause.

A leaked bearer token therefore produces a dialog Louie denies, never a silent call. The grant ID does appear in that conversation's transcript.

## How access works (Chrome)

The sandbox's `pinchtab-windows` shim (claude-skills `headless-browser/setup.sh`) sends the key from the skill's `windows.json` as `X-Gate-Key`. It drives the bridge with pinchtab's own CLI, and the grant goes as the Bearer token:

- `POST /grant {purpose, code, agent}` pops the dialog. The 4-character code is the one Claude has just written in the chat, so Louie can tell his own request from someone else's. `GET /grant/<id>?wait=55` long-polls, staying under Cloudflare's 100 s limit on a request and claude.ai's 300 s limit on a bash call.
- A grant lapses after 30 min idle or 4 h. `DELETE /grant` releases it, and `/active-tab` says which tab Louie is on.
- Every other path is proxied to the bridge, with the grant swapped for the bridge's own token, which never leaves the laptop. `/shutdown`, `/ensure-chrome` and `/browser/restart` are refused.
- **Only pinchtab's HTTP API crosses the tunnel.** pinchtab sends 12-40 CDP messages per command, one after another. Carrying CDP itself over the ~120 ms round trip from claude.ai made a `snap` take 1.5 s and a `nav` 6 s. Through the gate they take 0.27 s and ~1 s.
- **The bridge stays attached between grants.** Chrome asks "Allow remote debugging?" on every attach, so the bridge starts on the first grant and detaches after an hour without one. It is never sent `/shutdown`: before the fork's capsolver.32 fix, its Cleanup closed every tab it had attached, and so the whole of Louie's Chrome. That happened once, on 2026-10-09. The gate kills the process instead, which only drops the connection, after stripping the `[PinchTab :port]` title prefixes. Anything that could close tabs gets tested on a throwaway Chrome (`--remote-debugging-port`, its own `--user-data-dir`).
- **The bridge config is pinchtab's with the guards down,** like Louie's local tier, except that `maxTabs` is 500 with `tabEvictionPolicy: reject`. The default, 20 with `close_lru`, would evict one of his tabs.
- **The bridge binary** is `pinchtab-windows-amd64.exe` from the fork's latest release, checked at start and daily. The sandbox installs the Linux build of the same release, and `grant --wait` warns when the versions differ. `--pinchtab-bin <exe>` runs a local build.
- **The `/json/version` shim on :19871:** Chrome's chrome://inspect debugging mode 404s `/json/*`, which pinchtab needs. The shim answers that itself and splices everything else through to Chrome, re-reading `DevToolsActivePort` on every connection.

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
| Tunnel | Named tunnel `mcp-windows` (`47213dd5-…`), credentials in `~\.cloudflared\47213dd5-….json`, CNAMEs `mcp-windows.louietyj.me` and `browser.louietyj.me`. The gate writes its ingress rules to `cloudflared.yml`. |
| Connector | claude.ai → `mcp-windows`, URL `https://mcp-windows.louietyj.me/mcp`, bearer from the tray's "Copy connector bearer token" |
| Skill | claude-skills `headless-browser/windows.json`: `browser.louietyj.me` and the key from the tray's "Copy browser gate key", shipped in the skill zip |
| State | `%LOCALAPPDATA%\mcp-windows-gate\`: `bearer.txt`, `browser-key.txt`, `audit.jsonl` (each event tagged with its backend), `gate.pid`, `gate.log`, `windows-mcp.log`, `cloudflared.log`, and `pinchtab\` (the bridge's binaries, config and `bridge.log`) |

The gate supervises windows-mcp (`uvx windows-mcp serve --transport streamable-http …`), the bridge and `cloudflared tunnel run`, restarting windows-mcp and cloudflared if they die. All of them sit in a kill-on-close job object, so they exit with the gate. Its dependencies are declared inline (PEP 723), so `uv run --script` needs no install step.

## Operating it

- **Restart:** `Stop-ScheduledTask mcp-windows-gate; Start-ScheduledTask mcp-windows-gate`. Stopping kills only the `uvw` launcher and leaves the gate running, so each new gate terminates the previous one itself. It identifies it from `gate.pid`, which stores PID plus creation time, so a recycled PID can't match.
- **Rotate the bearer:** delete `bearer.txt`, restart, then paste the new token into the connector. For the browser key, delete `browser-key.txt`, restart, then update the skill's `windows.json` and re-upload the zip.
- **Test copy beside the live one:** `uv run --script gate.py --port 9341 --hold 10 --no-replace --only mcp-windows`, with no `--tunnel`. The pinchtab backend's ports are fixed, so test it with the live gate stopped, or with `--only pinchtab` while the live one is down.
- **Hand-probe:** POST to `/mcp` with `Authorization: Bearer …`, `Accept: application/json, text/event-stream`, `Mcp-Protocol-Version: 2026-07-28`, `Mcp-Method` (and `Mcp-Name` for calls), and `params._meta` carrying `io.modelcontextprotocol/protocolVersion`, `clientInfo` and `clientCapabilities`. A no-grant call should come back at once with "No valid grant".
- **Debug:** `audit.jsonl` shows each call and its decision. A request handler that throws lands in `gate.log` as aiohttp's "Error handling request", while the client sees a 500.

## Gotchas

- **pystray** passes `(icon, item)` to as many parameters as an action has, and a `v=value` default counts as one. Bind values with a factory (`revoker`, `copier`).
- **The backends `from gate import …`** while `gate.py` runs as `__main__`. `main()` registers itself as `gate` first; otherwise the backends get a second copy of the module, with its own activity list.
- **Tk** runs on the main thread. The asyncio server and pystray each run on their own thread and reach Tk through `UI.post`.
- **The tray redraw is wrapped** so that a failure there can't fail the request that created a grant. It once did, which returned a 500 and lost the grant.
