# MCP Streamable HTTP proxy (`backend/app/mcp_http_proxy.py`)

Status: **BUILT, tested against a hand-written HTTP MCP fixture only.** Not claimed production-ready or bypass-proof.
Integration id: `mcp_proxy_http` (`app/integrations.py`).

## Pinned protocol revision
**MCP 2025-11-25**, POST-only subset ([transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)).
The 2026-07-28 revision (no sessions, no `initialize`) is **not** interchangeable and is refused (`initialize` must carry
`protocolVersion: "2025-11-25"`; every later request must carry `MCP-Protocol-Version: 2025-11-25`; an upstream that
negotiates another version is rejected).
Confirmed from official pages: `MCP-Session-Id`, `MCP-Protocol-Version`, 403 for an invalid Origin, and an `Accept`
header listing both `application/json` and `text/event-stream`. **Not confirmed from retrieved text** (implemented from the
spec as understood, tested only against our own fixture): `202 Accepted` for notifications, `404` for an unknown session.
Re-check these against the live page before relying on third-party interoperability.

## Operations
| Supported | Refused |
|---|---|
| `initialize`, `ping` (answered locally), `tools/list` (relayed, observed for the coverage report), `tools/call` (Gate-protected), `notifications/initialized`, `notifications/cancelled`; `DELETE` (ends the proxy session) | JSON-RPC **batches**; **GET** and other verbs (405: no server-initiated stream); **resumability / `Last-Event-ID`**; client responses to server requests; `resources/*`, `prompts/*`, `completion/*`, `logging/*`, `sampling/*` and every other method (-32601); unknown notifications |

Responses are **always buffered and returned as one `application/json` message** (no incremental streaming). The upstream
may answer with JSON or an SSE stream (strict bounded parser; an unterminated final event is discarded). **Priming events**
(an SSE event with an id and an empty data field, a SHOULD in 2025-11-25) are skipped and counted; they can never be a
response, and non-empty malformed data still fails the exchange. **Resumability and polling remain unsupported**: a server
that closes the stream after a priming event *before* sending the response yields an unknown outcome (no `Last-Event-ID` GET). Notifications in
the stream are dropped; a **server-initiated request** in the stream is answered *toward the upstream* with a JSON-RPC
error and never relayed to the client.

## Authentication and sessions
* Every request needs `Authorization: Bearer <client token>`. `--client-tokens-file` holds `{client_id: sha256-hex(token)}`
  (hashes only; compared in constant time). Generate: `python3 -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" <token>`.
* `Host` must be in the allow-list (default: the `--listen` value); any `Origin` header is refused unless listed.
* Binds to loopback by default; a non-loopback bind needs `--allow-non-loopback` and **TLS in front** (the proxy itself
  speaks plain HTTP). Upstream must be `https://` (`http://` only on loopback); redirects are not followed.
* One proxy instance = **one Sentinel credential** (`QYRIX_TOKEN[_FILE]`), so all clients of an instance share one Gate
  agent identity and tenant. Use one instance per agent/tenant. Per-client identity at the Gate is NOT provided.
* Sessions are issued by the proxy (`secrets.token_urlsafe(32)`), bound to the authenticating client; foreign and unknown
  sessions are indistinguishable (404). The upstream session id never reaches the client. Bounded count and idle TTL.

## Argument policy (applies to the stdio AND the HTTP proxy)
Existing `tools.json` files must be migrated: see [MCP_TOOLS_JSON_MIGRATION.md](MCP_TOOLS_JSON_MIGRATION.md).
The Gate evaluates exactly one destination (`dest_arg`) and one method (`method` from the mapping). So every mapped tool
must declare the **complete** set of arguments it may receive, and anything else is refused *before the Gate is asked*
(rule code `ARGS_POLICY_<reason>`; nothing is evaluated, redeemed or forwarded):
```json
{"tools": {"fetch": {"tool": "http", "method": "GET", "dest_arg": "url", "args": ["url", "text"]}}}
```
* `args` is required, must contain `dest_arg`, and must contain **no other destination-like name** (`url`, `uri`, `endpoint`,
  `host`, `callback_url`, `webhook`, `path`, ... after case/separator normalisation) and **no method-like name**
  (`method`, `http_method`, `verb`). An ambiguous or allow-list-less mapping is rejected at startup (and blocked at call time).
* Per call: an argument outside `args`, a missing or non-string destination, or a non-scalar value (an object or array could
  hide a second destination) is refused. Arguments are never dropped or rewritten, so the upstream receives exactly the
  arguments that were digested and authorised.
* Unmapped tools are unchanged: the Gate refuses them (R8).
* Limits: values of *allowed* non-destination arguments are not interpreted (a `text` value containing a URL is the tool's
  business); a rejected call leaves no Gate decision record (the Gate was never asked); this is a name-based heuristic, so the
  operator must still list only arguments the tool genuinely treats as data.

## Authorization (unchanged)
`tools/call` -> `core.ToolCallGuard` -> `POST /gate/evaluate` -> `POST /tools/redeem` (single-use grant, exact
`params_digest`, agent/task/policy binding) -> only then a **fresh** upstream request carrying the exact evaluated message.
BLOCK, Gate errors, refused redemption and unmapped tools (R8) never reach the upstream. The upstream request is built from
an explicit header allow-list (`Content-Type`, `Accept`, `Accept-Encoding: identity`, `MCP-Protocol-Version`,
`MCP-Session-Id` (upstream's own), and `Authorization` **only** from `QYRIX_MCP_UPSTREAM_TOKEN[_FILE]`). The client's
Authorization is never forwarded.

## Retries and duplicates (not exactly-once)
Per session, bounded and **in memory (lost on restart)**: a duplicate request id *in flight* is refused (-32002); a
*completed* call is answered from a cache (same id and params; the tool is not run again); an id reused with different
params is refused. If the outcome is **unknown** (timeout, broken/oversize/unterminated stream, upstream error after the
grant was redeemed) the call is **never re-executed**: retries get -32003. Calls that fail *before* redemption (BLOCK,
Gate down) are not cached and may be retried. A client that picks a new request id performs a new execution. After a
restart the dedupe state is gone, so a retry may execute again. Cancellation (`notifications/cancelled`) is forwarded but
cannot undo an execution.

## Evidence boundary
Adapter reports are **E1 self-reports** (fire-and-forget, `AdapterReporter`; set `QYRIX_OBSERVER_ADAPTER_ID=mcp_proxy_http`)
and are never independent enforcement proof. Only observer sensors (egress proxy, canaries) produce E3. The coverage report
(`--coverage-file`) is advisory configuration analysis.

## Limitations
* **Direct upstream access bypasses the proxy.** The upstream URL is operator-configured trust; nothing here stops a client
  from calling it directly. Restrict it with upstream authentication/network rules; the C5 chokepoint helps only inside the
  Docker topology (the upstream then needs an operator allow-list entry because the proxy's own hop is untagged).
* Only `http`/`file.read`-shaped tools are Gate-evaluated; all others are default-denied (R8). No Gate change was made.
* No third-party MCP server/SDK interoperability test exists; no TLS test; no load test; no incremental streaming.
* Task ids come from `_meta["qyrix/task_id"]` and are caller-provided, not verified. Correlation ids are not unique-checked
  by the Gate (pre-existing).
