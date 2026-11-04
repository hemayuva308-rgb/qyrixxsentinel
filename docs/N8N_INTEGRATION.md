# Qyrix Sentinel HTTP node for n8n: Phase 1A (PROTOTYPE, security-remediated)

**Status: PROTOTYPE.** This is not a supported integration. The registry entry `n8n` stays `ROADMAP`.

**Supported target:** self-hosted **n8n 2.46.5 only**. n8n Cloud is **not** supported: you cannot install custom nodes there, pin the settings below, or control the network.

**Phase 1A scope after the security review:** `GET` and `HEAD` only, `https` on port 443 only.

> **Development checkpoint, not a security certification.** This is a controlled prototype. Several audit findings are still open; see [Known findings at this checkpoint](#known-findings-at-this-checkpoint) before relying on any statement below. Nothing here claims production readiness, universal protection, or exactly-once execution.

## What the node does

For every input item, in this order:

1. **Deployment check.** The node refuses to run (`DEPLOYMENT_INSECURE`) unless the pinned n8n hardening below is present.
2. **Strict argument check, done locally.** The method must be `GET` or `HEAD`. The URL must be `https`, canonical and on port 443, with no body. Headers must not include credentials. The lineage must be a fixed value. Anything else is refused before the Gate is asked.
3. **Gate evaluation.** The node calls `POST /api/v1/sentinel/gate/evaluate` over **verified HTTPS** with the exact Action: `tool:"http"`, `method`, `dest` (the URL) and `data`. `data` is a canonical JSON copy of the method, URL and headers. The response must meet all of these conditions:
   - the verdict is **ALLOW**;
   - it contains a well-formed `grant_id`;
   - its `params_digest` equals the digest the node computed locally;
   - its `correlation_id` and `task_id` equal the ones the node sent.

   If any of these fail, the node never attempts redemption.
4. **Grant redemption.** The node calls `POST /api/v1/tools/redeem` with `X-Qyrix-Integration: n8n_http`. This uses the existing single-use grant, bound to the tenant, the agent credential, the `task_id`, the `correlation_id` and the `params_digest`. The response must meet all of these conditions:
   - it says `redeemed:true`;
   - it echoes the same digest, `gate_evaluation_id` and `correlation_id`;
   - it carries a UUIDv4 `execution_id`.
5. **Send, only through the C5 egress proxy.** The node opens `CONNECT <pinned-ip>:443` with `X-Qyrix-Host` and `X-Qyrix-Execution: <execution_id>`. It then runs TLS inside the tunnel, with SNI and certificate verification for the hostname, TLS 1.2 or later. The bytes sent are exactly the authorized request.

   The proxy's N2 `grant_authorizer` independently requires **all** of the following signed Observer claims and conditions for that execution:
   - an `issued` claim for an ALLOW decision on the same host;
   - a **`redeemed`** (or `executed`) claim, which the Gate writes in the same transaction that consumes the grant;
   - no `refused` or `revoked` claim;
   - an age within the grant TTL (`QYRIX_GRANT_TTL_SECONDS`, default 120 s);
   - an active gate stream;
   - one tunnel only, on port 443.
6. **Output.** The node returns `status`, `headers`, `body`, and a `qyrix` block: `verdict`, `gate_evaluation_id`, `execution_id`, `correlation_id`, `task_id`, `params_digest`, `evidence:"E1_ADAPTER_SELF_REPORT"`.

The node **never** emits `ENFORCEMENT_VERIFIED`. Enforcement evidence comes only from the Observer.

The node uses the existing Gate. It doesn't change Gate rules, the policy version, grant lifetime, `params_digest` semantics or Observer evidence semantics. The digest the node computes is byte-identical to `app.gateway._digest`, and a test asserts this.

## Installation (self-hosted 2.46.5)

```bash
docker run ... -v /path/to/repo/integrations/n8n:/qyrix:ro -e N8N_CUSTOM_EXTENSIONS=/qyrix <pinned settings below> n8nio/n8n:2.46.5
```

The node shows up as **"Qyrix Sentinel HTTP (prototype)"**, type `CUSTOM.qyrixHttp`. The package has no npm dependencies.

## Configuration (environment of the n8n process)

| Variable | Required | Meaning |
|---|---|---|
| `QYRIX_SENTINEL_URL` | yes | Must be **`https://host[:port]`**. Plain `http://` is refused for every host, loopback included, so the bearer token is never sent without TLS. |
| `QYRIX_SENTINEL_CA_FILE` | if private PKI | CA for the Sentinel certificate. Verification is never disabled. |
| `QYRIX_SENTINEL_TOKEN_FILE` (preferred) or `QYRIX_SENTINEL_TOKEN` | yes | **Agent** API key. The tenant and agent binding come from this credential. The node has no tenant or credential parameter. Keep the file **outside** `N8N_RESTRICT_FILE_ACCESS_TO`; the node checks this. |
| `QYRIX_EGRESS_PROXY_URL` | **yes** | `http://host:port` of the C5 egress proxy. If it is missing, the node refuses (`EGRESS_NOT_CONFIGURED`) **before** asking the Gate. There is no direct mode. |
| `QYRIX_STATIC_HOSTS` | no | JSON `{"host":"ip"}` pin hint for the CONNECT target. The proxy re-checks the destination either way. |
| `QYRIX_UPSTREAM_CA_FILE` | no | Extra CA for upstream TLS, for tests or a private PKI. When set, it replaces the system trust store. |
| `QYRIX_GATE_TIMEOUT_MS` / `QYRIX_EGRESS_TIMEOUT_MS` | no | Defaults are 10000 and 30000 |

The token file must be readable by the n8n container user (uid 1000).

## Required, pinned n8n settings (checked by the node at run time)

The node runs only when **all** of these are set exactly as shown. Otherwise every item fails with `DEPLOYMENT_INSECURE`, before the Gate is contacted.

```bash
N8N_BLOCK_ENV_ACCESS_IN_NODE=true            # expressions / Code cannot read process.env (the token, the config)
N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES=true      # file nodes cannot read n8n's own files
N8N_RESTRICT_FILE_ACCESS_TO=/home/node/.n8n-files   # explicit, absolute; must NOT contain the token or CA files
NODES_EXCLUDE='["n8n-nodes-base.code","n8n-nodes-base.function","n8n-nodes-base.functionItem","n8n-nodes-base.executeCommand","n8n-nodes-base.ssh","n8n-nodes-base.ftp","n8n-nodes-base.git","n8n-nodes-base.httpRequest","n8n-nodes-base.readWriteFile","n8n-nodes-base.readBinaryFile","n8n-nodes-base.readBinaryFiles","n8n-nodes-base.writeBinaryFile","n8n-nodes-base.localFileTrigger","@n8n/n8n-nodes-langchain.code","@n8n/n8n-nodes-langchain.toolCode","@n8n/n8n-nodes-langchain.toolHttpRequest","@n8n/n8n-nodes-langchain.mcpClient","@n8n/n8n-nodes-langchain.mcpClientTool"]'
```

**Why each excluded node is listed.** The type names were checked against the 2.46.5 image. Each listed node can do at least one of these:

| Capability | Node types |
|---|---|
| Run code | `n8n-nodes-base.code`, `n8n-nodes-base.function`, `n8n-nodes-base.functionItem`, `@n8n/n8n-nodes-langchain.code`, `@n8n/n8n-nodes-langchain.toolCode` |
| Run commands | `n8n-nodes-base.executeCommand`, `n8n-nodes-base.ssh` |
| Read or write local files, including the token | `n8n-nodes-base.readWriteFile`, `n8n-nodes-base.readBinaryFile`, `n8n-nodes-base.readBinaryFiles`, `n8n-nodes-base.writeBinaryFile`, `n8n-nodes-base.localFileTrigger`, `n8n-nodes-base.git`, `n8n-nodes-base.ftp` |
| Make arbitrary HTTP or tool calls outside this node | `n8n-nodes-base.httpRequest`, `@n8n/n8n-nodes-langchain.toolHttpRequest`, `@n8n/n8n-nodes-langchain.mcpClient`, `@n8n/n8n-nodes-langchain.mcpClientTool` |

Setting `NODES_EXCLUDE` **replaces** n8n's built-in default exclusions, so the full list is required.

**`NODES_EXCLUDE` is defense in depth, not a bypass guarantee.** In the n8n 2.46.5 image, `n8n-nodes-base.graphql` (arbitrary POST) and `n8n-nodes-base.rssFeedRead` are **not** excluded, and both reached a local listener directly in a host-networked test. Other service nodes (databases, queues, mail, SaaS APIs) can also open network connections. The network topology below is what stops them. The node checks the settings, not the network.

## Required deployment topology (not optional)

1. **Network:** n8n runs on an internal Docker network with **no route to the internet**. The only egress is the C5 egress proxy, which uses N2 `grant_authorizer` with `untagged_allow=[]`. Phase 0 showed that, in this topology, the stock HTTP Request node, the Code node and DNS bypasses all fail.
2. Sentinel is reached over HTTPS on the internal network. It must not be reachable through the egress proxy.
3. Keep the existing Docker isolation and N2 policy unchanged.

If n8n is run **outside** this topology, the node still behaves fail-closed, but other nodes can reach the network directly. **Do not describe such a deployment as protected.**

## Supported operations

- **`GET` and `HEAD` only.** `POST`, `PUT`, `PATCH` and `DELETE` are refused before the Gate (`METHOD_NOT_SUPPORTED`) and aren't offered in the node UI.
  - **Why:** provenance labels are declared by the caller, and any agent key can create a TRUSTED step. The Gate's lineage rules (R13/R19) therefore can't safely authorize a state change from a workflow. This restriction stays until the provenance trust model is redesigned, which is out of scope for Phase 1A.
- `https` on **port 443 only**, and the URL must be in canonical form (lowercase A-label host, no userinfo, no fragment, no explicit `:443`). A non-canonical URL is refused, not normalized.
- **No request body.**
- **Restricted mode: method, URL, headers and lineage must be fixed values.** The four fields are marked `noDataExpression`, and the node also refuses an expression at run time, so item data (for example a webhook payload) can never choose a destination, a header or a provenance reference. On n8n 2.46.5, n8n strips the leading `=` of such a field and does **not** evaluate it, so an expression reaches the node as literal `{{ ... }}` text. The node refuses both spellings: `LINEAGE_EXPRESSION_NOT_ALLOWED` for lineage and `EXPRESSION_NOT_ALLOWED` for the other three. Tested through the node class with a stub `IExecuteFunctions`; the final code has **not yet** been re-tested inside a real n8n container (an earlier manual probe on a debug copy confirmed the stripped form).
- Destinations must be approved by the Gate, using the standard approved-domains configuration.

## Refused before evaluation (nothing sent, no Gate call)

- **Insecure deployment settings.**
- **Unknown argument keys.**
- **Non-GET/HEAD methods and any body.**
- **Payloads over 65,536 characters** of canonical `data` (`PAYLOAD_TOO_LARGE`).
- **Credential headers:** `authorization`, `cookie`, `x-api-key`, `api-key`, `x-auth-token`, `x-access-token`. The node never accepts upstream credentials in this phase.
- **Hop-by-hop or framing headers** (`host`, `content-length`, `transfer-encoding`, `connection`, `te`, `trailer`, `upgrade`, `keep-alive`, `expect`, `proxy-*`).
- **`x-qyrix-*` headers.**
- **Non-canonical percent-encoding in the URL** (`URL_NOT_CANONICAL`): a lowercase hex digit, an encoded unreserved character such as `%5F`, or a stray `%`. This stops a secret being hidden from a literal-text scanner by spelling it differently.
- **`NODE_TLS_REJECT_UNAUTHORIZED` set to anything but `1`** (`DEPLOYMENT_INSECURE`). The Gate client also requests certificate verification explicitly, so the variable cannot disable it.
- **Retry On Fail enabled on the node** (`RETRY_ON_FAIL_NOT_ALLOWED`).
- **Badly formed headers:** headers that differ only in case, CR/LF/NUL in a header, more than 20 headers, or a header value over 4096 characters.

## Fail-closed behaviour and error outputs

Any of these errors stops the item and sends nothing:

- Gate unreachable, timing out, or returning malformed output.
- A Gate TLS certificate that can't be verified.
- A BLOCK or any other non-ALLOW verdict.
- A missing grant.
- A digest, `correlation_id` or `gate_evaluation_id` mismatch.
- A failed or malformed redemption.
- A missing, unreachable or refusing proxy.
- A missing redemption claim at the proxy.
- A TLS failure.

There is **no fallback to ordinary HTTP**.

Errors look like:

```
Qyrix Sentinel: <CODE> - <detail> [correlation_id=…, task_id=…, gate_evaluation_id=…, execution_id=…, outcome=…]
```

The IDs are opaque identifiers, safe to log; the ones not yet known are left out. `outcome` is one of:

| outcome | meaning |
|---|---|
| `NOT_SENT` | Refused before or by the Gate. No grant was consumed and nothing was sent. |
| `NOT_SENT_GRANT_CONSUMED` | The grant was redeemed, but nothing reached the upstream (proxy refused or unreachable, TLS failed before the request was written). The grant is spent. |
| `UNKNOWN` | The request bytes were written to the upstream, and then the response failed. The upstream **may** have acted. |

With n8n's "Continue On Fail", the item is output as:

```
{qyrix:{error, message, outcome, sent:false|"unknown", correlation_id, task_id, gate_evaluation_id, execution_id, evidence:"E1_ADAPTER_SELF_REPORT"}}
```

The node writes nothing to logs. Error messages never contain the token, headers or request data.

**"Retry On Fail" must stay disabled on this node, and the node enforces it.** If the setting is on, the node refuses before contacting the Gate (`RETRY_ON_FAIL_NOT_ALLOWED`). Without this, a failure after the request was written caused the upstream to receive the request three times (observed on n8n 2.46.5 with three tries). After redemption a failure is `NOT_SENT_GRANT_CONSUMED` or `UNKNOWN`, and a re-run is a new, separately authorized request. Use the IDs in the error to reconcile with the Sentinel records (`EXECUTION_DELEGATED`) and the proxy's tunnel observations before re-running anything.

## Identifiers

- `correlation_id = n8n:<workflowId>:<executionId>:<nodeId>:<itemIndex>`. It is sanitized, and if it is longer than 64 characters it is replaced by a hash.
- `task_id = n8n-wf-<workflowId>`.
- `execution_id` is issued by the Gate at redemption. It is carried in the proxy tunnel tag, in the output and in error IDs.

## Limitations (honest)

- **Not exactly-once.** See the outcomes above.
- **Wait-node resume:** each item is authorized when the node runs, so a resumed execution re-authorizes. No workflow-level protection is claimed, and `workflow.preExecute` is not used.
- **No workflow-level Gate policy,** and no external lifecycle hook acting as an authorization boundary.
- **No state-changing methods,** no credential injection, no request body, and no streaming. The response is buffered, up to 1 MB.
- **One agent identity per n8n instance.** Everyone who can edit workflows acts as the same Sentinel agent. Per-workflow binding is `task_id` only.
- **Claim latency.** The proxy waits up to `GRANT_WAIT` (5 s) for the redemption claim to arrive through the Gate outbox and publisher. If the publisher is slower, or the Observer is down, the request fails closed with the grant spent (`NOT_SENT_GRANT_CONSUMED`). The backlog replays later, but it never opens a late tunnel.
- **Refusal claims are final for an execution.** Any `refused` claim for an execution blocks its tunnel, for example a mistaken or hostile redemption attempt with a stolen grant id by another agent of the same tenant.
- Evidence from the node is **E1 only.**
- Only one n8n version has been tested (2.46.5). Queue mode and multi-main were not tested in this phase.

## Known findings at this checkpoint

Found by an independent read-only audit of this branch. "Fixed" means a test reproduces the problem and the fix is covered.

| ID | Sev | Finding | Status at this checkpoint |
|---|---|---|---|
| A-1 | MEDIUM | `NODE_TLS_REJECT_UNAUTHORIZED=0` disabled Gate TLS verification and sent the bearer token to an impostor | **Fixed in the node**, with a test using an impostor server |
| A-2 | MEDIUM | The Gate secret scanner decodes percent-encoding only once (a keyword encoded twice, e.g. `to%256Ben=`, is not detected). It also has no token-format patterns, so a plain `ghp_…` value with no keyword is allowed | **Node side fixed** (canonical percent-encoding required). **Gate scanner NOT fixed**; adding token-format patterns would be a new Gate policy and is not approved |
| A-3 | MEDIUM | GET/HEAD carry no provenance gating, so workflow data could be sent to an approved host through the URL or headers | **Mitigated in the node** (fixed values only). The Gate itself is unchanged |
| A-4 | MEDIUM | `NODES_EXCLUDE` does not cover every network-capable node | **Documented**; the network topology is the real control, and the topology test for these nodes has not been run |
| A-5 | LOW | The node's expression check never fired on n8n 2.46.5 (n8n strips the `=`) | **Fixed in the node**; not yet re-tested in a real n8n container |
| A-6 | LOW | Retry On Fail repeated the upstream request | **Fixed in the node**; not yet re-tested in a real n8n container |
| A-7 | LOW | The port-443 rule covers tagged CONNECT but not tagged plain HTTP in the egress proxy | **OPEN** |
| A-8 | LOW | The Observer container gets no `QYRIX_GRANT_TTL_SECONDS`, so it always uses 120 s. Set the same value on **both** the Gate and the Observer until this is changed in Compose | **OPEN** (documented only) |
| A-9 | LOW | A redemption claim arriving behind a sequence gap still authorizes | **OPEN**, not approved for change |
| A-10 | LOW | A refusal claim does not identify the caller; with a leaked grant ID, another agent of the same tenant could cause a refusal that denies a legitimate tunnel | **OPEN**, not approved for change |

Also not done at this checkpoint: real-n8n-container regression tests for A-3, A-5 and A-6; Docker Compose validation; the MCP, adapter-core and offline-verifier reviews.

## Tests

| Test file | What it covers | Command |
|---|---|---|
| `backend/tests/test_n8n_http_node.py` | Real Gate over HTTPS, real `EgressProxy` with N2, local TLS origin, claim relay | `cd backend && python -m pytest tests/test_n8n_http_node.py -q` |
| `backend/tests/test_n8n_pg_publication.py` | Real PostgreSQL Gate → outbox → `Publisher` → Observer → proxy → node, including Observer downtime and publisher lag | `cd backend && python -m pytest tests/test_n8n_pg_publication.py -q` |
| `backend/tests/test_observer_n2_pg.py` | The N2 redemption, refusal, TTL and port rules | `cd backend && python -m pytest tests/test_observer_n2_pg.py -q` |

These tests need `node` on `PATH` and the PostgreSQL test clusters. They never contact a real external destination.
