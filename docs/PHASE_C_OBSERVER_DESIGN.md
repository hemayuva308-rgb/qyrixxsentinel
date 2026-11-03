# Phase C: Independent Observer Service (architecture design, for review; NOT implemented)

Status: **design only.** Nothing in this document is implemented. It changes no code, schema or behaviour. Every
"will" below is a proposal for review.

## 0. Summary
Today's Continuous Enforcement Verification (CEV) catches an adapter that ignores a BLOCK. It cannot catch a
compromised backend, because the observer, the canary tokens, the decision it reconciles against and the evidence
store all live in the backend. Phase C moves observation into a separate **Observer Service**. The service has:
- its own process, container and lifecycle;
- its own database, its own keys and its own evidence chain.

Gate decisions reach it as **signed claims to be checked, never as evidence of enforcement**. A result can be
`ENFORCEMENT_VERIFIED` only with **observer-originated evidence** for the channel, under three conditions:
- the observer can show that **the channel is mediated by it** (no unobserved path exists);
- its sensors passed a **positive control** in the same window;
- the observation window closed.

Anything less is `INCONCLUSIVE`.

## 1. Existing architecture audit (as implemented at `b7b6064`)
| Component | Where | What it does today | Independence finding |
|---|---|---|---|
| Execution Observer | `app/cev.py` (`CanaryHttpObserver`, `CanaryFileObserver`, `observers()`) | Loopback HTTP listener on `127.0.0.1:<ephemeral>` in a backend thread; canary files in a temp dir; hits kept **in memory** | Same process, memory, kernel namespace and credentials as the Gate. Hits are lost on restart. Backend code can read and clear them (`forget()`) |
| Canary runs | `cev.run_canary` | The **backend** generates the correlation id and canary token, calls the adapter in-process, waits for the window | A compromised backend chooses the tokens and can avoid or fake them |
| Reconciler | `cev.reconcile` (pure) | Truth table; missing or unproven telemetry gives INCONCLUSIVE; a seen side effect wins | Sound logic, **but the decision it uses is the Gate's in-process return value** (`adapter.submit()["decision"]`). That is a self-report |
| CEV evidence | `g._record(ctx, entry)`, kind `cev_reconciliation` | Written to the **backend's own** proof chain and DB mirror | The party being verified stores the verdict about itself |
| Adapter contract / registry | `app/integrations.py` | Capability declarations; fixtures; `RestApiAdapter` | Adapter self-reports are already never trusted (good) |
| MCP proxy | `app/mcp_proxy.py` | stdio proxy in the user's environment: `tools/call` → evaluate → `/tools/redeem` → forward | No telemetry leaves the proxy except through the backend; MCP-server egress is not observed at all |
| Gate + grants | `gateway.evaluate`, `execute_grant`, `redeem_grant` | Deterministic rules R0–R20; single-use grants bound to agent, task, policy version and params digest; atomic SQL consume | Authorization is sound. There is **no execution id** separate from `gate_evaluation_id`, and no outbound marker an observer could correlate |
| Proof chain | `app/proof.py`, chain file + `proof_records` mirror | SHA-256 hash-linked records, canonical JSON | Integrity, not authenticity. The backend can append anything |
| State witness | `app/integrity.py` | HMAC high-water mark on a separate volume; checked at persistence attach (durable mode only) | Detects truncation or regression at attach. The key and volume are mounted **into the backend container** |
| RFC 3161 anchoring | `app/anchor.py`, `proof.evaluate_anchors` | Optional, off by default; local TSA tested only | Independent timestamp **if** a public TSA is configured; does not cover records after the latest anchor |
| Database | PostgreSQL 16, roles `qyrix` (admin/superuser), `qyrix_runtime`, `qyrix_app`, `qyrix_auth`, `qyrix_maint`; RLS by `qyrix_tenant()` | Least privilege for the backend | One cluster, one superuser: **any observer table in this cluster shares that trust root** |
| Network (`docker-compose.yml`) | `internal` (no egress), `edge` (frontend only); opt-in `docker-compose.egress.yml` adds `egress` to the backend | Backend has no internet unless the overlay is used | With the overlay, the backend egresses **directly**: no chokepoint exists today |
| Crypto available | `cryptography 50.0.2` (pinned) | Used for AES-GCM today | Ed25519 signatures are available **without new dependencies** |

**Consequences that shape the design:**
- an observer that shares the backend's process, keys, DB superuser or egress path is not independent;
- "nothing observed" proves enforcement only if the observer **mediates every path** of that channel;
- a decision record, even signed, is a **claim**. It is compared with observations; it does not count as one.

## 2. Proposed architecture
```
                          trust boundary A: Sentinel backend (may be compromised)
  ┌───────────────────────────────────────────────────────────────────────────────────────┐
  │  frontend ──► backend (Gate, grants, adapters, MCP redeem API)                          │
  │                 │  signs decision/grant events with GATE key (Ed25519, publish-only)    │
  │                 │  durable OUTBOX (backend DB) ──► publisher thread                      │
  │                 ▼                                                                        │
  │           backend PostgreSQL (existing)          state witness (existing)               │
  └─────────────────┼──────────────────────────────────────────────────────────────────────┘
                    │ HTTPS (mTLS across hosts) on `observer_ingest` network, signed events only
  ┌─────────────────▼──────────────────────────────────────────────────────────────────────┐
  │  trust boundary B: Observer Service (separate container, own keys, own DB, own volumes) │
  │   ingest API ── verify signature, scope, replay, skew ──► observer ledger (hash chain,   │
  │                                                            signed by OBSERVER key)       │
  │   sensors (observer-originated evidence):                                                │
  │     • canary HTTP listener   (canary network; tokens minted BY THE OBSERVER)            │
  │     • canary file watcher    (observer-owned canary volume, inotify + snapshot)          │
  │     • egress chokepoint      (forward proxy; the ONLY route to `egress` when enabled)    │
  │   canary scheduler ── drives must-block canaries THROUGH integrations (canary agent key) │
  │   coverage prober ── proves bypass routes are closed (direct egress must fail)           │
  │   reconciler v2 ── evidence levels + coverage + positive control + window ──► results    │
  │   shadow policy check (advisory) ── independent re-evaluation of ALLOW claims            │
  │   observer PostgreSQL (SEPARATE container, own superuser) · observer witness · anchors   │
  │   read API (tenant-scoped keys) ──► dashboard / exports;  alert webhook ──► operators   │
  └───────────────────────────────────────────────────────────────────────────────────────┘
          ▲ canary traffic / mediated egress                         ▲ adapter self-reports (E1, signed)
  ┌───────┴─────────────────────────────┐                  ┌─────────┴─────────────────────────┐
  │ integrations: REST adapters, MCP    │                  │ MCP proxy (user env): publishes    │
  │ proxy, fixtures (boundary C)        │                  │ adapter events with ADAPTER key    │
  └─────────────────────────────────────┘                  └────────────────────────────────────┘
          trust boundary D: host / Docker daemon / kernel (shared by A and B in single-host compose)
```

**Process and code layout.**
- New package `backend/observer/`, with **no import of `app.gateway` or the backend's DB or identity code**. It
  shares only `app/proof.py` (pure hash-chain functions) and a pure canonical-JSON/signature helper, vendored into the
  package.
- Entrypoint: `python -m observer.main`.
- Same base image digest, separate compose service, separate build target later (smaller dependency set).

**Trust boundaries:**

| Boundary | Contains | Assumed compromise in the threat model? | Holds |
|---|---|---|---|
| A | backend, frontend, backend DB, backend witness | **Yes** (central scenario) | GATE signing key (publish only), canary agent credential is **not** here |
| B | observer, observer DB, observer witness, observer keys | No (trusted base); its compromise is out of scope, but mitigated by anchoring and exports | OBSERVER signing key, observer DB superuser, canary agent API key |
| C | integrations / adapters / MCP servers | Yes (an adapter may ignore decisions or lie) | ADAPTER keys (E1 self-reports only) |
| D | host, Docker daemon, kernel | Out of scope for single-host compose | Separation of A and B is **process/container-level**, not machine-level. Stated, never hidden |

## 3. Data flow
1. **Decision.** The Gate evaluates (unchanged).
   - In the same critical section that writes the proof record, it writes a **decision event** to a new backend
     **outbox** table.
   - A publisher thread signs each event with the GATE key and POSTs it to the observer. It retries with backoff;
     events are never dropped silently.
2. **Grant use.** On `execute`/`redeem`, the Gate mints an **`execution_id`** (UUIDv4, bound to the grant) and
   publishes a grant event (`redeemed`/`executed`/`refused`).
   - Sentinel's own HTTP adapter sends `X-Qyrix-Execution: <execution_id>` through the egress chokepoint.
   - The MCP proxy forwards the `execution_id` to the server in `_meta`, best effort.
3. **Observation.** The sensors record what they see, with observer timestamps:
   - canary hits;
   - canary file events;
   - chokepoint requests (CONNECT host:port and bytes for TLS; full method, path and body hash for plain HTTP and
     canaries).
4. **Canaries.** Observer-initiated: **the observer mints the token**.
   - It sends the must-block action **through the integration** using a dedicated `canary` agent API key, and awaits
     the decision event.
   - It checks its own sensors over the window. Before the window: positive control; within the hour: coverage probe.
5. **Reconciliation.** In the observer: claims (decision and grant events) against evidence (observations), with
   coverage and health. The result is appended to the **observer ledger**, signed, and optionally anchored.
6. **Consumption.** Reconciliation results flow back to the backend dashboard **by pull from the observer's read
   API**, never by the observer writing into the backend DB. Alerts go from the observer to an operator webhook
   directly.

## 4. Threat model and attack scenarios (STRIDE-oriented)
| # | Attacker | Attack | Expected observer outcome | Design element |
|---|---|---|---|---|
| T1 | Compromised backend | Records BLOCK but performs the action itself via its own code | Effect seen at chokepoint or canary with a BLOCK or no claim → **BYPASS_DETECTED** or **UNAUTHORIZED_EXECUTION** | Mediated egress; claims ≠ evidence |
| T2 | Compromised backend | Suppresses decision events | Effect without a claim → UNAUTHORIZED. Sequence gap → **DECISION_FEED_GAP**: affected windows INCONCLUSIVE plus an alert | Per-producer `seq`, gap detection |
| T3 | Compromised backend | Forges an ALLOW + execution for exfiltration to an approved-looking host | Claim and effect match, but the **shadow policy check** disagrees → INCONCLUSIVE + `POLICY_DIVERGENCE` alert (never VERIFIED) | Independent deterministic re-evaluation (advisory, never authorizing) |
| T4 | Compromised backend | Uses an unmediated channel (direct socket, DNS tunnelling, file side channel) | No evidence possible → **INCONCLUSIVE (COVERAGE_GAP)**, never VERIFIED | Coverage attestation per channel |
| T5 | Compromised backend | Steals the GATE key and injects fake **observations** | Rejected: the GATE key's scope is `decision`/`grant` only; observations come only from internal sensors | Per-key scopes |
| T6 | Compromised backend | Writes or deletes observer rows via shared DB credentials | Impossible by construction: separate PostgreSQL container and superuser; backend has no route or credentials | Separate observer DB |
| T7 | Compromised backend | Replays old signed events, or reorders them | `event_id` unique, per-producer `seq` monotonic, `issued_at` within skew → refused as `REPLAY` / `OUT_OF_ORDER` | Replay protection |
| T8 | Compromised backend | Floods ingestion (DoS) | Rate limit per producer; queue bound; overload → INCONCLUSIVE, never VERIFIED | Back-pressure |
| T9 | Compromised backend | Avoids canaries (detects test traffic) | Tokens and timing chosen by the observer, using an ordinary-looking agent credential; canaries are indistinguishable at the Gate API | Observer-initiated canaries |
| T10 | Malicious adapter | Ignores BLOCK and lies in its self-report | Sensors show the effect → BYPASS; the self-report is E1 and never decides | Evidence levels |
| T11 | Malicious adapter | Executes different arguments than evaluated | Chokepoint request ≠ claim's method/host/path digest → UNAUTHORIZED (`ARGUMENT_DEVIATION`) | Execution id + params match |
| T12 | Network attacker | Tampers with events in transit | Ed25519 signature fails → refused; mTLS across hosts | Signatures + mTLS |
| T13 | Insider with backend DB superuser | Rewrites backend proof chain | Observer ledger holds signed copies of the claims, so divergence is reported by cross-check | Observer as second ledger |
| T14 | Compromised observer (out of scope) | Hides bypasses or invents them | Mitigated, not prevented: external RFC 3161 anchoring of the observer chain, exportable bundles, optional second observer later | Residual risk |
| T15 | Host / Docker compromise (out of scope) | Controls both containers | No guarantee in single-host compose; documented. Separate host recommended | Residual risk |
| T16 | Clock manipulation | Shifts windows | Observer uses its own monotonic clock; skew bound on `issued_at`; anchors give external time | Time policy |

## 5. Evidence levels and reconciler v2
| Level | Source | Can support VERIFIED? |
|---|---|---|
| **E3 observer-direct** | Observer's own sensor saw it (canary hit, canary file event, chokepoint record) | Yes, with coverage + positive control + closed window |
| **E2 resource-attested** | A signed receipt from the target resource itself (future, e.g. a webhook signed by the target) | Yes (future) |
| **E1 adapter-reported** | Signed self-report from an integration | **No**: informational only |
| **E0 Gate-reported** | Decision or grant events | **No**: these are the *claims* being verified |
| colocated | Today's in-process observer (`app/cev.py`) | Kept for compatibility, labelled `colocated`; **does not count** under the Phase C threat model |

**VERIFIED rules (all must hold; otherwise INCONCLUSIVE with explicit reasons):**
- **BLOCK claim:**
  - the claim's signature is valid and it arrived within the window;
  - the channel is **mediated**, with a current coverage attestation (bypass probe passed within its interval);
  - the positive control passed in this window;
  - the window is closed;
  - no matching E3 observation exists (a match gives **BYPASS_DETECTED**).
- **ALLOW claim:**
  - a matching `redeemed`/`executed` grant event exists;
  - an E3 observation carries the same `execution_id`, or for TLS is the only mediated connection to `dest_host` in
    the window;
  - method, host and path (and the body hash where visible) match the claim's digest;
  - the decision arrived before the effect;
  - the shadow policy check agrees.

  Any mismatch gives **UNAUTHORIZED_EXECUTION** or INCONCLUSIVE with a reason.
- **No claim, E3 effect seen:** UNAUTHORIZED_EXECUTION.
- **Only E0/E1 evidence, observer unhealthy, feed gap, signature failure, unknown producer, tenant mismatch, or clock
  skew:** INCONCLUSIVE. **Never VERIFIED.**

## 6. API and event schemas (all bodies: canonical JSON with sorted keys, UTF-8, ≤ 64 KiB)
**Envelope (every ingested event):**
```json
{"schema": "qyrix.event/v1", "event_id": "<uuid4>", "producer_id": "gate:<install_id>|adapter:<integration_id>",
 "key_id": "<ed25519 key id>", "seq": 1042, "issued_at": "2026-11-03T06:00:00.123Z", "tenant": "default",
 "type": "decision|grant|adapter_report", "body": { ... }, "sig": "<base64 Ed25519 over canonical(envelope without sig)>"}
```
**Event bodies:**
- `decision` body: `gate_evaluation_id, correlation_id, agent_id, task_id, policy_version, verdict, rule_ids, tool,
  method, dest_host (A-label), params_digest, proof {n, hash}`.
- `grant` body: `gate_evaluation_id, grant_id, execution_id, kind (issued|redeemed|executed|refused), integration,
  refusal_code?, params_digest, proof {n, hash}`.
- `adapter_report` body: `execution_id?, correlation_id, integration, claims {forwarded: bool}`. E1 only.

**Observation (internal, never ingested from outside):**
`observation_id, sensor (canary_http|canary_file|egress_proxy), observed_at (observer clock), channel, tenant?,
canary_token?, execution_id?, method?, host, path_sha256?, body_sha256?, bytes, connection_id`.

**Reconciliation record (observer ledger):**
`recon_id, tenant, correlation_id, execution_id?, claim_refs [event_id], claim_sig_valid, observation_refs,
coverage {channel, mediated, attestation_at, positive_control_at}, window {opened, closed}, evidence_level, result,
reasons, n, prev, hash, observer_sig`. The `n`/`prev`/`hash` fields use the same rules as `app/proof.py`.

**Observer HTTP API (port 9000, `observer_ingest` network only):**

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/events` | Ed25519 envelope + registered producer key with scope | Ingest decision / grant / adapter_report |
| POST | `/v1/canaries/run` | operator key | Run a canary now (adapter, channel) |
| GET | `/v1/reconciliations?tenant=&since=` | tenant-scoped read key | Results for the dashboard |
| GET | `/v1/evidence/export?tenant=` | tenant-scoped read key | Signed observer ledger bundle (verifiable offline) |
| GET | `/v1/health` | none | Liveness only: no data, no counts |
| GET | `/v1/status` | operator key | Sensor health, coverage attestations, feed gaps, queue depth |
| POST | `/v1/producers` | operator key (out-of-band) | Register a producer public key and scopes |

**Error codes:** `SIGNATURE_INVALID`, `UNKNOWN_PRODUCER`, `SCOPE_DENIED`, `REPLAY`, `OUT_OF_ORDER`, `CLOCK_SKEW`,
`TENANT_MISMATCH`, `OVERSIZE`, `RATE_LIMITED`.

## 7. Database changes (all additive; none applied in this phase)
**Backend DB, migration `008` (proposal):**
- `observer_outbox`: `event_id`, `tenant_id`, `seq`, `type`, `body jsonb`, `created_at`, `sent_at`, `attempts`. RLS by
  tenant. The runtime role gets INSERT plus UPDATE of `sent_at`/`attempts` only.
- `grants.execution_id uuid NULL`.

Nullable additions only. There is no rewrite, and old code ignores them.

**Observer DB (new, separate PostgreSQL container `observer-db`, own superuser and own volume), migrations
`observer/migrations/O001…`:**
- tables `producers`, `events` (unique `event_id`; unique `(producer_id, seq)`), `observations`, `canary_runs`,
  `coverage_attestations`, `reconciliations` (hash-chained), `alerts_sent`;
- roles `observer_admin` (migrations), `observer_runtime` (INSERT/SELECT; no UPDATE/DELETE on evidence tables; RLS by
  tenant), `observer_reader` (SELECT on reconciliations for the read API);
- append-only triggers on evidence tables, as the backend already does.

**Separation guarantee:** the backend has **no network route and no credentials** to `observer-db`, and the observer
has **none** to the backend DB. No shared superuser.

## 8. Secure communication and keys
| Key | Generated by | Stored in (compose secret) | Mounted into | Scope |
|---|---|---|---|---|
| `gate_signing_key` (Ed25519) | operator setup | `secrets/gate_signing_key` | backend only | sign `decision`, `grant` |
| `observer_signing_key` (Ed25519) | operator setup | `secrets/observer_signing_key` | observer only | sign ledger records + exports |
| `observer_witness_key` (HMAC) | operator setup | `secrets/observer_witness_key` | observer only | observer state witness |
| `observer_db_*_password` | operator setup | separate secrets | observer + observer-db only | DB |
| `canary_agent_api_key` | created via the existing key API (role `agent`, its own key) | `secrets/canary_agent_key` | observer only | submit canaries like any agent |
| adapter keys (Ed25519) | per integration | integration's environment | MCP proxy etc. | `adapter_report` only |

- **Public keys** are registered with the observer out of band (operator CLI), never fetched from the backend at
  runtime.
- **Transport:**
  - within one compose project: an internal network plus signatures;
  - across hosts: mTLS with pinned certificates (stdlib `ssl`, no paid PKI);
  - rotation: new `key_id`, an overlap window, then the old key is revoked in the observer registry.

## 9. Health, timeouts and failure handling
| Failure | Detection | Result | Gate impact (default) |
|---|---|---|---|
| Observer down | Publisher retries; outbox grows | Windows without the observer give INCONCLUSIVE (`OBSERVER_UNAVAILABLE`); backlog replays later with original `issued_at` | **None.** The observer is not in the authorization path |
| Observer slow / queue full | Queue depth, ingest latency | 429 to producers; INCONCLUSIVE for affected windows | None |
| Observer DB down | Write failure | Ingest refuses (503); results INCONCLUSIVE; alert | None |
| Feed gap (missing `seq`) | Gap detector | `DECISION_FEED_GAP`; windows covering the gap INCONCLUSIVE; alert | None |
| Signature invalid / unknown producer / scope denied | Ingest | Event refused and recorded as a security event; alert | None |
| Replay / out of order / skew | Ingest | Refused, recorded | None |
| Canary listener down | Positive control fails | INCONCLUSIVE (`POSITIVE_CONTROL_FAILED`) | None |
| Bypass route open (coverage probe succeeds directly) | Coverage prober | `COVERAGE_GAP`: every BLOCK on that channel INCONCLUSIVE; **critical alert** | None |
| File canary watcher lost events | inotify overflow / snapshot drift | INCONCLUSIVE for that window | None |
| Observer ledger tampered | Observer chain verify + witness at start | Observer degrades: results INCONCLUSIVE; alert | None |
| Backend down | No events | Nothing to reconcile; canaries report `NO_DECISION_RECORDED` → INCONCLUSIVE | n/a |
| Network partition | Both sides | As "observer down" | None |
| **Optional strict mode** `QYRIX_REQUIRE_OBSERVER=1` (proposal, default OFF, needs separate approval) | Health check | — | State-changing ALLOWs would BLOCK with a new rule `R21_OBSERVER_UNAVAILABLE` |

**Timeouts:**
- publisher: 2 s connect, 5 s request, exponential backoff up to 60 s;
- observation window: default 2 s for canaries, configurable up to 30 s;
- coverage attestation: valid for 1 h;
- positive control: in each canary window.

## 10. Deployment (Docker Compose, no paid infrastructure)
New services in `docker-compose.observer.yml` (overlay, **opt-in**; the default stack is unchanged):
- `observer-db` (pinned `postgres:16-alpine` digest, own volume and superuser secret, network `observer_db` only);
- `observer-migrate` (one-shot, admin secret, like `migrate`);
- `observer`:
  - networks `observer_ingest` (with backend), `observer_db`, `canary` (with the backend and integrations), and
    `egress` when the chokepoint is enabled;
  - read-only root and `cap_drop: ALL`, like the backend;
  - own secrets, own volumes: `observer_witness`, `observer_canary`.

**Egress overlay change (proposal):** with the observer enabled, the backend **leaves the `egress` network** and
reaches the internet only through the observer's forward proxy. This is what makes HTTP egress *mediated* and lets
"no effect seen" mean something. Without this overlay change, HTTP egress coverage is `unmediated`, and BLOCKs on that
channel can only be verified through canaries.

**Single-host caveat:** containers on one Docker host share the kernel and daemon (boundary D). For
backend-compromise guarantees beyond container escape, run the observer on a separate host. That needs mTLS and costs
nothing extra beyond a machine the operator already has.

## 11. Migration and backward compatibility
- **Unchanged by default.** The current in-process observer and the `/api/v1/sentinel/cev/*` endpoints keep working.
  Their records gain `evidence_level: "colocated"` in the API output only (no schema change).
- **With the overlay enabled:**
  - the dashboard shows observer results next to colocated ones, clearly labelled;
  - colocated results never count toward "independently verified".
- **Backend DB migration 008 is additive.** The outbox is unused unless `QYRIX_OBSERVER_URL` is set, and old backends
  ignore the new column.
- **No change to Gate authorization**, R0–R20, R19/R20 behaviour, grant binding or policy version. The optional R21
  strict mode needs its own approval.
- **Removal of the colocated observer** happens only after the observer service passes the compatibility and regression
  suites, as you required.

## 12. Test and security validation plan
**Unit:**
- canonical JSON and signature round-trips;
- envelope validation (every error code);
- replay, out-of-order and skew;
- scope enforcement;
- reconciler v2 truth table, with an **exhaustive check that E0/E1-only, unhealthy, gap and unmediated inputs never
  produce VERIFIED**;
- observer chain and witness.

**Integration (two real processes):**
- backend plus observer over HTTP;
- outbox replay after the observer restarts;
- observer-initiated canary through the REST adapter and the MCP proxy;
- positive control;
- coverage probe.

**Adversarial (backend compromise simulated by a test harness with the GATE key):**
- T1: forged BLOCK plus direct canary hit → BYPASS;
- T2: suppressed events → feed gap plus INCONCLUSIVE;
- T3: forged ALLOW that the shadow policy rejects → INCONCLUSIVE plus divergence alert;
- T5: GATE key used to post an observation → `SCOPE_DENIED`;
- T6: backend DB role cannot even connect to the observer DB (negative network and credential test);
- T7: replay;
- T11: argument deviation.

**Isolation:** observer DB RLS per tenant; read keys tenant-scoped; cross-tenant reads refused.

**Chaos:** kill the observer mid-window, observer DB down, clock jump. Each gives INCONCLUSIVE, **never VERIFIED**.

**Regression:** the full backend suite, Benchmark v2 (digest unchanged for existing tiers), frontend build, gitleaks,
bandit.

**Benchmark extension:** a new system-check group, `observer_independence`, run against the two-process deployment and
reported separately.

## 13. Implementation phases and risks
| Phase | Scope | Exit criteria |
|---|---|---|
| C1 | `backend/observer/` package: signed ingest, producer registry, replay protection, own DB (O001), hash-chained signed ledger, health and status | Unit + integration tests; backend unchanged |
| C2 | Backend: outbox (migration 008, additive), Ed25519 decision/grant publisher, `execution_id` on redeem/execute; MCP proxy adapter reports | Backend suite green; publisher retry and outbox replay tests |
| C3 | Observer sensors: canary HTTP/file in the observer, observer-initiated canaries via the canary agent key, positive control | Canary through REST adapter and MCP proxy reconciled in the observer |
| C4 | Reconciler v2 (evidence levels, coverage, reasons), observer alerts, dashboard read integration (pull) | Exhaustive "never VERIFIED without E3 + coverage" tests |
| C5 | Egress chokepoint (forward proxy) + coverage prober + compose overlay | Bypass-route probe test; T1/T4 adversarial tests |
| C6 | Shadow policy check (advisory) | T3 adversarial test; documented as advisory, never authorizing |
| C7 | Hardening, benchmark extension, docs, feature matrix | Full validation; status labels only after tests |

**Risks:**
- **Scope:** this is the largest phase so far; C1–C4 deliver independent canary verification; C5–C6 add mediation
  and divergence.
- **TLS visibility:** the chokepoint sees host:port and bytes, not paths. ALLOW verification of real HTTPS traffic is
  host-level unless TLS is terminated (not proposed).
- **File watching reliability:** inotify on shared volumes needs validation in C3.
- **Operational complexity:** a second DB, more keys and more failure modes.
- **False sense of independence on one host:** stated in the threat model (boundary D).
- **Key management:** lost keys mean INCONCLUSIVE everywhere, which is safe but noisy.
- **Shadow policy drift:** it must use the same policy bundle and version; divergence alerts may be noisy at first.

## 14. Decisions requested before implementation
1. Approve the separate `observer-db` container (recommended), versus a separate database in the existing cluster
   (weaker: shared superuser).
2. Approve backend migration 008 (outbox + `grants.execution_id`, additive).
3. Approve moving the backend off the `egress` network behind the observer proxy when the overlay is enabled (C5).
4. Strict mode R21 (`QYRIX_REQUIRE_OBSERVER`): leave out, or implement default-off (needs separate approval).
5. Start with phases C1–C4 only.
