# Phase C: Independent Observer Service (architecture design, revision 2, for review; NOT implemented)

Status: **design only.** Nothing in this document is implemented. It changes no code, schema, migration or runtime
behaviour. Every "will" below is a proposal for review.

**Revision 2** answers the five review questions:
- event suppression and liveness (§5);
- canary independence (§6);
- egress coverage and HTTPS limits (§7);
- the trusted policy source (§8);
- observer compromise (§9);
- plus the delivery guarantees of migration 008 (§10).

R21 (strict "require observer" mode) is **out of scope**.

## 0. Summary
Today's Continuous Enforcement Verification (CEV) catches an adapter that ignores a BLOCK. It cannot catch a
compromised backend, because the observer, the canary tokens, the decision it reconciles against and the evidence
store all live in the backend. Phase C moves observation into a separate **Observer Service**. The service has:
- its own process, container and lifecycle;
- its own PostgreSQL container, its own keys and its own evidence chain.

Gate decisions reach it as **signed claims to be checked, never as evidence of enforcement**. A result can be
`ENFORCEMENT_VERIFIED` only with **observer-originated evidence** for the channel, under three conditions:
- the observer can show that **the channel is mediated by it**;
- its sensors passed a **positive control** in the same window;
- the window closed under the watermark rules in §5.

Anything less is `INCONCLUSIVE`.

**Honest bound.** Against an *adaptive* compromised backend, the independent guarantee comes from **mediation**: every
outbound path passes an observer sensor. It does not come from canaries or heartbeats. Canaries and heartbeats detect
faults, non-enforcing adapters, crashes and silence, but a backend that lies consistently can make its own statements
look healthy. Where a channel is not mediated, results stay INCONCLUSIVE by design.

## 1. Existing architecture audit (as implemented at `b7b6064`; unchanged)
| Component | Where | What it does today | Independence finding |
|---|---|---|---|
| Execution Observer | `app/cev.py` (`CanaryHttpObserver`, `CanaryFileObserver`, `observers()`) | Loopback HTTP listener on `127.0.0.1:<ephemeral>` in a backend thread; canary files in a temp dir; hits kept **in memory** | Same process, memory, kernel namespace and credentials as the Gate. Hits are lost on restart. Backend code can read and clear them (`forget()`) |
| Canary runs | `cev.run_canary` | The **backend** generates the correlation id and canary token, calls the adapter in-process, waits for the window | A compromised backend chooses the tokens and can avoid or fake them |
| Reconciler | `cev.reconcile` (pure) | Truth table; missing or unproven telemetry gives INCONCLUSIVE; a seen side effect wins | Sound logic, **but the decision it uses is the Gate's in-process return value**. That is a self-report |
| CEV evidence | `g._record(ctx, entry)`, kind `cev_reconciliation` | Written to the **backend's own** proof chain and DB mirror | The party being verified stores the verdict about itself |
| Adapter contract / registry | `app/integrations.py` | Capability declarations; fixtures; `RestApiAdapter` | Adapter self-reports are already never trusted |
| MCP proxy | `app/mcp_proxy.py` | stdio proxy in the user's environment: `tools/call` → evaluate → `/tools/redeem` → forward | No telemetry leaves the proxy except through the backend; MCP-server egress is not observed |
| Gate + grants | `gateway.evaluate`, `execute_grant`, `redeem_grant` | Rules R0–R20; single-use grants bound to agent, task, policy version and params digest; atomic SQL consume | Authorization is sound. There is **no execution id** and no outbound marker an observer could correlate |
| Proof chain | `app/proof.py`, chain file + `proof_records` mirror | SHA-256 hash-linked records | Integrity, not authenticity. The backend can append anything |
| State witness | `app/integrity.py` | HMAC high-water mark on a separate volume; checked at persistence attach (durable mode only) | Its key and volume are mounted **into the backend container** |
| RFC 3161 anchoring | `app/anchor.py`, `proof.evaluate_anchors` | Optional, off by default; local TSA tested only | Independent time only if a TSA is configured; not after the latest anchor |
| Database | PostgreSQL 16; roles `qyrix` (admin/superuser), `qyrix_runtime`, `qyrix_app`, `qyrix_auth`, `qyrix_maint`; RLS | Least privilege for the backend; `qyrix_app` has table-level INSERT on `grants`, UPDATE only on `used_at`/`revoked_at`/`revoked_by` (003) | One cluster, one superuser: an observer table here would share that trust root |
| Network (`docker-compose.yml`) | `internal` (`internal: true`, no egress), `edge` (frontend); `docker-compose.egress.yml` adds `egress` to the backend; every service has `cap_drop: [ALL]`; no network enables IPv6 | Backend has no internet unless the overlay is used | With the overlay the backend egresses **directly**: no chokepoint today |
| Crypto available | `cryptography 50.0.2` (pinned) | AES-GCM today | Ed25519 available **without new dependencies** |

## 2. Proposed architecture
```
                          trust boundary A: Sentinel backend (may be compromised)
  ┌───────────────────────────────────────────────────────────────────────────────────────┐
  │  frontend ──► backend (Gate, grants, adapters, MCP redeem API)                          │
  │                 │ OUTBOX (backend DB, same transaction as the decision) ──► publisher   │
  │                 │ signs events + HEARTBEATS with GATE key (publish-only scope)           │
  │                 │ Gate uses a SIGNED POLICY BUNDLE (verified, not authored, by backend)  │
  │           backend PostgreSQL (existing) · backend state witness (existing)               │
  │  networks: internal (no route out) · observer_ingest · egress_in (to proxy only)         │
  └─────────────────┼───────────────────────────────┬──────────────────────────────────────┘
                    │ signed events/heartbeats        │ ALL outbound traffic (only route)
  ┌─────────────────▼───────────────────────────────▼──────────────────────────────────────┐
  │  trust boundary B: Observer Service (own container, keys, DB, volumes)                  │
  │   ingest (sig, scope, replay, skew, watermarks) ──► observer ledger (hash chain, signed) │
  │   sensors: egress forward proxy (CONNECT + plain HTTP) · DNS resolver · canary HTTP ·    │
  │            canary file watcher                                                           │
  │   canary scheduler (tokens minted here) · coverage prober (controls a probe sidecar)     │
  │   reconciler v2 · decision check against the SIGNED POLICY BUNDLE (§8)                   │
  │   observer-db (separate container) · observer witness · RFC 3161 anchors · key manifest  │
  │   read API (tenant-scoped keys) · alert webhook (direct to operators)                    │
  └─────────────────┬──────────────────────────────────────────────────────────────────────┘
                    │ only the proxy/resolver reach `egress`
                 internet
  boundary C: integrations (REST adapters, MCP proxy + servers): may ignore decisions or lie
  boundary D: host / Docker daemon / kernel: shared by A and B on one host (out of scope; separate host recommended)
  OFFLINE (outside A and B): operator root key, policy-signing key; they sign the key manifests and policy bundles
```

**Code layout.**
- New package `backend/observer/`, with **no import** of the backend's gateway, DB or identity code.
- Pure helpers (canonical JSON, hash chain, Ed25519 verify) are vendored into it.
- The decision check (§8) uses a copy of the deterministic rule functions, pinned by engine version.
- Entrypoint: `python -m observer.main`.

## 3. Trust boundaries
| Boundary | Contains | Assumed compromised? | Holds | Must not hold |
|---|---|---|---|---|
| A backend | backend, frontend, backend DB/witness | **Yes** (central scenario) | GATE signing key (scope: decision, grant, heartbeat) | observer keys, observer DB access, policy-signing key, canary credentials |
| B observer | observer, observer-db, observer witness | Trusted base; compromise handled in §9 | OBSERVER signing key, observer DB, canary agent key(s) | backend DB access, policy-signing key, root key |
| C integrations | adapters, MCP proxy and servers | Yes | ADAPTER keys (scope: adapter_report) | anything else |
| D host | kernel, Docker daemon, compose config | Out of scope on one host | network attachments, capabilities | — |
| Offline | operator root key, policy-signing key | Trusted, kept off-line | signs key manifests and policy bundles | never mounted into A or B |

## 4. Data flow
1. **Decision.** The Gate evaluates (unchanged). In the **same database transaction** that stores the evaluation, it
   inserts a decision event into the outbox (§10). The publisher signs and delivers it.
2. **Grant.** When a grant is created, the Gate assigns an **`execution_id`**, stored on the grant row at INSERT time.
   On execute or redeem, a grant event is published. Outbound requests from Sentinel's own adapter carry the
   `execution_id` in the proxy **CONNECT request** header `X-Qyrix-Execution`. That header is visible to the proxy
   without TLS termination (§7).
3. **Heartbeats** (§5) are published every `H` seconds, with watermarks.
4. **Observation.** The proxy, resolver and canary sensors record effects with observer timestamps.
5. **Reconciliation** (§11) in the observer. Results are appended to the observer ledger, signed, and anchored (§9).
6. **Consumption.** The dashboard pulls from the observer read API. The observer never writes into the backend DB.

## 5. Event suppression, heartbeats, watermarks and window closure (review Q1)
**Signed heartbeat** (type `heartbeat`, same sequence space as the producer's events):
```json
{"type": "heartbeat", "body": {"published_through_seq": 1041, "outbox_depth": 0, "gate_clock": "…",
 "tenants": {"default": {"proof_n": 8812, "proof_head": "<sha256>", "last_decision_seq": 1040}}}}
```

**Watermarks kept by the observer per (producer, tenant):**
- `contiguous_seq`: the highest *n* such that all of 1…*n* have been received;
- `attested_seq`: `published_through_seq` from the newest valid heartbeat;
- `last_heartbeat_at`: observer clock time.

**Rules:**
| Situation | Detection | Outcome |
|---|---|---|
| Gap inside the stream | `contiguous_seq` < a received seq | `DECISION_FEED_GAP`; affected windows INCONCLUSIVE; alert |
| **Tail suppression** (events withheld but heartbeats continue) | `attested_seq` > `contiguous_seq` for longer than grace `G` | `DECISION_FEED_GAP` (tail); windows INCONCLUSIVE; alert |
| **Publisher stopped or partitioned** | no valid heartbeat for 3×`H` | `PRODUCER_SILENT`; every open window INCONCLUSIVE; alert. Any effect seen meanwhile → UNAUTHORIZED_EXECUTION |
| Heartbeat says the proof chain moved backwards (`proof_n` lower or `proof_head` diverged at the same `n`) | comparison with the previous heartbeat | `PRODUCER_REGRESSION` (security alert) |
| Heartbeat clock skew > `S` | `gate_clock` vs observer clock | heartbeat refused; counts as missing |
| **Consistent liar** (omits events *and* their sequence numbers, heartbeats agree) | **Not detectable from the feed alone** | Detected only through observer-originated stimuli: a canary with no decision within `T_decision` gives `DECISION_MISSING` (§6), and a mediated effect with no claim gives UNAUTHORIZED (§7) |

**Window closure** (for a correlation or canary run). A window opens at observer time `t0`, when the observer submits
a canary or receives the first claim or observation. It is **closed** only when all of these hold:
1. observer time > `t0 + W` (W = observation window);
2. a valid heartbeat issued after `t0 + W` has been received, with `contiguous_seq ≥ published_through_seq` at that
   heartbeat (the producer has reported everything up to after the window);
3. every sensor relevant to the channel reported healthy and the positive control passed inside `[t0, t0 + W]`.

If conditions 2–3 do not hold by `t0 + W + G`, the result is **INCONCLUSIVE** (`WINDOW_NOT_CLOSABLE`), never VERIFIED.

**Late data.** Results are **append-only and versioned.** An event or observation that arrives after closure triggers
re-reconciliation. A *new* ledger record supersedes the old one, which is never edited. VERIFIED → BYPASS raises a
critical alert.

**Defaults** (configurable): `H` = 10 s, `G` = 30 s, `W` = 2 s (canaries), `T_decision` = 10 s, `S` = 120 s.

## 6. Canary creation and injection (review Q2)
**What the observer controls alone:**
- **Token:** 128-bit CSPRNG, generated in the observer. The backend never sees it before submission.
- **Resource:** observer-owned and meaningless outside the run:
  - `https://<token>.c.<canary-domain>/<token2>` served by the observer's canary listener, where the observer's own
    resolver is authoritative for `c.<canary-domain>`; or
  - an IP literal from an observer-held pool;
  - or a file under the observer-owned `observer_canary` volume.
- **Expected decision:** BLOCK by the signed policy bundle (§8), checked by the observer before sending. A canary the
  bundle would allow is never sent.
- **Run record:** `{run_id, token, adapter, credential key_id, submitted_at, expected_rules}`, written to the observer
  ledger **before** submission.

**Injection paths, from strongest to weakest:**
| Path | How | Independence |
|---|---|---|
| **P1 agent-path injection** | The observer places the canary *task* where the agent takes work: an observer-operated MCP client or harness talks to the integration (MCP proxy → server), or a test item in the agent's own task queue where the deployment allows it | The integration and the backend see ordinary agent traffic from the agent's credential. Strongest, but needs deployment cooperation |
| **P2 integration API** | The observer acts as a client of the integration with a **canary agent API key**. The key is created by a human operator via the existing key API, stored only in the observer's secrets; the backend keeps only its hash, as for any key | The backend can recognise the key id. Several keys, rotated, named like ordinary agents, reduce this but **do not remove it** |
| **P3 colocated (today)** | `app/cev.py` | Not independent; kept only for compatibility |

**Honest limits:**
- **An adaptive compromised backend can discriminate on credentials or destinations**, behaving honestly for canaries
  and cheating otherwise.
- Canaries therefore establish:
  - enforcement by the **integration**;
  - absence of **non-adversarial** backend faults;
  - liveness of the decision feed (`DECISION_MISSING`).
- They do **not** establish that an adaptive backend never cheats. That guarantee comes only from mediation (§7):
  *every* real outbound request is observed, not only canary traffic.
- **An untrusted adapter** can special-case canary hosts. The pool of canary hostnames and paths is large, rotating
  and plain, but this is best effort: a non-enforcing adapter is still caught when it hits *any* canary, and real
  traffic is still mediated.

**Correlation and timeouts after submission:**
- the observer expects a signed decision event carrying its run's `correlation_id` within `T_decision`; if none
  arrives, `DECISION_MISSING` (suppression signal, alert);
- any observation of `token` at the listener, resolver or proxy means `BYPASS_DETECTED`.

## 7. Egress coverage and what HTTPS metadata proves (review Q3)
**Enforcement by network topology (Docker daemon, boundary D), not by backend code.** A compromised application cannot
change its own network attachments or capabilities:

| Bypass attempt | Control | Verified by the coverage prober (probe sidecar) |
|---|---|---|
| Direct TCP/UDP to an internet IP | Backend and integrations attach **only** to `internal: true` networks (no default route); only the observer proxy/resolver attach to `egress` | Connect to an observer-controlled external sink IP **must fail** |
| IPv6 | No `enable_ipv6` on any backend-side network; `sysctls: net.ipv6.conf.all.disable_ipv6=1` in backend containers | IPv6 literal connect to the sink **must fail** |
| DNS tunnelling or exfiltration | Backend containers use `dns: [<observer resolver>]`. The resolver answers only canary and allowlisted names and logs every query (a sensor). Recursion to the internet happens only in the observer | Query to a public resolver (UDP/TCP 53, DoT 853, DoH to an IP) **must fail**; query for a random external name must be **logged and refused** |
| Docker embedded DNS forwarding | The embedded resolver (127.0.0.11) forwards external names to the configured `dns:`, which is the observer | Validated in C5: a random-name query must appear at the observer resolver and nowhere else. **If validation fails, DNS coverage is `unmediated` and DNS-channel BLOCKs stay INCONCLUSIVE** |
| Alternate interfaces, host networking | `network_mode: host` forbidden (compose lint in CI); no other networks attached; `cap_drop: [ALL]` already removes NET_RAW/NET_ADMIN (no raw sockets, no route changes) | Raw socket and ICMP to the sink **must fail** |
| HTTP proxy env bypass | Irrelevant: without a route, a non-proxied connection fails | covered by the direct-connect probe |
| Domain fronting / SNI mismatch | The proxy peeks the TLS ClientHello: SNI must equal the CONNECT authority; ECH is refused | Mismatched-SNI CONNECT **must be refused and logged** |
| Side channels without network (shared volumes, timing) | **Not mediated** | Out of scope; stated |

**Probe sidecar.**
- A minimal container with the **same network attachments and restrictions** as the backend. It runs only the probe
  commands the observer sends it, on its own `observer_probe` network.
- It tests the network policy, **not** the backend container's own namespace. That is sound only under boundary D
  (the attacker cannot change Docker config).
- A probe success means `COVERAGE_GAP`: every BLOCK on that channel is INCONCLUSIVE, plus a **critical alert**.
- A coverage attestation is valid for 1 h and is re-run after every observer or backend restart.

**What HTTPS metadata can and cannot prove (no TLS termination):**
| Proxy sees (provable) | Proxy does not see (not provable) |
|---|---|
| destination host (CONNECT authority = SNI), port, time, connection count | URL path, query, method, request headers inside TLS, body |
| bytes in/out, handshake success | which **request** within a connection did what |
| `X-Qyrix-Execution` on the CONNECT request (plaintext to the proxy) | that a compromised sender did not attach a *legitimate* execution id to an illegitimate connection to the same host |
| DNS queries through the resolver | data hidden *inside* an allowed connection to an approved host (covert channel) |

**Resulting verification scope** (`verification_scope` field):
- **BLOCK of an unapproved host:** no connection to that host from the mediated networks in the window gives
  VERIFIED (`scope: host`); any connection gives BYPASS.
- **BLOCK of an approved host** (for example R19 on a POST to an allowlisted API): legitimate connections to the same
  host can exist, so the proxy cannot tell them apart. The result is INCONCLUSIVE (`HOST_SHARED_WITH_ALLOWED_TRAFFIC`),
  unless the traffic is plain HTTP (request-level) or no allowed execution to that host exists in the window.
- **ALLOW over HTTPS:** a matching execution id and host gives VERIFIED with `scope: host`. The path, method and body
  are never claimed.
- **Plain HTTP and canaries:** request-level (`scope: request`).

## 8. Independent policy verification: trusted source (review Q4)
**The source of truth is a signed policy bundle, never the backend's word.**
- **Authorship:** policies are written and approved by humans. A bundle is signed **offline** with the
  **policy-signing key** (Ed25519), held by the operator and never mounted into the backend or the observer.
- **Bundle contents:**
  `{bundle_version, not_before, not_after?, engine_version, tenants: {id: {approved_domains, workspace, tools,
  require_task_id, …}}, policy_inputs_digest, signature, key_id}`.
  It holds exactly the inputs of `gateway.policy_inputs`, so `policy_version` = SHA-256 of the canonical inputs.
- **Distribution:** the bundle is delivered **separately** to both sides, as an operator-provided file or a read-only
  mount from the operator's policy repository:
  - the backend verifies the signature before using it (future: the Gate refuses unsigned policy);
  - the observer verifies the signature against the **pinned policy public key** in its own configuration.
  - The observer never fetches policy from the backend.
- **Decision check in the observer (advisory, never authorizing):** for every claim, the observer computes:
  - `policy_version_match`: whether the claim's `policy_version` equals the hash of a currently valid signed bundle.
    A mismatch gives `POLICY_DIVERGENCE` (security alert).
  - **Stateless re-evaluation**, with the bundle and the pinned rule functions, of the rules that depend only on the
    request: R1, R2/R12 (secret patterns), R5, R8, R9, R10, R13 (presence), R20.
  - `decision_check` ∈ {`AGREES`, `DIVERGES`, `PARTIAL`}:
    - `PARTIAL`: state-dependent rules (R3, R4, R6, R7, R14, R19 provenance and approvals) cannot be re-derived from the
      bundle;
    - `DIVERGES`: the observer's stateless evaluation would BLOCK an ALLOW claim.
  - An **engine-version mismatch** gives `SHADOW_ENGINE_MISMATCH`, and `decision_check` is `PARTIAL` at best.
- **Effect on results:**
  - `decision_check` is about *whether the decision was right*; the CEV result is about *whether it was enforced*.
    They are reported separately.
  - An ALLOW whose check `DIVERGES` is never VERIFIED: it gets INCONCLUSIVE plus a `POLICY_DIVERGENCE` alert.
    `PARTIAL` is allowed, but shown.
  - **Future, not in scope:** signed provenance and approval events (for example approver WebAuthn signatures) would
    let the observer re-derive R19/R4/R6 too.

## 9. Observer compromise: keys, export, anchoring, recovery, independent verification (review Q5)
**Key hierarchy:**
- **Root key** (offline, operator): signs the *observer key manifest*.
- The manifest lists the observer signing keys (`key_id`, public key, `valid_from`, `valid_to`, `revoked_at`), the
  producer keys (gate and adapters, with scopes) and the policy public key.
- **Observer signing key:** online, in the observer only. It signs ledger records and exports.

**Rotation:** a new key is generated, a new manifest is signed offline and installed, and there is an overlap window
in which both keys are valid. After that the old key gets `valid_to`. Old records stay verifiable with the old public
key.

**Compromise handling:**
1. The manifest marks the key `revoked_at = T`.
2. Records signed by that key **after T** are invalid.
3. Records **before T** are trusted only if an RFC 3161 anchor dated before T covers them.

**External anchoring:**
- **What is anchored:** the ledger head, every `N` records or `M` minutes (defaults 100 / 10 min), at an
  operator-configured RFC 3161 TSA. A free public TSA, or a local TSA for testing; no paid service.
- **Cross-witnessing:** the observer's anchored head is also written into the backend proof chain, and the backend's
  head into the observer ledger. Each side then holds the other's history, so a rollback by either side contradicts
  the other.
- **Observer state witness:** same design as `app/integrity.py`, with its own key and volume.

**Evidence export** (`GET /v1/evidence/export`): ledger records, signatures, key manifest (with its root signature),
anchors with TSA tokens, producer public keys, and the policy bundle digests in effect.

**Independent verification:** a verifier needs only the bundle, the root public key and the TSA certificate. With them
it can check, offline (CLI now, browser verifier in Phase D):
- hash-chain integrity;
- signatures under keys valid at the signing time;
- anchor coverage and times;
- completeness up to the latest anchor.

It **cannot** check that the sensors saw everything. Coverage attestations are observer claims, and the export says so.

**Recovery after a suspected observer compromise:**
1. stop the observer and revoke its key in a new manifest;
2. rebuild from a clean image;
3. restore observer-db from backup;
4. verify the ledger against the last trusted anchor;
5. append a **recovery record** marking every result after the last anchor before T as `UNTRUSTED`, presented as
   INCONCLUSIVE and never deleted;
6. re-attest coverage and re-run canaries.

**Residual risk:** a compromised observer can hide bypasses *after* its last anchor and before detection. An optional
second, independently operated observer, whose results must agree, is future work.

## 10. Migration 008: delivery guarantees, idempotency, recovery, compatibility
**Schema (additive, backend DB):**
- `observer_outbox(tenant_id, seq bigint, event_id uuid unique, type, body jsonb, created_at, sent_at null, attempts int)`,
  primary key `(tenant_id, seq)`, RLS by tenant;
- `observer_seq(tenant_id primary key, n bigint)`: gap-free counter;
- `grants.execution_id uuid NULL`: set at INSERT, so no new UPDATE privilege is needed.

**Privileges:**
- `qyrix_app` gets INSERT and SELECT on `observer_outbox`, UPDATE (`sent_at`, `attempts`) only, and no DELETE;
- UPDATE (`n`) on `observer_seq`;
- pruning of sent rows is a `qyrix_maint` SECURITY DEFINER function, like the existing evidence reset.

**Delivery guarantees:**
| Property | Mechanism |
|---|---|
| **No lost decision once it is recorded** | The outbox row is inserted in the **same transaction** as `save_evaluation` (ALLOW and BLOCK). If the transaction fails, there is no decision and no event, and the Gate already fails closed (R17) |
| **Gap-free per-tenant sequence** | `UPDATE observer_seq SET n = n + 1 … RETURNING n` inside that transaction (DB sequences can leave gaps on rollback, which would raise false alarms). Writers are already serialized by the context lock |
| **At-least-once delivery** | The publisher sends unsent rows in `seq` order and sets `sent_at` on 2xx. It retries with exponential backoff (cap 60 s) and alerts when `outbox_depth` or age passes thresholds |
| **Idempotency** | The observer keys on `event_id`. A byte-identical duplicate is acknowledged (`200 duplicate`). Same `event_id` with different content gives `EVENT_CONFLICT` (security alert, refused) |
| **Ordering** | The observer accepts out-of-order arrival but reconciles only up to `contiguous_seq` (§5) |
| **Crash recovery** | On restart the publisher resumes from the lowest unsent `seq`. Rows sent but not marked are re-sent and deduplicated |
| **Outbox loss** (DB restored from backup) | The sequence regresses, so the observer sees a seq ≤ watermark with different content: `PRODUCER_REGRESSION`. The backend state witness also flags the DB regression. Operator recovery follows; results are never silently re-based |
| **Memory mode** (no PostgreSQL) | The observer feature is **unsupported**: the publisher is disabled and colocated CEV remains as today |

**Backward compatibility:**
- **Inactive until enabled:** nothing is written to the outbox unless `QYRIX_OBSERVER_URL` is set. The new columns are
  nullable, and old code ignores them.
- **Rollback:** disable the setting. The tables remain, with no destructive down-migration.
- **Mixed versions:** the existing rule of one backend process per database still applies.
- **No change to the Gate:** no change to Gate authorization, R0–R20, R19/R20, grant binding or policy version.
- **Existing CEV:** `/api/v1/sentinel/cev/*` is unchanged; results are labelled `evidence_level: colocated` in API
  output only.

## 11. Evidence levels and reconciler v2
| Level | Source | Can support VERIFIED? |
|---|---|---|
| **E3 observer-direct** | Observer sensor (proxy, resolver, canary listener, canary file) | Yes, with coverage + positive control + closed window |
| E2 resource-attested | Receipt signed by the target resource (future) | Yes (future) |
| E1 adapter-reported | Signed integration self-report | **No** |
| E0 Gate-reported | Decision, grant and heartbeat events (the *claims*) | **No** |
| colocated | Today's `app/cev.py` | Kept, labelled; **does not count** |

**VERIFIED requirements (all must hold; otherwise INCONCLUSIVE with reasons):**
- the window is closed per §5;
- the claim's signature is valid under a key in the current manifest;
- the channel is mediated, with a current coverage attestation (§7);
- the positive control passed in the window.

**Then, by claim type:**
- **BLOCK:** no matching E3 observation for the token or host, within the stated `verification_scope`.
- **ALLOW:** a matching grant event; an E3 observation with the same `execution_id`; method, host and path matching
  where visible; the decision before the effect; and `decision_check` ≠ `DIVERGES`.
- **E3 effect with no claim:** UNAUTHORIZED_EXECUTION.
- **E3 effect contradicting a BLOCK:** BYPASS_DETECTED.

## 12. API and event schemas
**Envelope** (canonical JSON with sorted keys, UTF-8, ≤ 64 KiB):
```json
{"schema": "qyrix.event/v1", "event_id": "<uuid4>", "producer_id": "gate:<install_id>|adapter:<integration_id>",
 "key_id": "<ed25519 key id>", "seq": 1042, "issued_at": "…", "tenant": "default",
 "type": "decision|grant|heartbeat|adapter_report", "body": {…}, "sig": "<base64 Ed25519 over canonical(envelope without sig)>"}
```

**Event bodies:**
- `decision`: `gate_evaluation_id, correlation_id, agent_id, task_id, policy_version, verdict, rule_ids, tool, method,
  dest_host (A-label), params_digest, proof {n, hash}`.
- `grant`: `gate_evaluation_id, grant_id, execution_id, kind (issued|redeemed|executed|refused), integration,
  refusal_code?, params_digest, proof {n, hash}`.
- `heartbeat`: see §5.
- `adapter_report`: `execution_id?, correlation_id, integration, claims {forwarded}`. E1 only.

**Observation (internal only):**
`observation_id, sensor (egress_proxy|dns|canary_http|canary_file), observed_at, channel, tenant?, canary_token?,
execution_id?, host, sni?, port, method?, path_sha256?, body_sha256?, bytes_in/out, connection_id`.

**Reconciliation record:**
`recon_id, version, supersedes?, tenant, correlation_id, execution_id?, claim_refs, claim_sig_valid, observation_refs,
coverage {channel, mediated, attestation_at, positive_control_at}, window {opened, closed, closure_heartbeat},
verification_scope, decision_check, evidence_level, result, reasons, n, prev, hash, observer_key_id, observer_sig`.

**Observer HTTP API** (port 9000, `observer_ingest` network only):

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/events` | Ed25519 envelope; producer key in manifest with matching scope | Ingest decision / grant / heartbeat / adapter_report |
| POST | `/v1/canaries/run` | operator key | Run a canary now |
| GET | `/v1/reconciliations?tenant=&since=` | tenant-scoped read key | Results (latest version per recon) |
| GET | `/v1/evidence/export?tenant=` | tenant-scoped read key | Verifiable bundle (§9) |
| GET | `/v1/health` | none | Liveness only (no data) |
| GET | `/v1/status` | operator key | Sensors, coverage, watermarks, feed state, queue depth |

**Key manifests** are installed from a file signed by the root key, never by an API call from the backend.

**Error codes:** `SIGNATURE_INVALID`, `UNKNOWN_PRODUCER`, `SCOPE_DENIED`, `REPLAY`, `OUT_OF_ORDER`, `CLOCK_SKEW`,
`TENANT_MISMATCH`, `OVERSIZE`, `RATE_LIMITED`, `EVENT_CONFLICT`.

## 13. Observer database (new, separate `observer-db` container; none applied in this phase)
- **Tables:** `producers`, `key_manifests`, `policy_bundles`, `events` (unique `event_id`, unique
  `(producer_id, tenant, seq)`), `watermarks`, `observations`, `canary_runs`, `coverage_attestations`,
  `reconciliations` (hash-chained, versioned), `anchors`, `alerts_sent`.
- **Roles:** `observer_admin` (migrations), `observer_runtime` (INSERT/SELECT; no UPDATE/DELETE on evidence tables;
  RLS by tenant), `observer_reader` (SELECT on reconciliations and exports).
- **Integrity:** append-only triggers on evidence tables.
- **Separation:** no network route and no credentials between the backend and observer-db, in either direction.
  No shared superuser.

## 14. Failure-mode matrix
| Failure | Detection | Result | Gate impact |
|---|---|---|---|
| Observer down | publisher retries; outbox grows | windows without the observer: INCONCLUSIVE (`OBSERVER_UNAVAILABLE`); backlog replays later | **None** (not in the authorization path; R21 out of scope) |
| Observer slow / queue full | queue depth | 429; affected windows INCONCLUSIVE | None |
| Observer DB down | write failure | ingest 503; INCONCLUSIVE; alert | None |
| Internal feed gap | `contiguous_seq` | `DECISION_FEED_GAP`; INCONCLUSIVE; alert | None |
| Tail suppression | `attested_seq` > `contiguous_seq` beyond `G` | `DECISION_FEED_GAP`; INCONCLUSIVE; alert | None |
| Publisher silent / partition | no heartbeat for 3×`H` | `PRODUCER_SILENT`; INCONCLUSIVE; effects meanwhile are UNAUTHORIZED | None |
| Producer regression | heartbeat or seq content regresses | `PRODUCER_REGRESSION`; security alert | None |
| Canary with no decision | `T_decision` timeout | `DECISION_MISSING`; INCONCLUSIVE; alert | None |
| Invalid signature / unknown producer / scope / replay / skew / conflict | ingest | refused, recorded, alert | None |
| Positive control fails | canary listener / resolver / file watcher | INCONCLUSIVE (`POSITIVE_CONTROL_FAILED`) | None |
| Bypass route open | probe succeeds | `COVERAGE_GAP`; BLOCKs on that channel INCONCLUSIVE; critical alert | None |
| DNS forwarding not via observer | C5 validation fails | DNS channel `unmediated`; DNS BLOCKs INCONCLUSIVE | None |
| Shared host with allowed traffic | proxy evidence | `HOST_SHARED_WITH_ALLOWED_TRAFFIC`; INCONCLUSIVE | None |
| Policy bundle invalid / expired / missing | signature or time check | decision check unavailable; ALLOW results INCONCLUSIVE; alert | None |
| Observer key revoked / manifest invalid | manifest check | observer refuses to sign; results INCONCLUSIVE; alert | None |
| Observer ledger tampered | chain verify + witness + anchors at start | observer degraded; recovery procedure (§9) | None |
| TSA unreachable | anchoring attempt | `ANCHOR_PENDING` (shown); results unchanged but marked unanchored | None |

## 15. Deployment (Docker Compose, opt-in, no paid infrastructure)
**`docker-compose.observer.yml` overlay.** The default stack is unchanged:
- `observer-db`: pinned `postgres:16-alpine` digest; own volume and secrets; `observer_db` network only.
- `observer-migrate`: one-shot.
- `observer`:
  - networks `observer_ingest`, `observer_db`, `egress_in` (backend side), `egress` (internet), `observer_probe`;
  - read-only root, `cap_drop: [ALL]` plus only what the proxy needs (no `NET_ADMIN`);
  - volumes `observer_witness`, `observer_canary`.
- `observer-probe`: probe sidecar on the backend's networks with the same restrictions.
- **Backend under this overlay:** leaves `egress` and reaches the internet only through `egress_in` → observer proxy;
  `dns: [observer]`; IPv6 disabled by sysctl.

**Secrets (all new, generated locally):** `observer_signing_key`, `observer_witness_key`, `observer_db_*`,
`canary_agent_key`, `gate_signing_key` (backend only).

The offline root and policy-signing keys are **never** placed in the compose secrets.

**Single-host caveat:** boundary D is shared. For guarantees beyond container isolation, run the observer stack on a
separate host, using mTLS with pinned certificates (stdlib `ssl`).

## 16. Test and security validation plan
**Unit:**
- envelope, signatures, scopes, replay, skew, conflict;
- watermark and window-closure state machine (gap, tail, silence, late data, supersession);
- reconciler v2 truth table, with an **exhaustive check that E0/E1-only, unclosed, unmediated, uncontrolled or
  diverging inputs never produce VERIFIED**;
- policy bundle verification (bad signature, expired, wrong key, digest mismatch);
- key-manifest rotation and revocation;
- ledger chain, witness and anchor coverage.

**Integration (real processes and compose):**
- outbox → publisher → observer, including crash/restart replay and duplicate idempotency;
- heartbeats;
- observer canaries via P2 (REST) and P1 (MCP harness);
- positive controls;
- **the full bypass-probe matrix in §7**: direct IPv4, IPv6, public DNS, DoH, raw socket, SNI mismatch;
- DNS-forwarding validation.

**Adversarial (simulated compromised backend holding the GATE key):**
- forged BLOCK plus direct exfiltration attempt → no route, plus BYPASS on canaries;
- tail suppression, with silent and with lying heartbeats;
- `DECISION_MISSING` on canaries;
- GATE key used to post an observation → `SCOPE_DENIED`;
- backend-to-observer-db connection must fail;
- replay and conflicting duplicates;
- forged ALLOW to a host the policy bundle disallows → `DIVERGES`;
- legitimate execution id reused for another connection to the same host → `HOST_SHARED…` INCONCLUSIVE, documented
  as a limit.

**Observer compromise drills:**
- key rotation, revocation and recovery record;
- an export verified offline with only the root public key and TSA certificate.

**Chaos:** kill the observer mid-window, stop heartbeats, observer-db down, clock jump, TSA down. Each gives
INCONCLUSIVE, **never VERIFIED**.

**Regression:** the full backend suite; Benchmark v2 (existing digest unchanged); frontend build; gitleaks; bandit.

## 17. Implementation phases and risks
| Phase | Scope | Exit criteria |
|---|---|---|
| C1 | Observer package: signed ingest, key manifest, replay/skew, watermarks + window closure, observer-db (O001), signed hash-chained ledger, health/status | Unit + integration; backend unchanged |
| C2 | Backend: migration 008 (outbox, seq counter, `grants.execution_id`), publisher + heartbeats, CONNECT execution header; MCP adapter reports | Backend suite green; delivery-guarantee tests (§10) |
| C3 | Observer canaries (P2, then P1 harness), canary listener + resolver zone + file watcher, positive controls, `DECISION_MISSING` | Canaries reconciled in the observer |
| C4 | Reconciler v2 + evidence levels + versioned results; alerts; dashboard pull | Exhaustive "never VERIFIED without…" tests |
| C5 | Egress proxy + resolver as chokepoint, compose overlay, probe sidecar, full bypass matrix, DNS-forwarding validation | All probes fail as required; T1/T4 tests |
| C6 | Signed policy bundle + decision check (stateless rules) | Divergence tests; documented PARTIAL scope |
| C7 | Observer anchoring, cross-witnessing, export + offline verifier, recovery drill, benchmark group, docs | Compromise drills pass |

**Risks:**
- **Scope:** the largest phase so far.
- **Docker embedded-DNS behaviour:** must be validated (C5); if it fails, the DNS channel stays unmediated.
- **HTTPS host-level limits:** documented in §7.
- **inotify on shared volumes:** must be validated (C3).
- **Operational load:** keys, an offline signing ceremony, a second DB.
- **Canary discrimination by an adaptive backend:** documented in §6.
- **Single-host boundary D.**

## 18. Decisions requested before implementation
1. Confirm the offline root and policy-signing key model (operator-held, never mounted into containers).
2. Approve migration 008 as specified in §10 (additive; outbox in the same transaction; gap-free counter).
3. Approve the egress topology in §7, under the observer overlay only: the backend leaves `egress`, its DNS goes to
   the observer, IPv6 is disabled.
4. Approve canary paths: P2 first, with the P1 MCP harness as a follow-up.
5. Start with C1–C2 only, then review again.

R21 stays out of scope.
