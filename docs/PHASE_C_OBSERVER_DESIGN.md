# Phase C: Independent Observer Service (architecture design, revision 3, for review; NOT implemented)

Status: **slices C1–C5 implemented** (canary-only reconciliation; ENFORCEMENT_VERIFIED requires a valid C5 coverage attestation; real-host validation in `evidence/c5/validation.json`) (see `docs/OBSERVER.md`, including the resolutions recorded in its §4 and the
owner's amended C3 decisions in its §1.3; C3 records canary observations and lifecycle only, with no reconciliation
and test-only sensor reach); **C6–C7 are not implemented** and remain proposals. Every "will" below that belongs to C3–C7 is a proposal for review.

**Approved amendment (C2, CONNECT header).** The backend keeps its SSRF IP pinning: the proxy is asked to
`CONNECT <pinned-ip>:<port>`, and the hostname travels as `X-Qyrix-Host` next to `X-Qyrix-Execution`. TLS SNI is the
hostname. Wherever §7.4 and §7.6 say "CONNECT authority = SNI", read instead "SNI = `X-Qyrix-Host`, and the CONNECT IP
is in the resolution of `X-Qyrix-Host`" (enforced by the C5 proxy).

**Revision 2** answers the five review questions:
- event suppression and liveness (§5);
- canary independence (§6);
- egress coverage and HTTPS limits (§7);
- the trusted policy source (§8);
- observer compromise (§9);
- plus the delivery guarantees of migration 008 (§10).

**Revision 3** adds four explicit resolutions:
- the host-level egress mechanism, and attestation of the *deployed* backend namespace (§7.1–7.3);
- established CONNECT tunnels and BLOCK windows (§7.5);
- heartbeat and sequence semantics, concurrency and restore (§5.1–5.4);
- the labelling of cross-witnessed heads as claims (§9).

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
**Principle.** Heartbeats and sequence numbers are **signed producer claims (E0)**, not independent evidence. They
control liveness and *when* a window may close. They are a **necessary but never sufficient** condition for VERIFIED:
- a lying heartbeat can make a window close early or late;
- it cannot create the E3 observation, coverage attestation and positive control that VERIFIED also requires (§11);
- it cannot hide a mediated side effect.

### 5.1 Two counters, two purposes
| Counter | Scope | Allocated by | Gap-free? | Used for |
|---|---|---|---|---|
| **Event `seq`** | per `(producer_id, epoch, tenant)` | `UPDATE observer_seq SET n = n + 1 WHERE tenant_id = $t AND epoch = $e RETURNING n`, inside the **same transaction** that writes the decision/grant and its outbox row (§10) | **Yes** (a rolled-back transaction rolls back its increment) | gap and tail detection |
| **Heartbeat `hb_seq`** | per `(producer_id, epoch)`, all tenants | separate monotonic counter `observer_hb_seq`, incremented per heartbeat, **outside** event transactions | No (gaps allowed and expected) | heartbeat ordering and replay protection only |

- **Heartbeats do NOT consume event sequence numbers.** Consuming them would put heartbeat traffic into event
  transactions and turn missed heartbeats into false gap alarms.
- **Producer identity:** `producer_id = gate:<installation.install_id>`, reusing the existing insert-once
  installation identity in `app/integrity.py`, so it is stable across restarts. `key_id` names the signing key.
- **`epoch`:** a small integer, starting at 1. It changes only through the signed recovery procedure in §5.4.

### 5.2 Heartbeat content
Signed with the GATE key; type `heartbeat`. It is a claim, E0:
```json
{"type": "heartbeat", "epoch": 1, "hb_seq": 90311, "body": {"gate_clock": "…", "outbox_depth": 0,
 "tenants": {"default": {"allocated_through_seq": 1041, "proof_n": 8812, "proof_head": "<sha256>"}}}}
```
`allocated_through_seq` is the counter value `n`: the highest event seq **committed**, whether or not it has been
delivered yet.

### 5.3 Concurrency, ordering and arrival
**Concurrent writers.**
- The `observer_seq` row lock serializes allocation per tenant, across threads and processes, so values are unique
  and gap-free.
- The existing rule (one backend process per database) still applies; the row lock is defence in depth, not a reason
  to run several.

**One active publisher per producer.**
- Each publisher must hold `pg_try_advisory_lock(hash(producer_id))` before sending.
- A second instance stays idle and retries the lock every `H`.
- The active publisher sends events in `(tenant, seq)` order and heartbeats on its own timer.

**Out-of-order arrival at the observer.**
- **Storage:** events are stored by `(producer_id, epoch, tenant, seq)`.
- **Watermarks:** `contiguous_seq` advances only when the next number arrives. Events beyond a hole are **held**: they
  are stored, but no window that depends on them can close.
- **Heartbeat before its events:** `attested_seq` (the largest `allocated_through_seq` seen) may run ahead of
  `contiguous_seq`. The observer waits grace `G`; if the hole is still open, the result is `DECISION_FEED_GAP`.
- **Old or out-of-order heartbeats:** a heartbeat whose `hb_seq` ≤ the newest already accepted never lowers a
  watermark. It is stored for audit and counted as `HEARTBEAT_OUT_OF_ORDER`.
- **Replays:** a duplicate `hb_seq` with identical bytes is ignored. A duplicate with different content raises
  `EVENT_CONFLICT`.

### 5.4 Restore from backup and epochs
- **What a restore looks like:** restoring the backend DB to an earlier point moves `observer_seq` back, so new events
  reuse numbers the observer already holds with **different content**. The observer detects
  `(producer, epoch, tenant, seq)` with a different `event_id` or bytes, which gives `PRODUCER_REGRESSION`.
- **Quarantine:** that stream (producer, epoch) is quarantined. Nothing further is reconciled, windows depending on it
  are INCONCLUSIVE, and a security alert is raised.
- **Recovery:**
  1. the operator runs the existing recovery procedure (`python -m app.recovery accept`, extended in C2);
  2. that tool emits an **epoch change record**, signed with the **operator recovery key**: offline or operator-held,
     **not** the GATE key;
  3. the record states the new epoch, the last trusted seq of the old epoch, and the reason;
  4. the observer accepts a new epoch only with this operator signature;
  5. sequence numbers restart at 1 within the new epoch.

  Because the observer requires the operator key, a compromised backend cannot reset its counters to hide a
  suppression.
- **Windows spanning the regression** stay INCONCLUSIVE permanently, recorded through a supersession record.

### 5.5 Suppression rules
| Situation | Detection | Outcome |
|---|---|---|
| Hole inside the stream | `contiguous_seq` < a received seq | `DECISION_FEED_GAP` after `G`; affected windows INCONCLUSIVE; alert |
| **Tail suppression** (heartbeats continue, events withheld) | `attested_seq` > `contiguous_seq` for > `G` | `DECISION_FEED_GAP` (tail); INCONCLUSIVE; alert |
| **Publisher stopped / partitioned** | no accepted heartbeat for 3×`H` | `PRODUCER_SILENT`; every open window INCONCLUSIVE; any mediated effect meanwhile → UNAUTHORIZED_EXECUTION |
| Proof head regresses between heartbeats | `proof_n` lower, or a different `proof_head` at the same `n` | `PRODUCER_REGRESSION` (claim-level alert; not evidence) |
| Heartbeat clock skew > `S` | `gate_clock` vs observer clock | heartbeat refused; counts as missing |
| **Consistent liar** (omits events and their numbers; heartbeats agree) | **Not detectable from the feed** | Only via observer stimuli: canary with no decision in `T_decision` → `DECISION_MISSING` (§6); mediated effect with no claim → UNAUTHORIZED (§7) |

### 5.6 Window closure
A window opens at observer time `t0`, when a canary is submitted or the first claim or observation arrives. It is
**closed** only when all of these hold:
1. observer time > `t0 + W`;
2. an accepted heartbeat with `issued_at > t0 + W` has arrived, and `contiguous_seq ≥ allocated_through_seq` of that
   heartbeat;
3. every sensor for the channel was healthy and the positive control passed inside `[t0, t0 + W]`;
4. no relevant tunnel overlapping the window is still open (§7.5).

If these do not hold by `t0 + W + G`, the result is **INCONCLUSIVE** (`WINDOW_NOT_CLOSABLE`). Closure is still only a
precondition: VERIFIED also needs §11.

**Late data:** results are append-only and versioned. A late event or observation produces a *superseding* record,
never an edit. VERIFIED → BYPASS raises a critical alert.

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

## 7. Egress coverage, enforcement mechanism and HTTPS limits (review Q3)
### 7.1 The enforcement mechanism (kernel and host firewall; not backend code)
Under the observer overlay, the backend container is attached **only** to `internal: true` networks (`internal`,
`observer_ingest`, `egress_in`). Docker implements an internal network as follows, and this is what stops direct
egress:
- **Routing:** the container gets **no default route**. Its routing table holds only the connected subnet routes of
  its attached bridges, so the kernel returns `ENETUNREACH` for any other IPv4 destination. Adding a route needs
  `CAP_NET_ADMIN`, which `cap_drop: [ALL]` already removes; raw sockets need `CAP_NET_RAW`, also removed.
- **Forwarding:** Docker installs `DOCKER-ISOLATION` / `FORWARD` rules that drop traffic from an internal bridge to
  any other interface. Even a packet sent to the bridge gateway address is not forwarded.
- **IPv6:** no backend-side network sets `enable_ipv6`, so the container has no global IPv6 address or route
  (link-local only). The backend also gets `sysctls: net.ipv6.conf.all.disable_ipv6=1`.
- **DNS:** the backend uses `dns: [<observer resolver IP on egress_in>]`. Docker's embedded resolver (127.0.0.11)
  forwards external names to that resolver. Whether the embedded resolver's upstream queries leave from the
  container's namespace (and so hit the observer) or from the daemon's must be **validated in C5**. If it is the
  daemon, the DNS channel is **`unmediated`**, and DNS-channel BLOCKs stay INCONCLUSIVE.
- **Host firewall, belt and braces:** independently of Docker's semantics, the operator installs `DOCKER-USER` rules
  for IPv4 and IPv6 (`iptables` and `ip6tables`). They are evaluated before Docker's own rules:
  - **drop** anything entering from the backend-side bridges whose destination is not the observer's address on that
    bridge;
  - **drop** anything leaving those bridges toward the host's uplink interfaces;
  - bridge names are fixed by `driver_opts: com.docker.network.bridge.name: qyrix-int` (and similar) so rules cannot
    drift.

  Docker's iptables management must stay enabled (`"iptables": true`, the default).
- **Only the observer** is attached to both `egress_in` and `egress`, and only its proxy and resolver forward.

This rests on boundary D: an attacker who controls the application **cannot** change network attachments,
capabilities, sysctls or host firewall rules. One who controls the host or Docker daemon can, and that is out of
scope.

### 7.2 Why a probe container is not proof, and what is
A sidecar with *similar* attachments tests the network, **not** the deployed backend's actual namespace. Neither is a
self-test run by backend code, because a compromised backend can skip the bypass attempts and report clean.
The sidecar is therefore kept only as a **continuous network-policy check**, labelled as such. It never counts as
coverage proof for the backend.

### 7.3 Deployment attestation of the actual backend namespace
A host-side **attestor** runs as root on the Docker host (boundary D), **not inside the backend**. It can be a
systemd timer or a CI job on the host. It signs its report with an **attestor key** registered in the observer key
manifest (§9). It runs:
- at deployment;
- whenever the backend container ID or init PID changes (container events);
- every hour.

**Checks:**
1. **`docker inspect` of the running backend container:**
   - exact set of networks;
   - `NetworkMode` is not `host` and not `container:*`;
   - not privileged;
   - `CapAdd` empty, `CapDrop` = ALL;
   - IPv6 sysctl disabled;
   - `Dns` = the observer resolver;
   - image digest recorded.
2. **Inside the backend's own network namespace**, via `nsenter --net=/proc/<backend-pid>/ns/net` and **host**
   binaries (no backend code involved):
   - `ip -4 route`: no default route;
   - `ip -6 addr` / `ip -6 route`: no global address or route;
   - connection attempts to an **observer-controlled external sink** (reachable only via `egress`), each with a unique
     token: direct IPv4 TCP, IPv6 TCP, UDP/TCP 53 to a public resolver IP, DoH to an IP, ICMP, and a CONNECT with
     mismatched SNI.
3. **Evidence is read from the receiving side.** The **observer's sink and proxy logs** decide, not the attempts' exit
   codes:
   - each direct-path token must be **absent** at the sink;
   - a **positive-control** token sent through the proxy from the same namespace must be **present** and recorded as
     mediated. This proves the attempts really ran in that namespace.
4. **Host firewall:** `iptables -S DOCKER-USER` and `ip6tables -S DOCKER-USER` contain the expected rules for the
   fixed bridge names.

**Result:**
- a coverage attestation bound to `(container_id, image_digest, attested_at)`, valid for 1 h, or until the container
  changes;
- if the container ID reported in the backend's heartbeat (a claim) differs from the attested one, the attestation is
  treated as **stale** and coverage is unmediated until re-attested;
- any failure gives `COVERAGE_GAP` (critical alert), and every BLOCK on that channel is INCONCLUSIVE.

### 7.4 Bypass matrix (every row is checked by 7.3 inside the real namespace)
| Bypass attempt | Control | Pass condition (observer-side) |
|---|---|---|
| Direct IPv4 TCP/UDP to an internet IP | no default route; DOCKER-ISOLATION + DOCKER-USER drop | sink never sees the token |
| IPv6 | no global v6; sysctl disabled; ip6tables DOCKER-USER drop | sink never sees the token |
| Public DNS / DoT / DoH | no route; `dns:` points to the observer | sink and public resolver unreachable; random-name queries appear only at the observer resolver |
| Docker embedded DNS forwarding | validated in C5 | random name logged at the observer resolver; else DNS channel `unmediated` |
| Raw sockets / ICMP | `cap_drop: [ALL]` (no NET_RAW) | socket creation fails; sink sees nothing |
| Route manipulation | no NET_ADMIN | attestor sees an unchanged routing table |
| Host networking / shared namespace | compose lint + `docker inspect` | attestor refuses |
| Domain fronting / SNI ≠ CONNECT host; ECH | proxy peeks the ClientHello | refused and logged |
| Non-network side channels (shared volumes, timing) | **not mediated** | out of scope; stated |

### 7.5 Established CONNECT tunnels, reuse and window boundaries
Without TLS termination the proxy cannot see requests inside a tunnel. These rules make that limit explicit:
- **One tunnel, one execution.**
  - Under the overlay, Sentinel's HTTP adapter opens a **new tunnel per execution**, with no connection pooling, and
    closes it after the single request.
  - The proxy binds a tunnel to the `X-Qyrix-Execution` id on its CONNECT request.
  - An execution id seen on more than one CONNECT gives `EXECUTION_ID_REUSE`, which is UNAUTHORIZED_EXECUTION.
- **Bounded tunnel life:** the proxy closes tunnels after `T_tunnel` (default 30 s) and records open and close times,
  so a tunnel cannot stay open indefinitely across many decisions.
- **Overlap:** a tunnel to host `H` is *relevant* to a BLOCK window on `H` if its lifetime `[opened, closed]` overlaps
  `[t0, t0 + W]`. That includes tunnels opened **before** the BLOCK decision and still open during the window, and
  tunnels still open when the window ends (they delay closure, §5.6 condition 4).
- **BLOCK on host `H`:**

  | Relevant tunnels to `H` in the window | Result |
  |---|---|
  | none (and coverage, positive control, closure all hold) | **ENFORCEMENT_VERIFIED** (`scope: host`) |
  | any tunnel **without** a valid execution id, or with one not matching an accepted, unused ALLOW grant event for `H` | **BYPASS_DETECTED** if `H` has no ALLOW in the window; otherwise **UNAUTHORIZED_EXECUTION** for that tunnel, and **INCONCLUSIVE** for the BLOCK (attribution impossible) |
  | only tunnels carrying valid execution ids of **other** ALLOWed executions to `H` (concurrent or pre-existing) | **INCONCLUSIVE** (`TUNNEL_SHARED_WITH_ALLOWED_EXECUTION`): the blocked request could have travelled inside one of them |
  | a relevant tunnel still open at `t0 + W + G` | **INCONCLUSIVE** (`WINDOW_NOT_CLOSABLE`) |

- **Keep-alive and HTTP/2 multiplexing** inside a tunnel are invisible, so they fall under the same rule: if a relevant
  tunnel exists and attribution is impossible, the result is INCONCLUSIVE.
- **Plain HTTP through the proxy** is request-level: each request is observed individually, including on keep-alive
  connections.

### 7.6 What HTTPS metadata can and cannot prove (no TLS termination)
| Proxy sees (provable) | Proxy does not see (not provable) |
|---|---|
| destination host (CONNECT authority = SNI), port, tunnel open/close time, bytes in/out | URL path, query, method, headers inside TLS, body |
| `X-Qyrix-Execution` on the CONNECT request | which request inside a tunnel did what; HTTP/2 streams; keep-alive reuse |
| DNS queries through the resolver | data hidden inside an allowed tunnel to an approved host (covert channel) |
| — | that a compromised sender did not put a legitimate execution id on an illegitimate tunnel to the same host |

**`verification_scope`:**
- `host` for HTTPS;
- `request` for plain HTTP and canaries.

An ALLOW over HTTPS can at most be VERIFIED at host scope; its path, method and body are never claimed.

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
- **Cross-witnessing (detection aid only):** the observer's anchored head is written into the backend proof chain, and
  the backend's head into the observer ledger.
  - **Backend heads stored in the observer** (from heartbeats or proof exports) are **backend-reported claims (E0)**.
    They live in a separate `producer_claims` table, labelled `backend_reported_head`. They **never** raise any
    result's evidence level, never count as observations, and **never establish the observer's authenticity**. Their
    only use is a later comparison: a backend whose claimed history regresses or diverges raises
    `PRODUCER_REGRESSION`, an alert and not a verification.
  - **Observer heads stored in the backend chain** are, from the backend's side, observer-reported data. They give the
    observer no authenticity either. Observer authenticity comes **only** from observer signatures under a valid
    manifest key, plus RFC 3161 anchors.
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
- `observer_seq(tenant_id, epoch, n bigint, primary key (tenant_id, epoch))`: gap-free event counter;
- `observer_hb_seq(producer_id primary key, epoch, n bigint)`: heartbeat counter (gaps allowed);
- `grants.execution_id uuid NULL`: set at INSERT, so no new UPDATE privilege is needed.

**Privileges:**
- `qyrix_app` gets INSERT and SELECT on `observer_outbox`, UPDATE (`sent_at`, `attempts`) only, and no DELETE;
- UPDATE (`n`) on `observer_seq`;
- pruning of sent rows is a `qyrix_maint` SECURITY DEFINER function, like the existing evidence reset.

**Delivery guarantees:**
| Property | Mechanism |
|---|---|
| **No lost decision once it is recorded** | The outbox row is inserted in the **same transaction** as `save_evaluation` (ALLOW and BLOCK). If the transaction fails, there is no decision and no event, and the Gate already fails closed (R17) |
| **Gap-free per-tenant sequence** | `UPDATE observer_seq SET n = n + 1 WHERE tenant_id = $t AND epoch = $e RETURNING n` inside that transaction. DB sequences can leave gaps on rollback, which would raise false alarms. The row lock serializes concurrent writers (§5.3); heartbeats use a separate counter and never consume `seq` (§5.1) |
| **At-least-once delivery** | The publisher sends unsent rows in `seq` order and sets `sent_at` on 2xx. It retries with exponential backoff (cap 60 s) and alerts when `outbox_depth` or age passes thresholds |
| **Idempotency** | The observer keys on `event_id`. A byte-identical duplicate is acknowledged (`200 duplicate`). Same `event_id` with different content gives `EVENT_CONFLICT` (security alert, refused) |
| **Ordering** | The observer accepts out-of-order arrival but reconciles only up to `contiguous_seq` (§5) |
| **Crash recovery** | On restart the publisher resumes from the lowest unsent `seq`. Rows sent but not marked are re-sent and deduplicated |
| **Outbox loss** (DB restored from backup) | The sequence regresses, so the observer sees a seq ≤ watermark with different content: `PRODUCER_REGRESSION` and stream quarantine. The backend state witness also flags the DB regression. Recovery needs an **operator-signed epoch change** (§5.4); the GATE key cannot reset counters; results are never silently re-based |
| **Single active publisher** | `pg_try_advisory_lock(hash(producer_id))`; other instances idle (§5.3) |
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
 "key_id": "<ed25519 key id>", "epoch": 1, "seq": 1042, "hb_seq": null, "issued_at": "…", "tenant": "default",
 "type": "decision|grant|heartbeat|adapter_report|epoch_change", "body": {…},
 "sig": "<base64 Ed25519 over canonical(envelope without sig)>"}
```

**Event bodies:**
- `decision`: `gate_evaluation_id, correlation_id, agent_id, task_id, policy_version, verdict, rule_ids, tool, method,
  dest_host (A-label), params_digest, proof {n, hash}`.
- `grant`: `gate_evaluation_id, grant_id, execution_id, kind (issued|redeemed|executed|refused), integration,
  refusal_code?, params_digest, proof {n, hash}`.
- `heartbeat`: see §5.2. `seq` is null and `hb_seq` is set; heartbeats never consume event `seq` (§5.1).
- `epoch_change`: `{new_epoch, last_trusted_seq_per_tenant, reason}`. It is signed with the **operator recovery key**,
  not the GATE key (§5.4).
- `adapter_report`: `execution_id?, correlation_id, integration, claims {forwarded}`. E1 only.

**Observation (internal only):**
`observation_id, sensor (egress_proxy|dns|canary_http|canary_file), observed_at, channel, tenant?, canary_token?,
execution_id?, host, sni?, port, method?, path_sha256?, body_sha256?, bytes_in/out, connection_id, tunnel_opened_at?,
tunnel_closed_at?`.

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
| Producer regression / restore | seq reused with different content, or proof head regresses | `PRODUCER_REGRESSION`; stream quarantined until an operator-signed epoch change; INCONCLUSIVE | None |
| Out-of-order or replayed heartbeat | `hb_seq` ≤ newest accepted | ignored for watermarks; `HEARTBEAT_OUT_OF_ORDER` logged | None |
| Relevant tunnel shared with allowed executions | tunnel overlap (§7.5) | `TUNNEL_SHARED_WITH_ALLOWED_EXECUTION`; INCONCLUSIVE | None |
| Execution id reused on a second CONNECT | proxy | `EXECUTION_ID_REUSE`; UNAUTHORIZED_EXECUTION | None |
| Deployment attestation stale or failed | attestor (§7.3) | `COVERAGE_GAP`; BLOCKs INCONCLUSIVE; critical alert | None |
| Canary with no decision | `T_decision` timeout | `DECISION_MISSING`; INCONCLUSIVE; alert | None |
| Invalid signature / unknown producer / scope / replay / skew / conflict | ingest | refused, recorded, alert | None |
| Positive control fails | canary listener / resolver / file watcher | INCONCLUSIVE (`POSITIVE_CONTROL_FAILED`) | None |
| Bypass route open | attestor token reaches the sink (§7.3) | `COVERAGE_GAP`; BLOCKs on that channel INCONCLUSIVE; critical alert | None |
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
- `observer-probe`: optional sidecar on the backend's networks with the same restrictions, a **network-policy check
  only, never coverage proof** (§7.2).
- Host attestor (§7.3): **not** a container in the stack. It runs on the Docker host, as root, from a systemd timer or
  CI job, with its own attestor key.
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
- **the full bypass matrix in §7.4, run by the host attestor inside the deployed backend's own namespace** with
  host binaries, judged from the observer sink. This includes a negative control: a deliberately mis-configured
  backend (extra `egress` attachment, IPv6 enabled) **must** produce `COVERAGE_GAP`;
- DNS-forwarding validation;
- tunnel rules (§7.5): pre-existing tunnel at BLOCK, concurrent allowed tunnel to the same host, tunnel still open at
  window end, execution-id reuse. Each must give the documented result, with INCONCLUSIVE whenever attribution is
  impossible;
- sequence semantics (§5): concurrent writers stay gap-free and unique; heartbeat-before-events; out-of-order and
  replayed heartbeats; restore from backup → quarantine → operator epoch change; a GATE-key-signed epoch change is
  **refused**.

**Adversarial (simulated compromised backend holding the GATE key):**
- forged BLOCK plus direct exfiltration attempt → no route, plus BYPASS on canaries;
- tail suppression, with silent and with lying heartbeats;
- `DECISION_MISSING` on canaries;
- GATE key used to post an observation → `SCOPE_DENIED`;
- backend-to-observer-db connection must fail;
- replay and conflicting duplicates;
- forged ALLOW to a host the policy bundle disallows → `DIVERGES`;
- backend-reported heads in `producer_claims` never change any result's evidence level (property test);
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
| C5 | Egress proxy + resolver as chokepoint, tunnel binding/limits (§7.5), compose overlay, DOCKER-USER rules, host attestor (§7.3), DNS-forwarding validation | Attestor matrix passes inside the real backend namespace; negative control fails as required; T1/T4 tests |
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

## 18. Final decision checklist (approval needed before any implementation)
| # | Decision | Proposed answer |
|---|---|---|
| 1 | Offline **root key**, **policy-signing key** and **operator recovery key** (epoch changes), held by the operator and never mounted into backend or observer | Approve |
| 2 | Migration 008 as in §10 (additive): same-transaction outbox, gap-free per-tenant/epoch counter, separate heartbeat counter, `grants.execution_id` at INSERT | Approve |
| 3 | Heartbeat and sequence semantics in §5 (heartbeats are E0 claims and never consume `seq`; single publisher via advisory lock; restore → quarantine → operator-signed epoch) | Approve |
| 4 | Egress topology under the observer overlay only (§7.1): internal-only backend networks, DOCKER-USER IPv4/IPv6 rules on fixed bridge names, `dns:` to the observer, IPv6 sysctl off | Approve |
| 5 | Host attestor (§7.3) as the **only** coverage proof for the backend namespace, judged from the observer sink; probe sidecar demoted to a network-policy check | Approve |
| 6 | Tunnel rules (§7.5): one tunnel per execution, `T_tunnel` limit, INCONCLUSIVE whenever attribution is impossible | Approve |
| 7 | Cross-witnessed backend heads are claims only (§9); they never raise evidence level or establish observer authenticity | Approve |
| 8 | Canary paths: P2 first, P1 MCP harness as a follow-up (§6) | Approve |
| 9 | R21 (require-observer strict mode) | **Out of scope** |
| 10 | First implementation slice | **C1–C2 only**, then a review |

