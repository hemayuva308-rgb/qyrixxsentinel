# Observer Service: Phase C1–C4 implementation

Design: `docs/PHASE_C_OBSERVER_DESIGN.md` (revision 3, approved at `fd76a80`). This document records what slices
**C1–C2** implement, how to run them, the resolutions taken where the design was silent or inconsistent, and the
limitations.

**C3–C7 are NOT implemented**:
- no sensors (egress proxy, resolver, canary listener or file watcher);
- no observer canaries, coverage attestation or host attestor;
- no reconciler, evidence levels or result API;
- no signed policy bundle;
- no anchoring, export or verifier.

R21 is not implemented. Consequently **nothing in C1–C2 can produce `ENFORCEMENT_VERIFIED`**, and the existing
colocated CEV is unchanged and labelled `evidence_level: colocated` (§10).

## 1. What is implemented

### 1.1 C1: observer package `backend/observer/` (separate process, separate database)
| Feature | Design § | Code | Tests |
|---|---|---|---|
| Separate package, **no import of backend code**; vendored canonical JSON, hash chain, Ed25519 | §2 code layout | `observer/__init__.py`, `canonical.py`, `crypto.py` | `test_observer_unit.py::test_observer_imports_nothing_from_backend`, `::test_canonical_matches_backend_publisher` |
| Key manifest signed by the offline **root** key (pinned public key in config) | §9, §12 | `observer/manifest.py` (details below) | `test_observer_unit.py` (manifest tests); `test_observer_pg.py::test_manifest_rollback_refused` |
| Envelope: canonical JSON, ≤ 64 KiB, Ed25519 over canonical(envelope without `sig`) | §12 | `observer/envelope.py` | `test_observer_unit.py` (structural refusals) |
| Signed ingest (`POST /v1/events`): producer, key, signature, scope, tenant, skew, replay, conflicts | §12, §14 | `observer/ingest.py` | `test_observer_pg.py` |
| Gap-free sequence watermarks; held events beyond a hole; tail detection; silence | §5.1, §5.3, §5.5 | `ingest.py`, `feed.py` | `test_observer_pg.py` (sequence and heartbeat tests) |
| Heartbeats: E0 claims, own `hb_seq`, never consume `seq`, never lower a watermark | §5.1–§5.3 | `ingest.py::_heartbeat` | `test_heartbeat_*`, `test_old_heartbeat_never_lowers_watermark` |
| Epochs, quarantine, restore detection, **operator-signed** epoch change only | §5.4 | `ingest.py::_epoch_change` | `test_restore_quarantine_then_operator_epoch_change`, `test_gate_signed_epoch_change_refused` |
| Backend-reported heads stored as **claims** (`producer_claims`, label `backend_reported_head`, E0 by constraint) | §9 | `O001`, `ingest.py` | `test_producer_claims_never_count_as_evidence` |
| Window closure state machine (pure) | §5.6 | `observer/feed.py::window_closure` | `test_window_*`, `test_exhaustive_no_sensor_window_is_never_closed` |
| observer-db O001: own roles, RLS by tenant, append-only triggers, no DELETE | §13 | `observer/migrations/O001_observer_core.sql`, `observer/migrate.py` | `test_runtime_account_is_least_privilege`, `test_evidence_is_append_only_even_for_owner`, `test_tenant_isolation_rls` |
| Signed, hash-chained observer ledger, verified at start (degraded ⇒ ingest refused) | §2, §9, §14 | `observer/ledger.py` | `test_ledger_tamper_detected_on_verify`, `test_observer_refuses_to_sign_with_unlisted_or_revoked_key` |
| `GET /v1/health` (no data), `GET /v1/status` (operator token) | §12 | `observer/app.py` | `test_http_api` |
| Fail-closed start-up: manifest, rollback, runtime privileges, schema, ledger | §13, §14 | `observer/main.py` | `test_observer_main_build_refuses_overprivileged_or_unmigrated` |
| Operator key tool (generate keys, sign manifest) | §9 | `observer/keytool.py` | (used by tests through `manifest.sign_manifest`) |

Manifest rules enforced by `observer/manifest.py`:
- Scopes are limited by producer kind. A **gate** key may hold only `decision`, `grant` and `heartbeat`. An **adapter** key may hold only `adapter_report`.
- An `epoch_change` verifies only against the recovery keys.
- A key may hold only one role.
- A manifest may not roll back to an older version.

### 1.2 C2: backend
| Feature | Design § | Code | Tests |
|---|---|---|---|
| Migration 008 (additive): `observer_outbox`, `observer_seq`, `observer_hb_seq`, `grants.execution_id` | §10 | `backend/migrations/008_observer_outbox.sql` | `test_observer_feed_pg.py::test_migration_008_is_additive_and_preserves_rows` |
| Outbox row in the **same transaction** as `save_evaluation` (ALLOW and BLOCK) and as the atomic grant consumption | §4, §10 | `app/persistence.py` (`save_evaluation`, `consume_grant`, `_emit`), `app/gateway.py` | `test_decisions_and_grants_emitted_in_order_without_raw_data`, `test_grant_consumption_and_refusal_events_carry_execution_id` |
| Gap-free per-(tenant, epoch) counter; rollback consumes no number; concurrent writers serialize | §5.1, §5.3, §10 | `qyrix_observer_emit` (SECURITY DEFINER) | `test_rolled_back_transaction_consumes_no_seq`, `test_concurrent_writers_are_gap_free_and_unique`, `test_concurrent_uncommitted_writer_blocks_and_rollback_leaves_no_gap` |
| Enabled feed that cannot write ⇒ decision not recorded ⇒ BLOCK (R17) | §10 | unchanged Gate error path | `test_outbox_failure_fails_closed`, `test_missing_installation_identity_fails_closed` |
| Producer id `gate:<installation.install_id>` | §5.1 | `app/observer_feed.py::producer_id` | all C2 tests |
| Publisher: in-order, at-least-once, deterministic re-signing (duplicates are idempotent), backoff, never skips a row | §10 | `app/observer_feed.py::Publisher` | `test_publisher_delivers_and_heartbeat_attests`, `test_crash_after_send_resends_are_duplicates`, `test_observer_down_gate_unaffected_backlog_replays_in_order` |
| Single active publisher (`pg_try_advisory_lock(hashtextextended(producer_id))`) | §5.3 | `Publisher.acquire` | `test_single_active_publisher` |
| Heartbeats with per-tenant `allocated_through_seq` and backend proof head (claims) | §5.2 | `Publisher.heartbeat_once` | `test_heartbeats_never_consume_seq` |
| Restore ⇒ observer quarantine ⇒ `python -m app.recovery observer-epoch` signed with the **operator recovery key** | §5.4 | `app/recovery.py` | `test_restore_quarantine_then_operator_epoch` |
| `execution_id` per grant (set at INSERT), in grant events and the redeem response | §4, §12 | `app/gateway.py::_new_grant`, `app/persistence.py` | `test_grant_survives_restart_with_execution_id` |
| CONNECT execution header (approved pinned-IP variant, §3 below) | §4, §7.5 | `app/netguard.py::_proxied_request`, `app/adapter.py` | `tests/test_egress_tagging.py` |
| MCP proxy adapter reports (E1, signed, fire-and-forget) | §12 | `app/observer_feed.py::AdapterReporter`, `app/mcp_proxy.py` | `test_egress_tagging.py::test_mcp_proxy_*`, `test_adapter_report_*` |
| Colocated CEV labelled `evidence_level: colocated` | §10 | `app/api.py` | `test_colocated_cev_results_are_labelled` |

### 1.3 C3: observer canaries (owner decisions D1–D5, amended)
| Feature | Design § / decision | Code | Tests |
|---|---|---|---|
| Tokens: 128-bit CSPRNG (`secrets.token_bytes(16)`) for the canary token, the positive-control token and the correlation id. All are minted in the observer; **only SHA-256 hashes are stored** | §6 | `observer/canary.py::mint` | `test_tokens_are_csprng_and_unique`, `test_run_is_recorded_before_submission_and_only_hashes_are_stored` |
| Run record, `CREATED` event and ledger record written **before** any submission; DB down ⇒ nothing submitted | §6 | `CanaryService.start` | same; `test_database_unavailable_nothing_submitted_and_hits_not_silent` |
| Expectation recorded only as a **test condition**: `expected_condition=BLOCK`, `expected_basis=construction`. The REST response, the signed claim (or its absence) and every discrepancy are recorded separately; nothing is assumed | D2 | `CanaryService._finish` | `test_signed_block_claim_matches_expectation_without_any_verdict`, `test_discrepancies_are_recorded_not_concluded`, `test_rest_response_is_never_treated_as_a_claim` |
| `DECISION_MISSING`: no signed decision claim (C2 feed, E0) with the observer-minted `correlation_id` within `T_decision` | §6, §5.5 | `_finish` | `test_decision_missing_and_late_claim` |
| P2 client: **only** `POST /api/v1/sentinel/gate/evaluate`, observer-held canary key (secret read from file at use, never stored; key id recorded); **live submission OFF by default** (`SUBMISSION_DISABLED`); no execute/redeem path | D4 | `P2Client` | `test_live_p2_is_disabled_by_default`, `test_p2_client_only_ever_calls_evaluate`, `test_backend_unavailable` |
| HTTP canary sensor: stdlib, **loopback only** (non-loopback bind refused), bounded concurrency and body, unknown tokens counted not stored, no request logging | D3 | `HttpCanarySensor` | `test_http_sensor_is_loopback_only`, `test_forged_and_invalid_observations_are_not_recorded` |
| File canary sensor: polling an **observer-owned** directory (mode 0700), regular files only, no symlinks | D3, D4 | `FileCanarySensor` | `test_file_channel_observation_and_cleanup`, `test_file_sensor_ignores_symlinks_and_requires_private_dir` |
| E3 observations (canary + positive control), `in_window` / `late`; repeated hits are separate observations; a token counts only on its own channel | §6, §12 | `CanaryService.record` | `test_token_observation_is_e3_and_produces_no_verdict`, `test_repeated_and_late_observations` |
| Positive controls: the observer stimulates its own sensor with the control token in every run; missing ⇒ `POSITIVE_CONTROL_FAILED` alert | §5.6, §14 | `_positive_control`, `_finish` | `test_positive_control_failure_alerts`, `test_positive_control_outside_window_fails` |
| Expiry and cleanup: lifecycle ends at `max(W, T_decision)`; canary files removed; evidence never deleted; hits after the window are `late` | §6 | `_finish`, `_cleanup` | `test_repeated_and_late_observations`, `test_file_channel_observation_and_cleanup` |
| Restart: runs left open become `INTERRUPTED` (alert `CANARY_RUN_INTERRUPTED`), are never "finished", and later hits are still recorded as `late` | §14 | `CanaryService.recover` | `test_restart_interrupts_open_runs_and_late_hits_still_recorded` |
| O002 (observer-db only): `canary_runs`, `canary_run_events`, `observations`; append-only, RLS by tenant, runtime SELECT/INSERT only; closed event vocabulary (no verdict value can be stored) | D5, §13 | `observer/migrations/O002_canaries.sql` | `test_o002_upgrade_preserves_o001_data_and_failed_migration_rolls_back`, `test_o002_runtime_privileges_and_append_only`, `test_runtime_cannot_insert_non_e3_or_verdict_rows`, `test_tenant_isolation` |
| API (operator token): `POST /v1/canaries/run`, `GET /v1/canaries/{tenant}/{run_id}`; canary counters in `/v1/status` | §12 | `observer/app.py` | `test_canary_api_requires_operator` |

**Alerts (ledger):** `CANARY_RUN_CREATED` (record), `CANARY_TOKEN_OBSERVED`, `DECISION_MISSING`, `DECISION_DISCREPANCY`,
`POSITIVE_CONTROL_FAILED`, `CANARY_RUN_INTERRUPTED`.

**No verdicts:** C3 generates no `ENFORCEMENT_VERIFIED`, `BYPASS_DETECTED` or `UNAUTHORIZED_EXECUTION`. This is enforced
three ways:
- the `canary_run_events.kind` CHECK constraint;
- an AST test over `observer/*.py`;
- a scan of every stored event and ledger record in the tests.

`WINDOW_ENDED` carries `result: null`. C4 will consume these records.

**C3 limitations (honest scope):**
- **Not reachable by the deployed backend.** Sensors are loopback / observer-directory only (D3). Backend writes
  through a shared volume and the DNS resolver zone are C5. **No claim is made that the deployed backend or any
  integration can reach a sensor.**
- **Live P2 coverage is not claimed.** Live P2 submission is disabled by default (D4) and was tested only with fixture
  transports. There is no observer→backend network route, and none was created. The P1 MCP harness is deferred.
- **The expectation is not validated by policy.** `expected_basis: construction` describes how the expectation was
  chosen. It is not validated by a signed policy bundle (C6), and the Gate is never assumed or forced to BLOCK.
- **No protection against an adaptive backend (§6).** An adaptive compromised backend can recognise the canary
  credential or the observer-owned destinations and behave honestly only for them. Canaries test the integration and
  non-adversarial faults, and exercise the decision feed; they do **not** detect every compromised-backend scenario.
- **Restarts lose sensor continuity.** Hits that arrive while the observer is down are not observed, which is why such
  runs are `INTERRUPTED`.
- **Unrecorded hits.** A sensor hit that cannot be recorded (observer DB down) is counted as `unrecorded`, not stored.
- **The canary listener accepts unauthenticated traffic.** It was built not to repeat F1/F3: synchronous handlers,
  bounded concurrency and body, unknown tokens counted rather than stored. F1/F3 themselves (`/v1/events`) remain
  open.
- **Defect found and fixed during C3.** `observer/main.py` re-fetched the applied-migration list once per expected
  migration. With O002 present, a migrated database was wrongly refused at startup. This was a C1 defect; it is now
  fetched once.

### 1.4 C4 (minimal, owner-approved): canary reconciliation, read API, dashboard panel
| Feature | Design § | Code | Tests |
|---|---|---|---|
| **Audit F4:** a revocation (operator, or compensation after a failed proof write) writes a `grant kind=revoked` claim **in the same transaction**. A reversed ALLOW also writes a superseding decision claim with `reversed_from: ALLOW`. If the claim cannot be written, the revocation still happens (safety beats telemetry) and a critical event is raised | §10, §12 | `app/gateway.py`, `app/persistence.py::revoke_grant`, `app/observer_feed.py::revocation_events` | `test_observer_c4_fixes_pg.py::test_f4_*` |
| **Audit F9:** an epoch change whose `last_trusted_seq` exceeds the observer's contiguous watermark is accepted (it is operator-signed) but alerted as `EPOCH_LAST_TRUSTED_AHEAD`. Runs touching an epoch change are INCONCLUSIVE | §5.4 | `observer/ingest.py` | `test_f9_*` |
| **Audit F13:** the publisher sends a heartbeat right after any batch that delivered events. Runs whose window touches an epoch change are INCONCLUSIVE (`EPOCH_BOUNDARY`) | §5.3, §5.4 | `app/observer_feed.py::publish_once` | `test_f13_*`, `test_every_missing_precondition_is_inconclusive[epoch]` |
| Canary-only reconciler (pure): BYPASS_DETECTED / UNAUTHORIZED_EXECUTION only when **every** precondition holds; otherwise INCONCLUSIVE with reasons. ENFORCEMENT_VERIFIED is **not producible** (needs a C5 coverage attestation) | §11 | `observer/reconcile.py` | `test_observer_reconcile.py` (exhaustive grid, more than 50,000 cases) |
| Facts from observer data only. E3 observations and run lifecycle; the signed claim is used only to classify an observed effect, and must come from an active, current-epoch gate stream, in time and unreversed. A closing heartbeat reached by the watermark is required for UNAUTHORIZED. Backend-reported heads are never an input | §5.6, §11 | `observer/canary.py::_facts` | `test_observer_reconcile_pg.py` |
| O003 `reconciliations` (observer-db only): versioned (`supersedes`), append-only, RLS by tenant, runtime SELECT/INSERT only. **ENFORCEMENT_VERIFIED is not an allowed value.** A definite result requires E3 and has no reasons; INCONCLUSIVE requires reasons. Each version is also signed into the ledger. Late data creates a new version; INCONCLUSIVE→definite raises `RESULT_ESCALATED` | §11, §12, §13 | `observer/migrations/O003_reconciliations.sql`, `CanaryService.reconcile_all` | `test_o003_*`, `test_unauthorized_needs_closing_heartbeat_then_supersedes` |
| Read API `GET /v1/reconciliations?tenant=&since=&limit=`. Accepts the operator token (all tenants) or **tenant-scoped read-only keys** (`OBSERVER_READ_TOKENS_FILE`, stored as SHA-256, constant-time compare). Read keys cannot start canaries or read status | §12 | `observer/app.py` | `test_read_api_tenant_scoped_tokens` |
| C3-3: at most 100 stored observations per run (the rest counted) and at most one `CANARY_TOKEN_OBSERVED` ledger alert per run per minute. C3-4: file-sensor scans serialized; per-run memory pruned on cleanup. C3-1/C3-2: an unknown submission and claims from quarantined or closed streams are INCONCLUSIVE | — | `observer/canary.py` | `test_c3_3_*`, `test_c3_4_*` |
| Dashboard: `GET /api/v1/sentinel/observer/reconciliations` (read permission, **caller's tenant only**) relays the observer read API with a read-only key (`QYRIX_OBSERVER_READ_TOKEN_FILE`). Allow-listed fields; an unexpected result value becomes INCONCLUSIVE. The response is labelled *relayed by the backend, not independent of it*. Panel "Independent Observer · Canary Reconciliations" on the Enforcement page, in the existing theme | §4 step 6 | `app/observer_feed.py::fetch_reconciliations`, `app/api.py`, `frontend/src/app/(app)/enforcement/page.tsx` | `test_observer_relay_pg.py`; browser end-to-end check (report) |

**C4 limitations:**
- **No ENFORCEMENT_VERIFIED, by design.** Absence of an observation is INCONCLUSIVE (`COVERAGE_UNATTESTED`) until C5 provides coverage attestation.
- **Canary runs only.** Real traffic is not reconciled; that needs proxy observations (C5).
- **C3 limits still apply.** Sensors are loopback / observer-directory only, and live P2 is off by default and untested live. BYPASS / UNAUTHORIZED results have so far come only from **test fixtures**: a deliberately broken integration.
- **The dashboard view is relayed by the backend.** A compromised backend could misreport it. Independent verification is the observer API and its signed ledger.
- **F13 residual.** The loss window shrinks to delivery-plus-heartbeat latency but is not zero.
- **Interrupted runs.** These, and runs whose positive control could not be evaluated, are always INCONCLUSIVE, even when the token was seen.
- **F1, F2, F3 and F7 remain open** and block C5.

## 2. Configuration

**Backend** (the feed is inactive unless `QYRIX_OBSERVER_URL` is set; durable mode only):

| Variable | Meaning |
|---|---|
| `QYRIX_OBSERVER_URL` | Observer base URL. Setting it turns on outbox writes and the publisher |
| `QYRIX_OBSERVER_GATE_KEY_FILE` | GATE signing key (Ed25519 PEM). Its public key must be in the observer manifest under the producer `gate:<install_id>`, with scopes decision, grant and heartbeat |
| `QYRIX_OBSERVER_HEARTBEAT_SECONDS` | Heartbeat interval; default 10 |
| `QYRIX_EGRESS_PROXY_URL` | `http://host:port` of the egress proxy (C5). If unset, egress is direct and pinned, exactly as before |
| `QYRIX_OBSERVER_ADAPTER_KEY_FILE` | MCP proxy only: adapter key (scope `adapter_report`) |
| `QYRIX_OBSERVER_ADAPTER_ID` | MCP proxy only: adapter id; default `mcp_proxy` |
| `QYRIX_OBSERVER_TENANT` | MCP proxy only: tenant; default `default` |

The feed needs the installation identity, which is created by the state witness (`app/integrity.py`). With
`QYRIX_STATE_WITNESS=disabled` and no `installation` row, an enabled feed **fails closed**: every evaluation is
blocked with R17. In that case enable the witness, or create the identity with `python -m app.recovery accept`.

**Observer canaries (C3, optional):**
- `OBSERVER_CANARIES=1` enables canaries.
- `OBSERVER_CANARY_HTTP_PORT` sets the HTTP sensor port (loopback only).
- `OBSERVER_CANARY_DIR` is the observer-owned directory for file canaries (mode 0700).
- `OBSERVER_CANARY_CREDENTIALS_FILE` maps each tenant to its credential: `{"tenants": {t: {"key_id", "token_file"}}}`.
- Live P2 runs only with **both** `OBSERVER_CANARY_P2_LIVE=1` and `OBSERVER_CANARY_BACKEND_URL`. It is off by default
  and must not be enabled before the deployment phase validates the route (D4).

**Observer**: all settings are listed in the docstring of `backend/observer/main.py` and include:
- `OBSERVER_DATABASE_URL` (or `OBSERVER_DB_*`);
- `OBSERVER_ROOT_PUBLIC_KEY`, `OBSERVER_MANIFEST_FILE`, `OBSERVER_SIGNING_KEY_FILE`;
- `OBSERVER_OPERATOR_TOKEN_FILE`.

## 3. Runbook (operator)

**Keys.** The root and operator recovery keys are generated **offline**, and the observer manifest is signed offline:
```bash
python -m observer.keytool gen --out root.pem
```
```bash
python -m observer.keytool gen --out recovery.pem
```
```bash
python -m observer.keytool gen --out observer-signing.pem
```
```bash
python -m observer.keytool gen --out gate-signing.pem
```
```bash
python -m observer.keytool sign-manifest --root-key root.pem --in manifest.json --out manifest.signed.json
```
`root.pem` and `recovery.pem` never go into a container. The backend receives only `gate-signing.pem`; the observer
receives only `observer-signing.pem`, `manifest.signed.json` and the root **public** key.

**Observer database.** Run the migration with the observer-db admin account:
```bash
OBSERVER_ADMIN_DATABASE_URL=... python -m observer.migrate --runtime-password-file pw
```
Then start the service with `python -m observer.main`.

**Backend database.** `python -m app.migrate` applies migration 008. Do not run it against production without the
normal change process.

**After a backend database restore.** The observer quarantines the stream (`PRODUCER_REGRESSION`). With the backend
stopped:
```bash
QYRIX_ADMIN_DATABASE_URL=... QYRIX_OBSERVER_URL=... python -m app.recovery observer-epoch --recovery-key recovery.pem --reason "restored backup <id> after <incident>" --out epoch.json --send
```
With `--send`, the epoch bump is committed only after the observer accepts the record. Outbox rows of the old epoch
that were never delivered are reported as `stale_epoch_unsent` and are never re-sent into the new epoch.

## 4. Resolutions where the design was silent or inconsistent (no new security decision)
1. **CONNECT header vs. SSRF pinning (approved by the owner before coding).**
   - The proxy is asked to `CONNECT <pinned-ip>:<port>`: the IP that the backend resolved and validated, exactly as
     today.
   - The CONNECT request carries `X-Qyrix-Host: <A-label>` and `X-Qyrix-Execution: <uuid4>`.
   - TLS SNI and certificate verification use the hostname.
   - Stdlib `http.client` and httpcore would use the CONNECT target (the IP) as the TLS server name, so the adapter uses
     a small tunnel subclass instead.
   - For plain HTTP through the proxy, the tags are request headers. The C5 proxy must strip them before forwarding.
   - **Doc amendment for C5:** the proxy checks *SNI = `X-Qyrix-Host`* and *CONNECT IP ∈ resolution of
     `X-Qyrix-Host`*, instead of "SNI = CONNECT authority" (§7.4, §7.6).
2. **Outbox key includes the epoch.** The key is `(tenant_id, epoch, seq)`, because seq restarts at 1 in a new epoch
   (§5.4). The §10 sketch said `(tenant_id, seq)`.
3. **Counter privileges are tighter than the §10 sketch.**
   - The runtime role has **no** INSERT on the outbox and **no** UPDATE on either counter.
   - Allocation and the outbox insert happen only inside `qyrix_observer_emit`, a SECURITY DEFINER function owned by the
     NOLOGIN role `qyrix_feed` and called in the caller's transaction.
   - The epoch can be changed only by the admin account, through the recovery tool.
   - A runtime that is a member of `qyrix_feed` is refused at start-up.
4. **Clock skew.**
   - Heartbeats must satisfy |issued_at − now| ≤ S.
   - Decision and grant events may arrive late, because outbox backlog replay is required (§10, §14), so only
     future-dated events are refused. Replay is still impossible: `event_id` and `(producer, epoch, tenant, seq)` are
     unique.
   - `issued_at` is the outbox `created_at`, so a re-send is byte-identical apart from its signature.
   - Duplicate/conflict detection compares content excluding `sig` and `key_id`, so a re-send signed with a rotated
     key is still a duplicate.
5. **Adapter reports** have no sequence stream (`seq` and `hb_seq` are null, epoch 1). They are E1 only, deduplicated
   by `event_id`, and never touch watermarks.
6. **ALLOW decision events carry `proof: null`.** The Gate persists an ALLOW evaluation *before* its proof record, and
   that order is unchanged. BLOCK events carry the proof reference. The heartbeat's proof head covers both.
7. **Refusals in the ledger are throttled:** at most one per (code, producer) per 60 s. Security alerts
   (`EVENT_CONFLICT`, `PRODUCER_REGRESSION`, `SCOPE_DENIED`) are never throttled. Unauthenticated content is never
   stored.
8. **Producer keys must be valid at receipt time**, not at the claimed `issued_at`, so a revoked key cannot backdate.
   Rotate with an overlap that is longer than the worst outbox backlog.
9. **Old-epoch unsent rows** are skipped by the publisher and counted. They are not deleted, because the runtime has
   no DELETE.
10. **Additional refusal codes**, beyond the §12 list: `MALFORMED`, `UNKNOWN_EPOCH` (retryable), `EPOCH_CLOSED`,
    `EPOCH_INVALID`, `STREAM_QUARANTINED`, `PRODUCER_REGRESSION`, `OBSERVER_KEY_INVALID`, `LEDGER_INVALID`,
    `OBSERVER_DB_UNAVAILABLE`, `MANIFEST_ROLLBACK`, `MANIFEST_VERSION_REUSED`.
11. **`/v1/status` operator authentication** uses a bearer token from `OBSERVER_OPERATOR_TOKEN_FILE`, compared in
    constant time. Without the file, the endpoint is disabled (503).

## 5. Limitations and unresolved risks (C1–C2)
- **No observer-originated evidence exists yet.** Everything ingested is a claim (E0) or a self-report (E1). The
  observer detects gaps, tails, silence, conflicts and regressions *in the claims*, but cannot detect a backend that
  lies consistently (§5.5). That needs C3 canaries and C5 mediation. Windows can never close without sensors.
- **The observer is not yet deployed as a separate container.** The compose overlay, networks and DOCKER-USER rules
  belong to C5. The code is separate and runs against its own database, but **nothing in C1–C2 provides process or
  host isolation by itself**. On a single host, boundary D (host and Docker daemon) is shared.
- **The GATE key lives in the backend.** A compromised backend can sign any claim it wants. The observer limits what
  such claims can do: scopes, gap-free sequences, operator-only epochs, and claims never counting as evidence.
- **The MCP proxy needs a network path to the observer** for its reports. If the observer is unreachable, reports are
  dropped (counted) and calls are unaffected.
- **Enabling the feed couples decision recording to outbox writes, by design (§10).** An outbox failure blocks
  decisions with R17. That is fail-closed, not an outage of authorization semantics.
- **The publisher runs as a backend thread** (modular monolith). It holds no observer keys and has no observer-DB
  access.
- **Ingest is serialized** by one global advisory lock: simple and linear, with limited throughput. Rate limiting
  (`RATE_LIMITED`) is not implemented. Only the ledger refusal records are throttled.
- **Tunnel binding and limits are not implemented** (§7.5: one tunnel per execution is enforced at the proxy, which is
  C5). The client already opens one connection per execution and never pools.
- **Prune:** `qyrix_observer_prune` exists but is granted to no one. Run it with the admin account.
