# Observer Service: Phase C1–C2 implementation

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
