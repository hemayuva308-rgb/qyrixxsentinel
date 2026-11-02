# QYRIX SENTINEL — Operations and Incident Runbooks (v1.4)

Audience: the operator running a deployment. Companion documents: `docs/DISASTER_RECOVERY.md` (backup, restore, key
management, RPO/RTO), `docs/SECURITY_TEST_PLAN.md`, `docs/DEPENDENCY_AUDIT.md`. Alert rules: `ops/prometheus/qyrix-alerts.yml`.

## 1. Deployment topology (Docker Compose)

| Service | Network | Secrets mounted | Notes |
|---|---|---|---|
| `db` (postgres:16-alpine, digest-pinned) | internal only | `db_admin_password` | never published |
| `migrate` (one-shot, backend image) | internal | `db_admin_password`, `db_runtime_password` | schema + least-privilege runtime role; must exit 0 before `backend` starts |
| `backend` (FastAPI) | internal only, **no egress** | `db_runtime_password`, `state_witness_key`, `data_key`, `client_sig_key` | logs in as `qyrix_runtime`; refuses to run with an over-privileged account |
| `frontend` (Next.js) | internal + edge | `client_sig_key` | only published port: `127.0.0.1:3000` — put a TLS reverse proxy in front |

Volumes: `pgdata` (database), `chain` (proof chains, anchors), `witness` (data-loss witness — keep it on **different
storage** from `pgdata` and `chain` where possible), `workspaces` (tenant `file.read` jails).

**Production deployment requirements** (not provided by the Compose file itself):
1. TLS termination in front of the frontend; set `QYRIX_COOKIE_SECURE=1`.
2. If that proxy appends the visitor address to `X-Forwarded-For`, set `QYRIX_TRUSTED_PROXY_HOPS=1` (else per-IP limits
   are skipped; per-account and global limits still apply).
3. Prometheus scraping `/api/v1/metrics` (`QYRIX_METRICS_TOKEN`), the rules in `ops/prometheus/qyrix-alerts.yml`, a
   blackbox probe on `/api/v1/ready`, node_exporter textfile collector on `backups/` (backup age).
4. After the first start, put the logged `install_id` into `QYRIX_EXPECTED_INSTALL_ID`.
5. Scheduled `scripts/backup.sh` (≥ daily) with off-site upload; quarterly restore drill.
6. One backend replica per database is the tested configuration; the shared rate limiter supports more, but
   multi-replica operation has not been load-tested.

## 2. Health, readiness, metrics, events

* `GET /api/v1/health` — process alive. `GET /api/v1/ready` — 200 only when: proof chain valid, Gate not degraded,
  persistence not down, database reachable, integrity `OK`/`FRESH_INSTALL`/`ADOPTED_EXISTING`. 503 body lists `checks`
  and `integrity_reason`. The Compose health check uses it.
* `GET /api/v1/metrics` (bearer `QYRIX_METRICS_TOKEN`; 404 when unset) — counters + per-tenant gauges
  (`qyrix_proof_chain_length`, `qyrix_gate_degraded`, `qyrix_persistence_up`, `qyrix_integrity_ok`, `qyrix_external_calls`).
* Security events: one JSON line per event on the backend's stdout (logger `qyrix.security`). Field names that can
  carry secrets are dropped and values that look like credentials are replaced by `[REDACTED]` (tested). E-mail
  addresses appear only as a 12-hex pseudonymous `account` tag. Ship stdout to your log platform with retention ≥ 1 year.
* Alerts: `{"event":"alert", "alert":..., "severity":..., "tenant":..., "count":...}` + `qyrix_alerts_total`; optional
  signed webhook (`QYRIX_ALERT_WEBHOOK_URL`, `QYRIX_ALERT_WEBHOOK_SECRET_FILE`; verify `X-Qyrix-Signature` =
  HMAC-SHA256(body)). In the default Compose network the backend has no egress, so the webhook receiver must be
  reachable on the internal network (or use log-based alerting).

## 3. Incident runbooks

General rules for every incident: do not restart repeatedly to "clear" a state (the blocking states are deliberate and
are not cleared by restarts); preserve logs, the chain volume and the witness volume before any change; record actions
with timestamps; never paste secrets into tickets or chat.

### <a id="rb-isolation"></a>RB-1 Tenant-isolation violation (critical)
Meaning: PostgreSQL row-level security rejected a statement that tried to touch another tenant's rows. Correct code never
triggers this; it indicates a bug being exercised or an attack via code execution / SQL injection.
1. Declare a security incident. Capture the `tenant_isolation_violation` events and surrounding requests (`cred`, tenant).
2. Revoke the credentials involved (`POST /sentinel/keys/{id}/revoke`, or disable the tenant via the platform API).
3. If code execution is suspected: stop the backend, rotate `db_runtime_password` (re-run `migrate`), `client_sig_key`,
   `data_key` (requires MFA re-enrolment), operator tokens; rebuild images from a clean commit.
4. Review: RLS held (the event proves the statement was refused); determine what the attacker could read within the
   compromised tenant. Note the documented limit: code running *inside* the backend can choose any tenant context.

### <a id="rb-db-privilege"></a>RB-2 Over-privileged runtime database account (critical)
Meaning: the backend refused to start persistence because its login is superuser / BYPASSRLS / owner / member of a
privileged role. The Gate blocks everything (R17) — fail closed.
1. Check `QYRIX_DB_USER` (must be `qyrix_runtime`) and that `db_runtime_password` is not the admin password.
2. `docker compose run --rm migrate` re-asserts the role attributes. Never "fix" this by granting more privileges.

### <a id="rb-integrity"></a>RB-3 Data integrity: RECOVERY_REQUIRED (critical)
Meaning: the database, the proof chain and the signed state witness disagree (database lost/replaced, chain deleted or
rolled back, witness missing/forged, restore of an older backup). The Gate blocks everything.
1. Read the reason: `GET /api/v1/ready` → `integrity_reason`, or `docker compose run --rm backend python -m app.recovery status`.
2. Decide from the reason table in `docs/DISASTER_RECOVERY.md` §4 whether this is *expected* (you just restored a backup)
   or *unexpected* (possible tampering or data loss). Unexpected ⇒ treat as a security incident; preserve all volumes.
3. Only when the current state is the one you want to run with: stop the backend, then
   `docker compose run --rm backend python -m app.recovery accept --reason "<incident id + what happened>"`, start it.
   The acceptance is logged in the witness and written into each affected tenant's proof chain (`RECOVERY_ACCEPTED`).
4. `QYRIX_STATE_WITNESS=disabled` is never a fix (it removes the protection; `QyrixStateWitnessDisabled` fires).

### <a id="rb-proof"></a>RB-4 Proof chain degraded (critical)
Meaning: chain verification failed (edited, reordered, truncated record; anchor mismatch; DB mirror ≠ chain prefix).
1. `python backend/scripts/verify_proof.py` on a copy of the chain file to locate the first bad record.
2. Compare with the latest backup (`scripts/backup.py verify --decrypt`) and with RFC 3161 anchors (`--tsa-ca`).
3. There is no API to clear the degraded state. Restore known-good evidence (DR runbook) and accept the recovery.

### <a id="rb-database"></a>RB-5 Database unavailable / rate-limit store errors (high/critical)
Effect: evaluations BLOCK with `R17_PERSISTENCE_UNAVAILABLE`, executions are refused, human logins and other
authentication paths answer 503 (their rate limits fail closed). Nothing is authorised while the database is down.
1. Check `db` container health, disk space, connection limits (`QYRIX_DB_POOL_SIZE` × replicas < `max_connections`).
2. Recovery is automatic: the backend re-verifies the account and the proof mirror before accepting traffic again.

### <a id="rb-auth"></a>RB-6 Authentication / MFA failure spike (high)
1. Look at `login_failed` / `auth_failure` / `mfa_failed` events: same `account` tag (targeted) or many (stuffing)?
2. Targeted: the account is already locked for `QYRIX_LOGIN_LOCK_SECONDS`; contact the user out of band; consider an
   admin password reset. Many accounts: verify the reverse proxy passes visitor IPs (`QYRIX_TRUSTED_PROXY_HOPS`),
   consider lowering `QYRIX_LOGIN_PER_IP_PER_MIN`, block sources at the edge.
3. `recovery_code_used` / `mfa_reset` alerts: confirm with the user that it was them.

### <a id="rb-blocks"></a>RB-7 Repeated execution blocks / refusals (high)
Meaning: an agent keeps attempting actions the Gate blocks (prompt injection in progress, compromised integration, or
misconfiguration), or grant ids are being replayed/forged (`repeated_execution_refusals`).
1. Identify `cred` and rule ids from `gate_decision` events; inspect the provenance in the console (Forensic view).
2. Revoke the agent's key if it is compromised; review the skill/instruction sources flagged UNTRUSTED.

### <a id="rb-ready"></a>RB-8 Not ready
Read the `checks` object from `/api/v1/ready` and follow RB-3/4/5 accordingly.

### <a id="rb-alerts"></a>RB-9 Alerting pipeline
`QyrixAlertEngineBroken` means in-process alert evaluation raised; events are still logged. Check backend logs for
the stack trace; alert from logs until fixed. Webhook delivery failures: `qyrix_alert_deliveries_total{ok="false"}`.

## 4. Routine operations
* **Key rotation:** API keys — create new, update the integration, revoke old (sessions die immediately). Operator env
  tokens — change and restart (their sessions die). `db_runtime_password` — change the file, `docker compose run --rm
  migrate`, restart backend. `client_sig_key` — change file, restart frontend + backend together. `state_witness_key` —
  stop backend, change key, `app.recovery accept --reinitialize-witness --reason "key rotation"`. `data_key` — rotating
  it invalidates stored TOTP secrets: users re-enrol (admin MFA reset) — plan accordingly.
* **Tenant lifecycle:** `POST /api/v1/platform/tenants`, bootstrap owner via `POST /api/v1/platform/tenants/{id}/invitations`,
  disable with `POST /api/v1/platform/tenants/{id}/disable` (all keys/sessions stop working at once).
* **E-mail:** not built in. Configure `QYRIX_MAIL_WEBHOOK_URL` (+ secret, `QYRIX_PUBLIC_URL`) to an internal relay you
  operate; otherwise invitation and admin-reset tokens are shown once to the admin for out-of-band delivery.
