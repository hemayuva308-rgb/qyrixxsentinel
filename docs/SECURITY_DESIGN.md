# QYRIX SENTINEL — Security Design (as implemented, v1.2)

## 1. Principles
1. **Prevention before execution.** A tool action runs only after a deterministic ALLOW, a recorded proof, and a valid single-use grant.
2. **Default deny, fail closed.** Unknown tool, destination, label, lineage, approval or any exception ⇒ BLOCK (`R0_FAIL_CLOSED`).
3. **AI is advisory.** The Meta Llama classifier explains; it cannot allow, approve, change trust, create grants or call tools.
4. **Evidence first.** The decision (and the execution start) is fsync'd to the hash chain before anything acts. A failed write blocks.
5. **No raw secrets at rest.** Secrets are redacted before provenance storage, proof records, AI calls and API responses of the demo.

## 2. Trust model
| Actor | Trust | Can |
|---|---|---|
| Admin token (human operator) | authenticated | everything incl. approve/deny, reset/benchmark (demo mode only) |
| Agent token | authenticated | inspect, add provenance, request approvals, evaluate, execute with a grant; **not** approve/reset/benchmark |
| Public visitor | none | website, `/api/demo` (fixed scenarios only) |
| Instruction content (skills, READMEs, issues, email, web) | UNTRUSTED/UNVERIFIED unless labelled | becomes provenance; never authority |
| LLM provider | untrusted output | strict-schema advisory text only |

## 3. Provenance rules
* Labels: TRUSTED > UNVERIFIED > UNTRUSTED. Unknown label ⇒ UNVERIFIED.
* Effective trust = min(declared, effective trust of all parents). Unknown parent ⇒ ≤ UNVERIFIED. Trust never increases.
* Ids: server-generated UUID v4; malformed ids are "unknown lineage" (`R13`).
* 50-step working window; effective trust of up to 10,000 recent ids retained after eviction (delayed attacks keep their taint).
* Cycle in lineage ⇒ `LINEAGE_CYCLE_DETECTED` (defence in depth; the API cannot create cycles).
* Trust ≠ authorisation: TRUSTED actions still go through every Gate rule.

## 4. Gate policy (evaluation order is irrelevant; all applicable rules are collected)
| Check | Rule |
|---|---|
| proof chain broken | R11 |
| tool not in {http, file.read} (shell never executes) | R8 |
| SSRF: IP literal in private/loopback/link-local/reserved/multicast, IPv4-mapped, NAT64/6to4/Teredo, numeric host tricks, `localhost`, userinfo | R9 |
| host not on allowlist, non-80/443 port, bad scheme | R1 |
| file path outside workspace, protected name, symlink anywhere on path, NUL | R10 |
| secret-looking data with unapproved destination or tainted lineage / to any destination | R2 / R12 |
| tainted lineage with unapproved destination or commands | R3 |
| unknown/malformed lineage, or non-GET http with no lineage | R13 |
| client "approved" claim not matching the action | R4 |
| command chaining/injection | R5 |
| approval: wrong scope/digest / used / expired / missing for DELETE | R4 / R6 / R14 / R7 |
| redirect hop invalid / > 5 | R16 / R15 |

## 5. Controlled execution
* Grant = `{id, gate_evaluation_id, digest, used, exp}`; TTL `QYRIX_GRANT_TTL_SECONDS` (120 s).
* `/tools/execute` accepts only `{gate_evaluation_id, grant_id}`; extra keys ⇒ `400 CLIENT_PARAMS_NOT_ALLOWED` before lookup.
* Server recomputes the digest of the stored parameters and compares with evaluation and grant digests.
* The grant is consumed and `EXECUTION_STARTED` recorded **before** the adapter runs; result recorded after.
* **HttpAdapter:** re-checks destination against the current allowlist; resolves all A/AAAA answers; any prohibited answer ⇒ refuse
  (mixed answers too); connects to the first validated IP with `Host` and TLS SNI set to the original hostname
  (no second lookup); `follow_redirects=False`; `trust_env=False` (no proxy env); sends no credentials.
* **FileAdapter:** `openat`-style walk with `O_NOFOLLOW|O_DIRECTORY` per component from a root fd, regular files only,
  streaming read capped at 1 MB, redacted output. Refuses to run on platforms without `O_NOFOLLOW`.
* **SandboxAdapter:** demo only; no I/O.

## 6. Approvals
Exact scope = sha256 over `[tool, METHOD, dest, cmd, sha256(data)]`; TTL 900 s; admin-only decision; one decision only.
Consumption happens in the Gate's critical section together with grant creation; a failed grant insertion or proof write
rolls the approval back to unused. Tested: 20 parallel resubmissions ⇒ exactly one grant.

## 7. Proof
Canonical JSON (sorted keys, compact, ASCII) SHA-256 chain; v1 records remain verifiable. Status: FAIL on any broken link,
hash, sequence or format; PARTIAL_UNANCHORED when consistent; PASS reserved for an externally anchored head — **anchoring
is NOT IMPLEMENTED**, so PASS is never returned. Empty bundle ⇒ `EMPTY_PROOF_BUNDLE`. On startup a broken stored chain puts the
gate into degraded mode (blocks everything, refuses execution) until an admin investigates.

**NOT IMPLEMENTED (from master plan §11):** S3 Object Lock / WORM anchoring, signing key isolation and revocation,
clock-anomaly DEGRADED/FAIL/recovery thresholds.

## 8. AI minimisation
Redacted and bounded (4,000 chars) input sent as JSON data under a fixed system prompt, temperature 0, no tools; reply must be
exactly `{label, explanation}`; `-contributor` models and non-HTTPS endpoints refused; provider errors fall back to a labelled
heuristic. Live provider: **NOT VERIFIED** in this environment.

## 9. Web security
Token only in httpOnly, SameSite=Strict cookie (Secure when `QYRIX_COOKIE_SECURE=1`); proxy requires `x-qs-csrf: 1` and same origin
for non-GET; proxy path allowlist (`health`, `sentinel/*`, `tools/execute`); login redirect allowlisted to `/dashboard|/forensic`;
headers `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. **No CSP yet.**

## 10. Public demo isolation
Fresh context per request; fixed fixtures (RFC 2606 example domains); no workspace; sandbox adapter; heuristic-only inspector;
redacted instruction text; per-client (from `x-qyrix-demo-client`, set by the frontend relay) and global rate limits;
kill switch `QYRIX_PUBLIC_DEMO=0`. Tested: production chain unchanged after all scenarios; no DNS or LLM call.

## 11. Known gaps (do not claim)
Single tenant; in-memory provenance/approvals/grants; no network-level egress firewall; TLS SNI with pinned IP not verified live;
DNS has no explicit timeout; broad secret regex; no CSP; no external anchor; no third-party audit or penetration test.
