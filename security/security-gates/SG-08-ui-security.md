# SG-08 UI Quality & No Secret Leakage

**Status: PARTIAL**  (TESTED = all listed checks executed and passing; PARTIAL = listed checks pass but part of the control is missing)

## Control
Token never reaches client JavaScript; CSRF-protected same-origin proxy; no secrets in the browser bundle; honest UI states.

## Evidence records
Build: branch `claude/hopeful-franklin-5ggx72`, backend v1.2.0 · Environment: Linux, Python 3.13, pytest 8, Chromium 153, Docker 29 (cloud container) ·
Owner: QYRIX SENTINEL engineering · Timestamp: 2026-11-01 (UTC) ·
Artifact: `evidence/pytest-junit.xml` (SHA-256 recorded in `docs/IMPLEMENTATION_REPORT.md`). Preconditions: `backend/tests/conftest.py`
(test tokens, temporary chain file and workspace, demo/eval mode on).

| Test ID | Action | Test / artifact | Expected vs actual | Result |
|---|---|---|---|---|
| SG08-T1 | production bundle grep for tokens/keys/fixture secrets: no match | `evidence/secret-scan.txt` | as expected | PASS |
| SG08-T2 | all public routes 200, no console errors, no horizontal overflow at 390/820/1440 px | `evidence/route-sweep.txt / authenticated-flow.txt` | as expected | PASS |
| SG08-T3 | authenticated browser flow: login -> evaluate -> execute with grant -> benchmark, no console errors | `evidence/route-sweep.txt / authenticated-flow.txt` | as expected | PASS |
| SG08-T4 | CSP present and enforced: in-document eval blocked, external fetch/img blocked + reported, no CSP errors on 33 page loads | `evidence/csp-check.txt`, `evidence/route-sweep.txt` | as expected | PASS |
| SG08-T5 | public demo relay accepts only {"scenario": id}; extra fields/arrays/unknown ids -> 422 | `evidence/docker-compose-validation.txt` | as expected | PASS |

## Open items (not claimed)
- CSP still allows `'unsafe-inline'` scripts (Next.js inline bootstrap; nonces not used).
- No automated accessibility (axe) suite; manual keyboard/contrast review only.
