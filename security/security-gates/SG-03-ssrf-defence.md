# SG-03 SSRF Defence

**Status: PARTIAL**  (TESTED = all listed checks executed and passing; PARTIAL = listed checks pass but part of the control is missing)

## Control
Internal, reserved and spoofed destinations are blocked at evaluation; at execution every DNS answer is validated and the IP is pinned.

## Evidence records
Build: branch `claude/hopeful-franklin-5ggx72`, backend v1.2.0 · Environment: Linux, Python 3.13, pytest 8 (cloud container) ·
Owner: QYRIX SENTINEL engineering · Timestamp: 2026-11-01 (UTC) ·
Artifact: `evidence/pytest-junit.xml` (SHA-256 recorded in `docs/IMPLEMENTATION_REPORT.md`). Preconditions: `backend/tests/conftest.py`
(test tokens, temporary chain file and workspace, demo/eval mode on).

| Test ID | Action | Test / artifact | Expected vs actual | Result |
|---|---|---|---|---|
| SG03-T1 | 10 SSRF payloads (loopback, metadata, userinfo, numeric, IPv6-mapped, NAT64, private) | `test_hardening.py::test_ssrf_destinations_blocked` | as expected | PASS |
| SG03-T2 | private or mixed DNS answers refused, no request made | `test_hardening.py::test_dns_answer_in_private_range_blocks_and_makes_no_request` | as expected | PASS |
| SG03-T3 | pinned IP, Host + SNI = original hostname, redirects not followed | `test_hardening.py::test_execute_resolves_validates_pins_and_records_before_request` | as expected | PASS |
| SG03-T4 | redirects need fresh gate decision; max 5 hops | `test_v12_controls.py::test_redirect_is_not_followed_and_needs_fresh_gate` | as expected | PASS |

## Open items (not claimed)
- TLS certificate/SNI behaviour of the pinned connection against a live host: NOT RUN.
- DNS resolution has no explicit timeout.
