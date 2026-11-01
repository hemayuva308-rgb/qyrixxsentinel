# QYRIX SENTINEL — Implementation Roadmap

Phases follow the approved implementation plan. Status reflects this repository on branch `claude/hopeful-franklin-5ggx72`.

| Phase | Scope | Status |
|---|---|---|
| 1 Repository & foundation | master plan in docs, route structure (`/` public, `/dashboard`), brand assets, design tokens, `.env.example` | **DONE** |
| 2 Public website | homepage (13 sections), features, how-it-works, pricing, security, forensic-lab, contact, docs, draft legal; responsive + motion | **DONE** |
| 3 Core security modules | UUID provenance + monotone trust + cycles; grant-only execution; controlled adapter; redirect re-gating; descriptor-relative file jail; canonical proof + bundle verification | **DONE** (see gaps below) |
| 4 Safe demo & forensic experience | `/api/v1/demo/run`, fixed scenarios, isolated context, backend-driven UI, browser re-verification, authenticated forensic insights from real chain | **DONE** |
| 5 SaaS & advanced | organisations, users, RBAC, tenant isolation, metering, quotas, external anchoring | **NOT STARTED** — schema drafted in DATABASE_DESIGN.md |
| 6 Meta Llama | advisory classifier integrated with strict schema; failure paths tested on real sockets; live verification needs a key and network access | **PARTIAL** — NOT LIVE VERIFIED |
| 7a Hackathon close-out | CSP, internal-only backend network, strict demo relay, judging workflow script, 3-minute demo script, submission checklist | **DONE** |
| 7 Final validation | tests, build, benchmark, route sweeps, demo isolation, secret scan | **DONE for this scope** — see IMPLEMENTATION_REPORT.md |

## Next steps, in order
1. PostgreSQL persistence for provenance, approvals, evaluations, grants, proof records (DATABASE_DESIGN.md §2).
2. Organisations, memberships, agent identities, per-org API keys; tenant filter on every query + RLS; IDOR test suite (SG-07).
3. Usage metering with idempotency keys; plan quotas enforced in the Gate path.
4. External anchoring of the chain head (S3 Object Lock, compliance mode) with signed checkpoints; PASS only when anchored (SG-06).
5. Per-destination network allowlist for the opt-in egress mode (default deployment already has no egress) and a live TLS SNI test (SG-01, SG-03).
6. Nonce-based CSP (remove `'unsafe-inline'` scripts) and an automated accessibility suite (SG-08).
7. Live Meta Llama verification with `scripts/verify_meta.py --record` on a machine that holds the key.
8. Policy versioning (immutable versions, draft/publish separation).
