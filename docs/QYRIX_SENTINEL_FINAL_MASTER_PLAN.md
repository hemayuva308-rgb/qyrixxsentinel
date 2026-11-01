# QYRIX SENTINEL — FINAL PRODUCT, WEBSITE & IMPLEMENTATION MASTER PLAN

**Status:** Locked implementation brief  
**Product:** QYRIX SENTINEL — Trust-to-Execution Guard  
**Goal:** Complete an existing project into a real, multi-user B2B SaaS product with a professional public website, authenticated security platform, working demonstrations, security evidence, and repeatable release process.

---

# 0. NON-NEGOTIABLE PROJECT RULES

This is an **existing-project upgrade**, not a new project.

1. Open and inspect the complete existing repository before editing.
2. Preserve the existing login page, authenticated application theme, working dashboard components, backend behavior, and existing API contracts unless a specification explicitly requires a change.
3. Do not scaffold a second application or duplicate routes/components.
4. Do not delete working files or rewrite working modules without evidence and a migration plan.
5. Implement missing requirements with the smallest safe changes.
6. Maintain a requirement-to-code-to-test traceability matrix.
7. Never fabricate API responses, customers, testimonials, certifications, metrics, benchmark results, AI verification, security evidence, purchases, or proof status.
8. Distinguish `IMPLEMENTED`, `TESTED`, `LIVE VERIFIED`, `ILLUSTRATIVE`, `NOT CONFIGURED`, and `NOT RUN`.
9. Security failures must fail closed. Do not weaken security to make a demo look successful.
10. Never put secrets in source code, browser bundles, screenshots, prompts, logs, audit events, Git history, or public reports.
11. Do not report a test as PASS unless it was actually executed and evidence was retained.
12. When an external service, credential, cloud resource, or payment provider is unavailable, document the dependency and keep the relevant feature disabled or clearly marked as a preview.
13. Do not claim production readiness until the release acceptance checklist is satisfied.
14. Keep the existing dark authenticated product theme that the owner has approved. The public marketing website has a separate light/white visual theme.

# 1. PRODUCT DEFINITION — LOCKED

**Name:** QYRIX SENTINEL  
**Product category:** B2B AI Gateway Security / AI Execution Firewall  
**Product statement:** Secure every AI action before execution.  
**Pitch line:** Detection is not prevention. We enforce from trust to execution.

**Research question:** Can we stop unsafe agent actions before execution even when an instruction looks trusted?

QYRIX SENTINEL is a security layer between AI agents and tool execution. It inspects skill/instruction content, tracks trust provenance, evaluates the requested action with deterministic policies, and records verifiable evidence.

## Four core modules — do not change the scope

1. **Skill Inspector** — inspect skill files, README/configuration content, domains, commands, sensitive references, and suspicious instructions.
2. **Trust Provenance Engine** — label sources TRUSTED / UNTRUSTED / UNVERIFIED, track lineage and transformations, and preserve trust constraints.
3. **Execution Gate** — validate destination + action + data + authentication before a tool executes; deterministic ALLOW/BLOCK; fail closed.
4. **Verifiable Proof** — lineage, rule ID, blocked destination, audit events, hash-chain integrity, and trusted anchoring status.

Meta Llama is an advisory classifier for untrusted instruction classification and evidence explanation. **Deterministic policy is the only authority that can ALLOW or BLOCK. AI must never authorize execution.**

# 2. EXISTING REPOSITORY PRESERVATION

The supplied `qyrix-sentinel-phase1.zip` was inspected. It contains an existing Next.js frontend and Python backend, including:

- Frontend: `frontend/src/app/page.tsx`, `login/page.tsx`, `forensic/page.tsx`, `globals.css`, `layout.tsx`, API proxy/session routes, dashboard components, and `lucide-react`.
- Backend: `backend/app/main.py`, `auth.py`, `provenance.py`, `gateway.py`, `netguard.py`, `core/gate.py`.
- Tests: unit, integration, classifier, hardening, and sentinel test modules.
- Evaluation scripts and docs/security gate material.

The existing Navbar uses a Lucide `ShieldCheck` icon as a temporary brand mark. **No dedicated logo asset, brand folder, favicon, or public image asset was found in the inspected ZIP.** Do not overwrite the existing login/dashboard theme. Create a dedicated QYRIX SENTINEL logo asset and use it consistently in the public website, login, favicon, and authenticated Navbar while retaining the existing layout/theme.

# 3. BRAND & VISUAL SYSTEM

## Public website: LIGHT THEME

Create a white / very light cool-gray public marketing website inspired by the quality and presentation of polished SaaS/creative studio sites such as Wix, Hack4Hack, and Big Studio. Use these as broad inspiration only; do not copy their layouts, branding, text, or assets.

Visual direction:
- White / off-white background, clean premium typography.
- Navy text, electric blue and cyan accents, subtle violet accents where useful.
- Spacious layout, high-quality grid, strong visual hierarchy.
- Fine gradients, soft shadows, glass panels used selectively.
- Large product headlines and clear explanatory diagrams.
- Carefully choreographed scroll storytelling.
- Smooth but restrained motion; no animation that harms readability or accessibility.
- Responsive desktop, tablet, and mobile layouts.
- Respect `prefers-reduced-motion`.
- High contrast and keyboard accessibility.

## Authenticated application: KEEP EXISTING DARK THEME

The existing dark navy/cyan login and dashboard theme is approved by the owner. Preserve it. Do not convert the authenticated application to the public white theme.

## Motion and interaction direction

Use animation intentionally:
- Hero entrance sequence.
- Scroll-triggered reveal for section content.
- Sticky/vertical narrative sections where useful.
- Horizontal pinned storytelling for the four-step workflow.
- Animated flow lines between Inspect → Provenance → Gate → Proof.
- Interactive before-execution Gate demo.
- Slide transitions between demo states.
- Subtle hover and focus transitions on cards and navigation.
- Optional globe/forensic visualization inside the product preview.
- Reduced-motion fallback and mobile-safe behavior.

Do not add excessive animation libraries if CSS/Framer Motion already exists. Inspect installed dependencies first. If Framer Motion or GSAP is missing, decide whether adding it is justified; avoid unnecessary dependency weight. Never fake a live operational visualization.

# 4. LOGO REQUIREMENT

Create a distinct QYRIX SENTINEL brand symbol because the supplied ZIP has no dedicated logo file.

Logo concept:
- Original geometric shield silhouette.
- A subtle embedded “Q” or abstract execution/checkpoint path.
- Communicate protection, trust, and controlled execution.
- Modern enterprise cybersecurity identity.
- Must work as a small favicon and as a larger horizontal lockup.
- Avoid generic clip-art shields and overly complex details.
- Provide vector SVG as the primary scalable logo, plus PNG exports if the toolchain supports them.
- Create variants: icon-only, horizontal logo + QYRIX SENTINEL wordmark, and monochrome.
- Keep source SVG in the repository, e.g. `frontend/public/brand/qyrix-mark.svg`, `qyrix-logo.svg`, and favicon assets.
- Do not use an uneditable generated raster as the only logo source. Recreate the final approved mark as clean SVG.
- Use the same mark on public site and authenticated app; preserve the current dark app styling.

# 5. PUBLIC WEBSITE — ROUTES AND INFORMATION ARCHITECTURE

Build a complete public-facing SaaS marketing website, separate in visual style from the dark authenticated dashboard.

Required routes:
- `/` — Homepage
- `/features` — Four core modules
- `/how-it-works` — Full trust-to-execution flow
- `/pricing` — Proposed business model
- `/security` — Security architecture, boundaries, and evidence approach
- `/forensic-lab` — Public product preview / explanation of Global Forensic Lab
- `/contact` — Contact and enterprise demo request
- `/login` — Existing login flow, unchanged in behavior
- `/dashboard` — Existing authenticated dashboard
- `/forensic` — Existing authenticated Global Forensic Lab

If current route names conflict, preserve existing routes and use redirects/links rather than breaking them.

## Homepage content and storytelling

A visitor should understand what QYRIX SENTINEL does, why it is needed, how it works, and what they can try without reading a long technical document.

### Section 1 — Hero

Headline:
**Secure Every AI Action. Before Execution.**

Subheading:
Trust-aware execution security for AI agents, tools, and enterprise workflows.

Supporting points:
- Inspect risky instructions and skills.
- Track source trust and lineage.
- Enforce deterministic ALLOW/BLOCK before tool execution.
- Verify security evidence.

Primary CTA: `Explore Working Demo`  
Secondary CTA: `View How It Works`  
Header actions: `Login` and `Get Started`

No unsupported customer logos, adoption claims, or certifications.

### Section 2 — The problem

Explain clearly:
AI agents can read instructions and invoke tools. A malicious or manipulated instruction may appear in trusted content, survive transformation, or arrive later. Prompt filtering and monitoring alone do not guarantee that the final tool action is safe.

Use an animated visual:
Agent → Tool request → Security gap → Unsafe action risk.

### Section 3 — QYRIX solution

Show QYRIX SENTINEL as the security checkpoint between the agent and tools.

Visual:
AI Agent → QYRIX SENTINEL Security Layer → Approved Tool / Blocked Request.

Explain that the Gate checks the destination, action, data, and authentication before execution.

### Section 4 — Four core modules

Create interactive cards and a connected visual:
1. Skill Inspector
2. Trust Provenance
3. Execution Gate
4. Verifiable Proof

Each card must explain input, operation, and output. Link to `/features`.

### Section 5 — How it works: scroll-driven narrative

Use a vertical or horizontal interactive story:
1. INSPECT — identify domains, commands, sensitive references, suspicious instructions.
2. ESTABLISH TRUST — label source and preserve lineage.
3. GATE EXECUTION — deterministic policy checks destination + action + data + auth.
4. VERIFY PROOF — audit event, lineage, rule ID, hash-chain verification.

As the user scrolls, highlight each step and animate a flow marker. On mobile, convert to a readable vertical stepper. Do not require horizontal scrolling on small screens.

### Section 6 — WORKING DEMO (important)

Create a real interactive demonstration on the homepage, not just a static mockup.

Demo controls:
- `Run Safe Scenario`
- `Run Direct Attack`
- `Run Transformed Attack`
- `Run Delayed Attack`
- `Reset Demo`

Demo sequence:
- Display sample instruction and source.
- Show Inspector findings.
- Show trust label and lineage.
- Send the scenario to the real demo/sandbox backend Gate if an appropriate safe endpoint exists.
- Show deterministic ALLOW/BLOCK decision and rule ID.
- Show whether an adapter was invoked.
- Show proof/audit verification state.

Security:
- Prefer a dedicated isolated demo mode with synthetic, clearly labeled scenarios.
- Never let a public visitor invoke arbitrary external tools, arbitrary URLs, or real file operations.
- Never expose production credentials or internal admin APIs.
- If a safe backend demo endpoint does not exist, implement a constrained backend demo endpoint with fixed allowlisted fixtures and no outbound network access.
- If the demo is only client-side simulation, label it `SIMULATED DEMO`; never call it a live security test.
- The demo must distinguish actual backend decisions from simulated animation.

Expected showcase:
Unsafe scenario → BLOCKED before execution → proof displayed.
Safe scenario → ALLOWED by policy → safe sandbox task completes.
A blocked attack must not prevent an independent safe task from completing.

### Section 7 — Global Forensic Lab preview

Explain the forensic workspace and show a real product preview or a clearly labeled illustrative visual. The actual authenticated Forensic Lab remains at `/forensic`.

The public preview may show:
- Threat timeline
- Provenance graph
- Gate decisions
- Proof integrity
- Operational health

No fake live risk score, token count, CPU/GPU/TPU split, confidence percentage, or active threat count. If decorative data is used, label it `ILLUSTRATIVE DEMO DATA`.

### Section 8 — Target customers

Describe use cases for:
- AI startups and AI engineering teams
- Enterprise IT and security teams
- FinTech and banking
- Healthcare and regulated organizations
- SaaS businesses deploying AI agents

Do not claim actual customers or production deployments unless verified.

### Section 9 — Pricing preview

Use the proposed plans in Section 6 below. Clearly label pricing as proposed launch pricing until billing and commercial terms are validated.

### Section 10 — FAQ

Answer:
- What does QYRIX SENTINEL protect?
- Does it replace prompt injection detection?
- Does AI decide whether an action is allowed?
- What is a security check?
- What is a verified tool execution?
- Can it run on-premise?
- Does a proof hash automatically mean legal admissibility?
- How can a team request a demo?

### Section 11 — Final CTA and footer

CTA:
**Put a security checkpoint between your AI and every tool.**

Buttons:
- Get Started
- Request Enterprise Demo

Footer links:
Features, How It Works, Pricing, Security, Forensic Lab, Documentation, Contact, Privacy, Terms.

Do not create fake legal pages with invented legal assurances. Create clear draft placeholders for review if final legal text is unavailable.

# 6. BUSINESS MODEL — PROPOSED PRICING

Target customers:
- AI startups — prevent unsafe agent actions.
- Enterprise IT/security teams — control AI access to files and tools.
- Banks and healthcare organizations — traceability and verifiable integrity evidence.
- SaaS and AI product teams — secure tool integrations.

## Proposed plan cards

### FREE — ₹0 / month
- 1,000 security checks per month
- Basic API access
- Basic security dashboard

### PRO — ₹2,999 / month
- Up to 100,000 security checks per month
- Trust provenance
- Execution Gate API
- Audit and proof dashboard
- Usage analytics

### ENTERPRISE — ₹29,999 / month
- Enterprise security controls
- Global Forensic Lab access
- Advanced audit and reporting
- Priority support
- Usage subject to a written fair-use/volume policy; do not advertise unlimited usage without technical and commercial validation.

### ON-PREMISE — starting license ₹5,00,000
- Private deployment
- Customer-controlled infrastructure
- Deployment and integration scope
- Custom support agreement

## Additional revenue streams
- Pay-as-you-go additional security checks.
- Proposed ₹500 per verified forensic report export.
- Enterprise private deployment/license.

## Billing definition — must be clarified in product

Do not treat these as interchangeable:
- Security check request
- Skill inspection
- Gate evaluation
- Verified tool execution
- Blocked request
- Successful execution

Define precisely which event is billable. Prevent duplicate billing with idempotency keys and server-side usage metering.

Do not create fake payment success. If payment integration is not configured, CTA must lead to a contact/demo flow or clearly labeled pricing preview. Subscription status must come from the backend, never from frontend assumptions.

A PDF/hash-chain report is a **verifiable forensic report**, not automatically legally admissible proof. Do not market it as guaranteed legal proof.

# 7. AUTHENTICATED PRODUCT — KEEP CURRENT DARK THEME

Preserve the existing login page and authenticated dashboard styling. The user explicitly likes the current dark theme.

Keep existing login/session behavior unless audit finds a concrete security defect.

Complete and connect:
- Operations Dashboard
- Skill Inspector
- Trust Provenance
- Execution Gate
- Approvals
- Audit / Proof
- Global Forensic Lab
- Settings / account / organization flows required for a multi-user SaaS

Global Forensic Lab should be a first-class authenticated navigation destination. Public homepage can preview it, but the actual lab belongs inside the product after login.

# 8. MULTI-USER SAAS REQUIREMENTS — NOT ADMIN-ONLY

This is intended as a working product for multiple organizations, not an admin-only showcase.

Implement:
- Organization / tenant model.
- User accounts and secure authentication.
- Organization membership and invitations.
- Role-based access control.
- Object ownership and tenant isolation at backend/database level.
- Organization-specific API keys where supported.
- Usage metering by tenant.
- Plan and quota enforcement on the server.
- Audit events associated with organization and actor.
- Safe account onboarding and password/session handling.
- Account settings and member management.
- Tenant-scoped dashboard, approvals, proofs, and inspection records.

Suggested roles (map to the actual security specification; do not weaken it):
- Organization Owner
- Administrator
- Security Reviewer
- Approver
- Auditor
- Integrator / Developer
- Agent identity

Important:
- Do not implement authorization only in the frontend.
- Every backend query and mutation must enforce tenant ownership and role permissions.
- Prevent cross-tenant IDOR and object reference attacks.
- Agent identities cannot approve human requests.
- An approval is not execution.
- If organization isolation, billing, or invitation workflows are not complete, label the product as a controlled beta rather than claiming fully production-ready multi-tenancy.

# 9. FOUR CORE MODULES — FUNCTIONAL REQUIREMENTS

## 9.1 Skill Inspector
- Inspect supported skill/README/configuration text.
- Extract domains, commands, sensitive references, suspicious instructions.
- Preserve source identity and digest where specified.
- Redact secrets before storage/logging/AI.
- Respect role and ownership permissions.
- Enforce size/type limits.
- Never equate an accepted finding with permission to execute.

## 9.2 Trust Provenance
- States: TRUSTED / UNTRUSTED / UNVERIFIED.
- Session starts UNVERIFIED.
- UUID v4 lineage.
- Required 50-step memory/window for delayed instructions.
- Preserve parent/child relationships and transformations.
- Child trust cannot exceed ancestor trust.
- Trust may decrease but cannot be raised by summarization, transformation, or delay.
- Detect cycles with `LINEAGE_CYCLE_DETECTED`.
- Trust and human authorization are separate.

## 9.3 Execution Gate
- Validate destination + action + data + authentication before tool execution.
- Deterministic policy is final authority.
- Default deny and fail-closed.
- Unknown tool/destination, invalid scope/authentication, unsafe input, or policy error => BLOCK.
- All supported tool execution routes must pass through the Gate.
- Block before adapter invocation/network egress.
- Measure invocation and egress independently where possible.

## 9.4 Verifiable Proof
- Record lineage, rule ID, decision, blocked destination, redacted evidence, timestamps.
- Canonical JSON and SHA-256 hash chaining.
- Append-only audit behavior.
- Chain verification.
- Trusted external anchoring if configured.
- States: PASS / FAIL / PARTIAL_UNANCHORED as appropriate.
- Empty proof bundle must not pass.
- Tampered chain must fail.
- Never log raw secrets.

# 10. META LLAMA — STRICT ADVISORY ROLE

- Meta Llama classifies untrusted instructions and provides evidence explanations.
- AI receives only redacted, bounded content.
- AI output uses strict schema validation.
- Record provider/model/latency/status without credentials.
- Timeout/retry/failure handling.
- AI must never authorize execution, modify trust directly, create grants, approve requests, or call tools.
- Deterministic Gate does not depend on AI output to authorize.
- Provider outage must fail safely.
- Clearly distinguish MOCKED, CONFIGURED, LIVE VERIFIED, and NOT VERIFIED.
- Baseten may be an optional model host/provider only if explicitly configured; it is not a replacement for the local coding agent.

# 11. FROZEN API / SECURITY SPECIFICATION

Treat supplied API Specification v1.1 updated, Security Design v1.2, Database Design v1.2, SRS v1.3, and Architecture documents as authoritative. If documents conflict, record the conflict and request a decision; do not silently invent a resolution.

Critical requirements:
- `/api/v1` API base path where specified.
- `POST /tools/execute` accepts `gate_evaluation_id` and `grant_id` only.
- Client-supplied params rejected with 400 `CLIENT_PARAMS_NOT_ALLOWED` before grant lookup, invocation, or network access.
- Server loads immutable params and recomputes digest.
- No public approval-consume endpoint.
- Agent resubmission consumes approval atomically with grant creation in one transaction.
- 20 parallel same-approval requests => exactly one successful grant/consumption.
- Grant insertion failure rolls back approval consumption.
- Do not invent public `CONSUMED` approval status.
- Signing key isolated from DB/Agent/Adapter; revoked key fails.
- Empty proof bundle returns specified validation error; malformed hash fails; tampered chain FAIL; no anchor => PARTIAL_UNANCHORED, never PASS.
- Immutable policy versions; draft creation separate from publish.
- `enableIntegratorInspectionUpload=false`; Reviewer-only upload; Integrator receives 403.
- Validate all A/AAAA DNS results; reject unsafe/mixed answers; pin selected IP; no second DNS lookup for same hop; preserve original hostname for TLS SNI/cert verification.
- Every redirect requires fresh Gate + grant; max 5 redirects; strip credentials cross-host.
- File jail uses safe descriptor-relative access, rejects symlinks for MVP, prevents traversal/races, enforces 1 MB streaming limit.
- Audit append-only hash chain.
- S3 Object Lock Compliance anchoring must follow exact version, retention, timestamp, checksum and signature requirements in Security Design v1.2.
- Clock anomaly behavior follows documented DEGRADED/FAIL/recovery thresholds; acknowledgement alone does not restore integrity.
- All SG-01 to SG-08 controls require retained evidence.

# 12. SECURITY GATES

SG-01 No Direct Egress  
SG-02 Default Deny & Schema Validation  
SG-03 SSRF Defence  
SG-04 Secret Handling & File Jail  
SG-05 Approval Replay & Atomicity  
SG-06 Audit / Proof Integrity  
SG-07 RBAC & Ownership  
SG-08 UI Quality & No Secret Leakage

Each evidence record must include:
- Test ID and preconditions
- Build/version and environment
- Action and expected result
- Actual result
- PASS / FAIL / NOT RUN
- Request/response evidence
- Audit/database/network evidence where relevant
- Artifact location and hash
- Owner and timestamp

PASS only if the test was executed and evidence retained.

# 13. EXACT TEN-CASE BENCHMARK

Required distribution:
- 3 SAFE PASS
- 3 DIRECT BLOCK
- 2 TRANSFORMED BLOCK
- 2 DELAYED BLOCK

Measure:
- Prevention rate
- False-positive rate
- Safe task completion rate
- Latency

Report exact numerator, denominator, conditions, and artifacts. Do not inflate or change the 10-case distribution. Do not fabricate results.

# 14. IMPLEMENTATION PHASES

## Phase 0 — Audit and baseline
- Inspect repository, docs, API contracts, frontend, backend, tests, dependencies, assets, brand.
- Confirm existing logo status and preserve existing login theme.
- Create gap matrix and baseline test report.
- No code changes until baseline is documented.

## Phase 1 — Brand and public website foundation
- Create original logo SVG variants and favicon.
- Add public light-theme layout and navigation without changing authenticated dark theme.
- Implement homepage structure, features, how-it-works, pricing, security, forensic-lab preview, contact.
- Add responsive design and accessible motion foundation.

## Phase 2 — Core backend completion
- Complete Inspector, Provenance, Gate, Proof integration.
- Ensure every supported execution path passes through deterministic Gate.
- Add tests for trust monotonicity, transformation, delay, cycle detection, safe task after block.

## Phase 3 — Security and controlled execution
- Controlled Adapter.
- Exact API contract.
- Approval replay and atomicity.
- SSRF defenses.
- File jail and secret handling.
- RBAC, tenant ownership, session protections.
- SG-01 through SG-05 and SG-07 tests.

## Phase 4 — Proof and anchoring
- Canonical JSON.
- Append-only audit hash chain.
- Offline proof verification.
- External WORM anchor if configured.
- Clock anomaly and recovery behavior.
- SG-06 evidence.

## Phase 5 — Meta Llama and benchmark
- Live provider integration or honest NOT VERIFIED state.
- Advisory-only classification.
- Exact ten benchmark cases.
- Reproducible evaluation command and report.

## Phase 6 — Real interactive homepage demo and Forensic Lab
- Homepage interactive demo backed by safe constrained demo endpoint.
- Attack → BLOCK → proof.
- Safe task → ALLOW → completion.
- Public forensic preview and authenticated full Global Forensic Lab.
- Real API data only; illustrative data clearly labeled.

## Phase 7 — Multi-tenant SaaS and business model
- Organizations, users, invitations, roles, tenant isolation.
- Server-side plans, usage metering, quota enforcement.
- Pricing display and contact flows.
- Payment integration only if credentials/provider are configured and tested.
- Forensic report export only from actual proof data.
- Do not claim fully production-ready billing if not implemented.

## Phase 8 — Integration, security and release
- End-to-end clean-start demo.
- Backend tests, frontend typecheck/build, integration tests.
- SG-01 through SG-08 evidence.
- Exact benchmark report.
- README, architecture, setup, limitations, demo script.
- Git hygiene and secret scan.
- Final GO / NO-GO.

# 15. DEMO ACCEPTANCE FLOW

A repeatable demo must show:

1. Start from documented clean environment.
2. Sign in as an authorized organization user.
3. Inspect a suspicious skill/instruction.
4. Show Inspector evidence and redaction.
5. Show provenance and lineage.
6. Attempt an unsafe action.
7. Gate blocks before adapter/network activity.
8. Show measured invocation/egress evidence.
9. Show rule ID, blocked destination, lineage, and proof.
10. Verify proof integrity.
11. Run an independent safe task.
12. Show safe task completion.
13. If approval is configured, show exact-scope approval and atomic Agent resubmission.
14. Export and independently verify proof.
15. Explain limitations honestly.

The public homepage demo must use a constrained isolated sandbox and must not expose arbitrary external tool execution.

# 16. FINAL ACCEPTANCE CHECKLIST

- [ ] Existing app and login preserved.
- [ ] Dedicated original QYRIX SENTINEL logo SVG + favicon.
- [ ] Public light-theme homepage complete.
- [ ] Scroll storytelling and responsive animations work.
- [ ] Four module explanations complete.
- [ ] Homepage working demo uses safe backend or is explicitly labeled simulated.
- [ ] Public routes load and links work.
- [ ] Existing dark authenticated dashboard preserved.
- [ ] Global Forensic Lab is reachable and functional after login.
- [ ] All four core modules implemented and integrated.
- [ ] Deterministic Gate controls every supported execution path.
- [ ] Meta Llama live verification status is honest.
- [ ] Exact 10-case benchmark report exists.
- [ ] SG-01 through SG-08 evidence retained.
- [ ] Multi-user organization and tenant isolation tested.
- [ ] Pricing is clearly marked proposed until validated.
- [ ] No fake checkout or payment success.
- [ ] Forensic export uses real verified proof.
- [ ] Backend tests pass.
- [ ] Frontend typecheck passes.
- [ ] Production build passes.
- [ ] Clean-start end-to-end demo passes.
- [ ] README and docs match implementation.
- [ ] No secrets in source, build, logs, or Git history.
- [ ] Known limitations and NOT RUN controls documented.

# 17. CODING AGENT WORKING RULE

Start with Phase 0 only.

At the end of each phase, report:
1. Files inspected.
2. Files changed.
3. Features implemented.
4. Exact commands run.
5. Exact test results.
6. Evidence paths.
7. Security gaps remaining.
8. Requirements not implemented.
9. GO / NO-GO for the next phase.

Do not merely generate code snippets in chat. Work in the opened repository, edit the actual files, run tests, fix failures, and preserve the working project. If the environment cannot edit files or run commands, say so clearly and provide exact patch instructions instead of claiming completion.
