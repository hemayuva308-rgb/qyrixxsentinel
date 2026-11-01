// Single source of truth for public-site copy. Every claim here must match the implementation (see docs/).

export const MODULES = [
  { id: "inspector", n: "01", name: "Skill Inspector",
    input: "Skill files, README / config text, tool instructions",
    op: "Normalises obfuscation (base64, hxxp, [.], percent-encoding), extracts domains, commands and secret references, redacts secrets.",
    out: "Structured findings + advisory classification (never an authorisation)" },
  { id: "provenance", n: "02", name: "Trust Provenance",
    input: "Every instruction source and every derived step",
    op: "Labels TRUSTED / UNTRUSTED / UNVERIFIED with UUID v4 lineage. A child's trust is the minimum of its ancestors; it can never be raised. 50-step delayed window, cycle detection.",
    out: "Effective trust + full lineage for each proposed action" },
  { id: "gate", n: "03", name: "Execution Gate",
    input: "Proposed tool call: destination, action, data, auth, lineage",
    op: "Deterministic default-deny policy. SSRF, allowlist, secret-exfiltration, injection, approval-scope and provenance rules. Fails closed.",
    out: "ALLOW + single-use grant, or BLOCK with rule IDs, recorded before anything runs" },
  { id: "proof", n: "04", name: "Verifiable Proof",
    input: "Every decision and execution event",
    op: "Canonical JSON records, SHA-256 hash-linked, append-only, no raw secrets. Offline verification of exported bundles.",
    out: "PASS / FAIL / PARTIAL_UNANCHORED verification result" },
] as const;

export const WORKFLOW = [
  { k: "INSPECT", t: "Inspect what the agent read", d: "Domains, commands, sensitive references and suspicious instructions are extracted from skills, READMEs and configs, including obfuscated forms. Secrets are redacted before storage or any AI call." },
  { k: "ESTABLISH TRUST", t: "Label the source and keep the lineage", d: "Every source is TRUSTED, UNTRUSTED or UNVERIFIED. Derived steps inherit the lowest trust of their ancestors, so a summary of an untrusted email stays untrusted, even 20 steps later." },
  { k: "GATE EXECUTION", t: "Decide before the tool runs", d: "The Gate checks destination + action + data + authentication + provenance with deterministic policy. Unknown means BLOCK. ALLOW issues a short-lived, single-use grant bound to the exact parameters." },
  { k: "VERIFY PROOF", t: "Keep evidence anyone can check", d: "Each decision is written to a hash-linked chain before execution, with rule IDs, lineage and redacted data. Export the bundle and verify it offline." },
] as const;

export const CUSTOMERS = [
  { t: "AI startups & AI engineering teams", d: "Ship agents that call real tools without trusting every README, issue or web page they read.", big: true },
  { t: "Enterprise IT & security teams", d: "Put one enforceable control point in front of agent access to files, APIs and internal tools." },
  { t: "FinTech & banking", d: "Block credential and data exfiltration paths before they execute; keep a verifiable decision record." },
  { t: "Healthcare & regulated organisations", d: "Show which source led to which action, with lineage and tamper-evident evidence." },
  { t: "SaaS businesses deploying AI agents", d: "Secure tool integrations offered to customers, with scoped, single-use approvals for high-impact actions." },
] as const;

export const PLANS = [
  { id: "free", name: "Free", price: "₹0", per: "/ month", blurb: "Evaluate the Gate on real workloads.",
    f: ["1,000 security checks / month", "Basic API access", "Basic security dashboard"], cta: "Request access" },
  { id: "pro", name: "Pro", price: "₹2,999", per: "/ month", blurb: "For teams running agents in production.", featured: true,
    f: ["Up to 100,000 security checks / month", "Trust provenance", "Execution Gate API", "Audit & proof dashboard", "Usage analytics"], cta: "Talk to us" },
  { id: "enterprise", name: "Enterprise", price: "₹29,999", per: "/ month", blurb: "Controls, forensics and support.",
    f: ["Enterprise security controls", "Global Forensic Lab access", "Advanced audit & reporting", "Priority support", "Volume under a written fair-use policy"], cta: "Request enterprise demo" },
  { id: "onprem", name: "On-premise", price: "₹5,00,000", per: "starting licence", blurb: "Private deployment on your infrastructure.",
    f: ["Private deployment", "Customer-controlled infrastructure", "Deployment & integration scope", "Custom support agreement"], cta: "Contact sales" },
] as const;

export const FAQ = [
  { q: "What does QYRIX SENTINEL protect?", a: "The moment an AI agent turns an instruction into a tool action. It sits between the agent and its tools (HTTP calls and file reads in this build) and decides ALLOW or BLOCK before anything executes." },
  { q: "Does it replace prompt-injection detection?", a: "No. Detection tools are useful signals. QYRIX SENTINEL adds enforcement at execution time: even if a malicious instruction is not detected, an unapproved destination, a secret leaving through tainted lineage, or an out-of-scope action is still blocked." },
  { q: "Does AI decide whether an action is allowed?", a: "Never. A Meta Llama model can classify untrusted text and explain evidence, but it is advisory only. The Gate has no code path that reads the classification; deterministic policy is the only authority." },
  { q: "What is a security check?", a: "One Gate evaluation of a proposed tool action (ALLOW or BLOCK). It is the proposed billable unit. Inspections, approvals and proof verification are not counted as checks." },
  { q: "What is a verified tool execution?", a: "An execution performed through POST /api/v1/tools/execute with a gate_evaluation_id and a single-use grant. The server reloads the stored parameters, re-checks their digest and records the start before the adapter runs." },
  { q: "Can it run on-premise?", a: "The product runs as two containers (API and web) via Docker Compose, with the API not exposed to the host. Private deployment is offered as an on-premise licence; scope is agreed per customer." },
  { q: "Does a proof hash mean legal admissibility?", a: "No. The hash chain is tamper-evident and can be verified offline, which makes it strong technical evidence. It is not automatically legally admissible. External anchoring is not implemented yet, so verification reports PARTIAL_UNANCHORED rather than PASS." },
  { q: "How can my team request a demo?", a: "Use the contact page and choose “Enterprise demo”. You can also run the public sandbox demo on the homepage right now; it uses the real Gate on fixed scenarios." },
] as const;
