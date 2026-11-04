// Single source of truth for the homepage copy. Every statement must match the current implementation (docs/ and the
// repository state). Status words are deliberately conservative; nothing here is a security certification.
import {
  Bot, Cable, EyeOff, FileCheck2, GitBranch, Globe, KeyRound, Network, Radar, Route, Scale, ScanSearch, ShieldCheck,
  Waypoints, Workflow, type LucideIcon,
} from "lucide-react";

export const NAV_LINKS = [
  { href: "/#platform", label: "Platform" },
  { href: "/#architecture", label: "Architecture" },
  { href: "/#integrations", label: "Integrations" },
  { href: "/security", label: "Security" },
  { href: "/docs", label: "Documentation" },
  { href: "/#why", label: "About" },          // no About page exists: this is the "Built around the execution boundary" section
] as const;

export const DEMO_HREF = "/contact?topic=enterprise-demo";   // real route; the form copies/emails a request, it books nothing

export const HERO_STEPS = [
  { icon: Bot, t: "Agent Request", d: "A tool action is requested" },
  { icon: Scale, t: "Gate Evaluation", d: "Deterministic policy decides" },
  { icon: KeyRound, t: "Scoped Grant", d: "Short-lived, single-use" },
  { icon: Route, t: "Controlled Execution", d: "Via the protected path" },
  { icon: FileCheck2, t: "Evidence", d: "Recorded for verification" },
] as const;

export const PROBLEMS = [
  { icon: Waypoints, t: "Uncontrolled Tool Access", d: "Agents may attempt actions beyond their intended scope, and a connected tool is often a standing permission." },
  { icon: EyeOff, t: "Hidden Execution Paths", d: "Direct network access can bypass controls that only the application cooperates with." },
  { icon: ScanSearch, t: "Insufficient Evidence", d: "Logs alone do not always prove that an action was actually prevented." },
] as const;

export const PLATFORM = [
  { icon: GitBranch, t: "Trust & Provenance", d: "Evaluate the context and trust information associated with a protected action." },
  { icon: Scale, t: "Deterministic Gate", d: "Evaluate whether a requested action is permitted under defined policy. The Gate is the authorization authority; AI output is advisory." },
  { icon: KeyRound, t: "Scoped Grants", d: "Use short-lived, task-bound and single-use grants for protected execution." },
  { icon: Network, t: "Controlled Egress", d: "Route supported outbound execution through a controlled proxy path." },
  { icon: FileCheck2, t: "Verifiable Evidence", d: "Collect and verify evidence about authorization and execution." },
] as const;

export type ArchNode = { id: string; icon: LucideIcon; label: string; sub: string; text: string; limit: string; badge?: string };
export const ARCH_FLOW: ArchNode[] = [
  { id: "agent", icon: Bot, label: "AI Agent / Workflow", sub: "Requests an action",
    text: "An AI agent or automation workflow requests a protected action.",
    limit: "Sentinel does not run or replace the agent or the workflow engine." },
  { id: "adapter", icon: Cable, label: "Qyrix Adapter", sub: "Translates the request",
    text: "A supported integration translates the tool request into the Sentinel execution path. Today that means the MCP proxies and the n8n custom HTTP node (prototypes).",
    limit: "Only supported integrations are covered. An agent that can reach a tool directly is not protected unless the network blocks that path." },
  { id: "gate", icon: Scale, label: "Gate Evaluation", sub: "Decides ALLOW or BLOCK", badge: "Authorization authority",
    text: "Deterministic policy evaluates the protected action. The Gate is the only authorization authority; unknown or unmatched actions are blocked.",
    limit: "Decisions follow the configured policy. AI classification is advisory and is never read by the authorization path." },
  { id: "grant", icon: KeyRound, label: "Scoped Grant", sub: "Short-lived, single-use",
    text: "An allowed action receives a scoped, expiring authorization grant, bound to the exact request, the calling credential and the task context.",
    limit: "A grant authorizes one specific request. It is not a general permission to use a tool." },
  { id: "egress", icon: Network, label: "Controlled Egress Proxy", sub: "The protected network path",
    text: "The request uses the protected network path. The proxy opens a tunnel only for an execution that has a recorded, redeemed grant.",
    limit: "Enforcement is only as strong as the deployed network topology: direct internet access must be removed for the protected workload." },
  { id: "tool", icon: Globe, label: "External Tool / API", sub: "The approved destination",
    text: "The approved destination or service receives the request.",
    limit: "Sentinel validates the destination against policy; it does not vouch for what the destination does with the request." },
];
export const ARCH_OBSERVER: ArchNode = {
  id: "observer", icon: Radar, label: "Observer", sub: "Evidence & verification layer", badge: "Does not authorize",
  text: "A separate service that receives and verifies evidence associated with the protected execution, such as signed Gate claims, adapter reports and observations of the controlled egress path.",
  limit: "The Observer never makes or changes an authorization decision. Missing evidence stays INCONCLUSIVE.",
};

export const STEPS = [
  { n: "01", t: "Request", d: "An agent requests a tool action." },
  { n: "02", t: "Evaluate", d: "Sentinel evaluates the action against deterministic policy." },
  { n: "03", t: "Authorize & Execute", d: "A scoped grant is redeemed and the supported request uses controlled egress." },
  { n: "04", t: "Verify", d: "Evidence is collected and assessed." },
] as const;

export const OUTCOMES = [
  { kind: "allow", t: "Allowed request", d: "The request matches policy. A scoped grant is issued and redeemed, the request goes out through controlled egress, and evidence is recorded for assessment.", tag: "ALLOW" },
  { kind: "block", t: "Denied request", d: "The destination is not approved. The Gate returns BLOCK with a rule identifier (for example R1_DEST_NOT_APPROVED). No grant is issued and nothing is sent.", tag: "BLOCK" },
  { kind: "inconclusive", t: "Missing evidence", d: "Evidence is missing or incomplete. The outcome stays INCONCLUSIVE; it is never reported as a verified block.", tag: "INCONCLUSIVE" },
] as const;

export type CapStatus = "Implemented" | "Prototype" | "In validation" | "Opt-in";
export const CAPABILITIES: { icon: LucideIcon; t: string; d: string; s: CapStatus }[] = [
  { icon: ShieldCheck, t: "Default-deny authorization", d: "Unknown or unmatched actions are blocked.", s: "Implemented" },
  { icon: Scale, t: "Fail-closed protected execution", d: "If the Gate or a required component is unavailable, the protected action does not run.", s: "Implemented" },
  { icon: KeyRound, t: "Scoped and expiring grants", d: "Grants are short-lived (120 s by default).", s: "Implemented" },
  { icon: KeyRound, t: "Single-use grant redemption", d: "A grant can be redeemed once; a replay is refused.", s: "Implemented" },
  { icon: Cable, t: "Exact request-parameter binding", d: "A grant is bound to a digest of the exact request that was evaluated.", s: "Implemented" },
  { icon: Globe, t: "Destination validation", d: "Approved-destination and private-address checks reduce SSRF exposure; they are not a complete defence.", s: "Implemented" },
  { icon: Network, t: "Controlled outbound execution", d: "Supported paths use a controlled proxy. Strength depends on network isolation.", s: "Prototype" },
  { icon: Workflow, t: "Tenant-aware context", d: "Separate contexts per tenant when multi-tenancy is enabled.", s: "Opt-in" },
  { icon: GitBranch, t: "Correlation & execution identifiers", d: "Requests carry correlation and Gate-issued execution IDs end to end.", s: "Implemented" },
  { icon: EyeOff, t: "Secret-safe evidence and logging", d: "Secrets are redacted before storage. Detection is pattern-based and not exhaustive.", s: "Implemented" },
  { icon: Radar, t: "Replay resistance", d: "Replayed grants and reused execution IDs are refused.", s: "Implemented" },
  { icon: FileCheck2, t: "Evidence verification", d: "Hash-linked records can be verified offline; Observer verification is under validation.", s: "In validation" },
];

export const INTEGRATIONS = {
  mcp: {
    name: "MCP", mark: "MCP", status: "Implemented prototype", sub: "Integration under validation", tone: "amber",
    text: "Protect supported Model Context Protocol tool interactions through Qyrix Sentinel's adapter and authorization path.",
    tags: ["MCP stdio", "Streamable HTTP"],
    points: ["Tool calls are evaluated by the Gate before they are forwarded", "Only allow-listed tool arguments are accepted, bound to the evaluated request", "A grant is redeemed before the upstream request is made", "If the Gate is unavailable, the call is refused"],
    limits: "An agent that can reach the MCP server directly bypasses the proxy; network isolation is required.",
  },
  n8n: {
    name: "n8n", mark: "n8n", status: "Controlled prototype", sub: "Security validation ongoing", tone: "amber",
    text: "Route supported n8n HTTP actions through the Qyrix Sentinel custom HTTP node.",
    tags: ["Custom Qyrix HTTP node"],
    points: ["Gate evaluation", "Grant redemption", "Controlled proxy execution", "GET and HEAD over HTTPS only"],
    limits: "Covers this node only. Other n8n nodes are not protected, n8n Cloud is not supported, and network isolation is required to prevent direct bypass. Self-hosted n8n 2.46.5 only.",
  },
} as const;

export const EVIDENCE = [
  { id: "E1", t: "Adapter-reported evidence", d: "Evidence reported by the integration or adapter itself. Useful for troubleshooting and audit trails, but self-reported.", tone: "slate" },
  { id: "E3", t: "Independently observed enforcement", d: "Evidence supported by independent observation of the enforcement path, from sensors outside the adapter.", tone: "blue" },
  { id: "INCONCLUSIVE", t: "Missing or insufficient", d: "Evidence is missing or insufficient to make a verified enforcement claim. This is the default, not a failure.", tone: "amber" },
] as const;
export const EVIDENCE_ROWS = [
  { k: "Reported by", e1: "The adapter or integration", e3: "A separate observer on the controlled path" },
  { k: "Independent of the adapter", e1: "No", e3: "Yes" },
  { k: "Can support", e1: "Audit trail and troubleshooting", e3: "An enforcement claim, when the evidence is complete" },
  { k: "Cannot show", e1: "That an action was actually prevented", e3: "Anything outside the observed path or time window" },
] as const;

export const USE_CASES = [
  { icon: Bot, t: "AI Agent Tool Security", d: "Control which tools and destinations an agent may use through supported adapters.", note: "Supported adapters only" },
  { icon: Cable, t: "MCP Tool Access Control", d: "Evaluate MCP tool calls before they reach the upstream server.", note: "Prototype" },
  { icon: Workflow, t: "Automation Workflow Protection", d: "Route n8n HTTP requests through a Gate-authorized node.", note: "Controlled prototype; other engines not covered" },
  { icon: ScanSearch, t: "Developer Tool Execution Security", d: "Gate-evaluate HTTP and file-read tool actions.", note: "Current tool types only" },
  { icon: Globe, t: "Controlled API Access", d: "Limit outbound calls to approved destinations with scoped, single-use grants.", note: "Where egress is controlled" },
  { icon: FileCheck2, t: "Enterprise AI Governance", d: "Keep an evidence trail with correlation IDs and verifiable records.", note: "Not a compliance certification" },
] as const;

export const WHY_ROWS = [
  { k: "Authorization", a: "Permission granted when a tool is connected", b: "Evaluated before each protected execution" },
  { k: "Permission scope", a: "Broad, standing tool permission", b: "A scoped, expiring, single-use grant" },
  { k: "Network", a: "Relies on the application following convention", b: "A controlled egress path, where the network is isolated" },
  { k: "Evidence", a: "Success logs", b: "Verifiable evidence, and INCONCLUSIVE when it is missing" },
] as const;

export const STATUS = [
  { t: "Core Gate and Observer foundation", s: "Implemented", d: "Ongoing validation." },
  { t: "MCP integration", s: "Prototype", d: "Implemented; further regression review required." },
  { t: "n8n integration", s: "Prototype", d: "Controlled prototype; remediation and runtime validation ongoing." },
  { t: "Production readiness", s: "Not certified", d: "Not yet independently certified." },
] as const;

export const FAQ = [
  { q: "What is Qyrix Sentinel?", a: "A Trust-to-Execution Guard. It places deterministic authorization, scoped grants, controlled egress and verifiable evidence between AI agent intent and external tool execution, for the integrations it supports." },
  { q: "How does the Gate work?", a: "The Gate evaluates a requested action (destination, method, data and provenance) against deterministic, default-deny policy. It returns ALLOW with a scoped grant, or BLOCK with rule identifiers. AI classification is advisory only and never decides." },
  { q: "What is a scoped grant?", a: "A short-lived authorization issued only for an allowed action. In the current protected flow it is single-use and bound to the exact request, the calling credential, the task context and the policy version. The default lifetime is 120 seconds." },
  { q: "Does Sentinel replace an AI agent or workflow engine?", a: "No. Your agent or workflow engine keeps doing its job. Sentinel sits on the path between it and the tools it calls." },
  { q: "Does it support MCP?", a: "There are prototype proxies for MCP over stdio and Streamable HTTP. They are implemented but still under validation, and they only protect traffic that goes through them." },
  { q: "Does it support n8n?", a: "Through a custom Qyrix HTTP node, as a controlled prototype for self-hosted n8n 2.46.5. It sends GET and HEAD requests over HTTPS through the Gate and the controlled proxy. n8n Cloud is not supported." },
  { q: "Does Sentinel protect every n8n node?", a: "No. Only requests made through the Qyrix node are covered. Other nodes can reach the network unless the deployment isolates it, so network isolation is required. Excluding nodes helps but is not a guarantee." },
  { q: "What is the role of the Observer?", a: "The Observer is a separate service that receives and verifies evidence, including signed Gate claims and observations of the controlled egress path. It never makes authorization decisions." },
  { q: "What is the difference between E1 and E3?", a: "E1 is evidence reported by the adapter itself. E3 is evidence from independent observation of the enforcement path. E1 is never presented as E3, and when evidence is missing the outcome is INCONCLUSIVE." },
  { q: "Is Qyrix Sentinel production-ready?", a: "No. It is a prototype-stage platform. Known findings are tracked openly in the documentation, and the system has not been independently certified." },
] as const;

export const FOOTER_COLS = [
  { h: "Platform", l: [["/#platform", "Platform overview"], ["/#architecture", "Architecture"], ["/#integrations", "Integrations"], ["/#evidence", "Evidence"]] },
  { h: "Resources", l: [["/docs", "Documentation"], ["/security", "Security"], ["/how-it-works", "How it works"], ["/forensic-lab", "Forensic Lab"], ["/pricing", "Pricing"]] },
  { h: "Company", l: [["/contact", "Contact"], [DEMO_HREF, "Request a demo"], ["/privacy", "Privacy"], ["/terms", "Terms"], ["/login", "Operator login"]] },
] as const;
