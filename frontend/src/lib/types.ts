export type Verdict = "ALLOW" | "BLOCK";
export interface Proof { n: number; ts: string; tool: string; verdict: Verdict; rule_ids: string[]; blocked_dest: string | null;
  lineage: string[]; data: string | null; ext_calls: number; prev: string; hash: string }
export interface Status { api: string; gate: string; provenance: string; proof: string; ai_provider: string; ai_providers: string[];
  pending_approvals: number; decisions: number; blocked: number; allowed: number; external_calls: number;
  avg_latency_ms: number | null; p95_ms: number | null; chain_head: string | null; anchor_status: string; role: string;
  demo_mode: boolean; recent: Proof[] }
export interface GateResult { verdict: Verdict; rules: string[]; blocked_dest: string | null; lineage: string[]; latency_ms: number;
  external_calls: number; executed: boolean; exec_status: number | string | null; proof: Proof | null }
export interface Step { id: number; source: string; label: "approved" | "untrusted" | "unverified"; text: string; parents: number[]; tainted: boolean; ts: string }
export interface Approval { id: string; status: "pending" | "approved" | "denied"; used: boolean; digest: string;
  scope: { tool: string; method: string; dest: string; cmd: string; data_sha256: string | null };
  requested_by: string; ts: string; expires_at: string; decided_by: string | null }
export interface Inspect { domains: string[]; commands: string[]; secrets: string[]; unapproved: string[];
  classification: { label: string; explanation: string; source: string; provider: string; model: string | null; latency_ms: number;
    attempts: { provider: string; ok: boolean; ms: number; error: string | null }[] } }
export interface Verify { valid: boolean; length: number; head: string | null; broken_at?: number; anchor_status?: string; degraded?: boolean; simulated?: boolean }
export interface BenchCase { name: string; type: string; verdict: Verdict; rules: string[]; ms: number; ok: boolean; lineage: string[] }
export interface Bench { cases: BenchCase[]; metrics: { prevention: number; false_positive: number; task_completion: number; avg_latency_ms: number };
  hypotheses: { q: string; holds: boolean }[] }
