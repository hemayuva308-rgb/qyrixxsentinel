export type Verdict = "ALLOW" | "BLOCK";
export type RecordVerdict = Verdict | "EXECUTION_STARTED" | "EXECUTED" | "EXECUTION_FAILED" | "EXECUTION_REFUSED";
export type TrustLabel = "TRUSTED" | "UNTRUSTED" | "UNVERIFIED";
export interface Proof { v?: number; n: number; ts: string; kind?: "gate_decision" | "execution"; gate_evaluation_id?: string | null;
  tool: string | null; method?: string; verdict: RecordVerdict; rule_ids: string[]; blocked_dest?: string | null;
  lineage?: string[]; data?: string | null; ext_calls: number; result_status?: number | null; params_digest?: string; prev: string; hash: string }
export interface Status { api: string; gate: string; provenance: string; proof: string; ai_provider: string; ai_providers: string[];
  pending_approvals: number; decisions: number; blocked: number; allowed: number; external_calls: number; executions?: number;
  avg_latency_ms: number | null; p95_ms: number | null; chain_head: string | null; chain_status?: string; anchor_status: string; role: string;
  demo_mode: boolean; recent: Proof[]; persistence?: "memory" | "postgres" | "down"; anchors?: number }
export interface Anchor { id: string; n: number; head_hash: string; method: string; tsa_url: string; gen_time: string | null; serial: string | null; created_at: string }
export interface AnchorInfo { configured: boolean; problem: string | null; can_verify: boolean; tsa_url: string | null; anchors: Anchor[] }
export interface GateResult { verdict: Verdict; rules: string[]; blocked_dest: string | null; lineage: string[]; latency_ms: number;
  external_calls: number; executed: boolean; exec_status: number | string | null; proof: Proof | null;
  gate_evaluation_id: string; params_digest: string; redirect_hop: number; grant_id: string | null; grant_expires_at: string | null }
export interface ExecResult { executed: boolean; tool: string; gate_evaluation_id: string; result: Record<string, unknown>; adapter: string;
  external_calls: number; proof_start: Proof; proof_result: Proof | null }
export interface Step { id: string; source: string; label: TrustLabel; declared_label: TrustLabel; text: string; parents: string[];
  unknown_parents: string[]; tainted: boolean; ts: string }
export interface Approval { id: string; status: "pending" | "approved" | "denied"; used: boolean; digest: string;
  scope: { tool: string; method: string; dest: string; cmd: string; data_sha256: string | null };
  requested_by: string; ts: string; expires_at: string; decided_by: string | null }
export interface Inspect { domains: string[]; commands: string[]; secrets: string[]; unapproved: string[];
  classification: { label: string; explanation: string; source: string; provider: string; model: string | null; latency_ms: number;
    attempts: { provider: string; ok: boolean; ms: number; error: string | null }[] } }
export interface Verify { valid: boolean; status?: "PASS" | "FAIL" | "PARTIAL_UNANCHORED"; length: number; head: string | null; broken_at?: number | null;
  anchor_status?: string; degraded?: boolean; simulated?: boolean;
  anchored_through?: number | null; anchor_detail?: string | null; anchors?: number }
export interface BenchCase { name: string; type: string; expected?: string; verdict: Verdict; rules: string[]; ms: number; ok: boolean; lineage: string[]; external_calls_delta?: number }
export interface Bench { cases: BenchCase[]; metrics: { prevention: number; false_positive: number; task_completion: number; avg_latency_ms: number; max_latency_ms?: number };
  counts?: { safe: number; attacks: number; attacks_blocked: number; safe_allowed: number; safe_blocked: number };
  hypotheses: { q: string; holds: boolean }[] }
