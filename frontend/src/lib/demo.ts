// Response contract of POST /api/demo -> backend POST /api/v1/demo/run (isolated sandbox, fixed scenarios).
import type { GateResult, Proof, Step, Verify } from "./types";

export type ScenarioId = "safe" | "direct" | "transformed" | "delayed";
export interface DemoExecution { adapter_invoked: boolean; adapter: string; result: Record<string, unknown> | null; refused: string | null; proof_start?: number; proof_result?: number | null }
export interface DemoRun {
  mode: "SIMULATED_DEMO"; isolated: boolean; notice: string;
  scenario: { id: ScenarioId; title: string; category: string; expected: "ALLOW" | "BLOCK"; summary: string };
  instruction: { source: string; declared_label: string; text: string };
  action: { tool: string; method: string; dest: string; data?: string };
  inspection: { domains: string[]; commands: string[]; secrets: string[]; unapproved: string[];
    classification: { label: string; explanation: string; provider: string; advisory_only: boolean; note: string } };
  provenance: { steps: Step[]; memory_limit: number; lineage_requested: string[] };
  gate: GateResult; execution: DemoExecution;
  followup: { gate: GateResult; execution: DemoExecution } | null;
  proof: { chain: Proof[]; verify: Verify };
  external_calls: number; matched_expectation: boolean; elapsed_ms: number;
}

export const SCENARIOS: { id: ScenarioId; label: string; short: string }[] = [
  { id: "safe", label: "Run Safe Scenario", short: "Safe" },
  { id: "direct", label: "Run Direct Attack", short: "Direct" },
  { id: "transformed", label: "Run Transformed Attack", short: "Transformed" },
  { id: "delayed", label: "Run Delayed Attack", short: "Delayed" },
];

export async function runDemo(scenario: ScenarioId, signal?: AbortSignal): Promise<DemoRun> {
  const r = await fetch("/api/demo", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ scenario }), cache: "no-store", signal });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(typeof j?.detail === "string" ? j.detail : `Demo backend error (HTTP ${r.status})`);
  if (j?.mode !== "SIMULATED_DEMO") throw new Error("Unexpected demo response");
  return j as DemoRun;
}

/** Steps on the requested lineage (ancestors included), in creation order. */
export function lineageSteps(run: DemoRun): Step[] {
  const ids = new Set(run.gate.lineage.map((x) => x.split(":")[0]));
  return run.provenance.steps.filter((s) => ids.has(s.id));
}
