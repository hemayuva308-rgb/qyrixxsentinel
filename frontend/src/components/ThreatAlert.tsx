"use client";
import { ShieldAlert } from "lucide-react";
import type { Proof } from "@/lib/types";
import { RULE_HELP } from "@/lib/rules";
import { Badge, Card, Empty, Mono } from "./ui";

// Built only from the latest real BLOCK in the proof chain. No data => empty state (never invented).
export default function ThreatAlert({ recent }: { recent: Proof[] | undefined }) {
  const p = recent?.find((x) => x.verdict === "BLOCK");
  if (!p) return <Card title="LATEST BLOCKED ACTION"><Empty text="No blocked actions recorded" /></Card>;
  const crit = p.rule_ids.some((r) => ["R2_SECRET_EXFIL", "R9_SSRF_BLOCKED", "R12_SECRET_TO_EXTERNAL", "R11_PROOF_DEGRADED"].includes(r));
  return (
    <section role="alert" className="rounded-2xl border border-crit/60 bg-crit/10 p-4 shadow-[0_0_30px_-10px_rgba(255,59,92,.6)]">
      <div className="flex items-center gap-2 text-crit"><ShieldAlert className="h-5 w-5" /><h2 className="text-sm font-semibold tracking-[.18em]">LATEST BLOCKED ACTION</h2>
        <Badge t={crit ? "crit" : "warn"}>{crit ? "HIGH SEVERITY" : "BLOCKED"}</Badge></div>
      <div className="mt-2 grid gap-2 text-sm md:grid-cols-2">
        <div>Tool: <Mono>{p.tool}</Mono><br />Destination: <Mono>{p.blocked_dest ?? "n/a"}</Mono><br />Detected: <Mono>{new Date(p.ts).toLocaleString()}</Mono><br />Lineage: <Mono>{p.lineage.join(", ") || "none"}</Mono></div>
        <ul className="space-y-1">{p.rule_ids.map((r) => <li key={r}><Badge t="crit">{r}</Badge> <span className="text-mute">{RULE_HELP[r] ?? ""}</span></li>)}</ul>
      </div>
      <p className="mt-2 text-xs text-mute">Recommended: review the lineage source; if it is untrusted, keep the agent blocked. Proof #{p.n} is in the chain.</p>
    </section>);
}
