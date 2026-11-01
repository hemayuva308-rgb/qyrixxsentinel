"use client";
import { useState } from "react";
import { CheckCircle2, FlaskConical, XCircle } from "lucide-react";
import { api, S } from "@/lib/api";
import type { Bench } from "@/lib/types";
import { Badge, Btn, Card, Empty, Mono, useToast, verdictTone } from "./ui";

export default function BenchmarkPanel({ demo, onDone }: { demo: boolean; onDone: () => void }) {
  const toast = useToast();
  const [b, setB] = useState<Bench | null>(null); const [busy, setBusy] = useState(false);
  async function run() {
    if (!confirm("The benchmark RESETS provenance, approvals and the proof chain, then replays the 10 plan cases. Demo/eval mode only. Continue?")) return;
    setBusy(true);
    try { setB(await api<Bench>(`${S}/benchmark`, { method: "POST" })); onDone(); toast("ok", "Benchmark finished"); }
    catch (e) { toast("err", (e as Error).message); } finally { setBusy(false); }
  }
  const max = b ? Math.max(...b.cases.map((c) => c.ms), 0.001) : 1;
  return (
    <Card title="ATTACK -> BLOCK -> PROOF -> SAFE BENCHMARK" right={<Btn loading={busy} disabled={!demo} onClick={run} title={demo ? "" : "disabled: server not in demo/eval mode"}><FlaskConical className="h-3.5 w-3.5" />RUN 10 CASES</Btn>}>
      {!demo && <p className="mb-2 text-xs text-warn">Server is in production mode (QYRIX_ENABLE_DEMO_RESET unset): the benchmark is disabled because it resets evidence.</p>}
      {!b ? <Empty text="Run the benchmark to measure prevention, false positives, task completion and latency" /> : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {[["PREVENTION", b.metrics.prevention + "%"], ["FALSE POSITIVE", b.metrics.false_positive + "%"], ["TASK COMPLETION", b.metrics.task_completion + "%"], ["AVG LATENCY", b.metrics.avg_latency_ms + " ms"]].map(([k, v]) => (
              <div key={k} className="rounded-xl border border-white/10 bg-bg2 p-3"><div className="text-[10px] tracking-[.18em] text-mute">{k}</div><div className="font-mono text-2xl text-neon">{v}</div></div>))}
          </div>
          <p className="mt-1 text-[11px] text-mute">{b.counts ? `${b.counts.attacks_blocked}/${b.counts.attacks} attacks blocked, ${b.counts.safe_allowed}/${b.counts.safe} safe tasks allowed. ` : ""}Measured on these 10 synthetic cases only - not a claim about real-world attack coverage.</p>
          <div className="mt-3 overflow-x-auto"><table className="w-full text-left text-xs"><thead className="text-mute"><tr><th className="py-1">Case</th><th>Type</th><th>Expected</th><th>Actual</th><th>Rules</th><th>ms</th><th></th></tr></thead>
            <tbody>{b.cases.map((c) => (
              <tr key={c.name} className="border-t border-white/5"><td className="py-1.5 pr-2">{c.name}</td><td><Badge>{c.type}</Badge></td><td><Badge>{c.expected ?? (c.type === "SAFE" ? "ALLOW" : "BLOCK")}</Badge></td><td><Badge t={verdictTone(c.verdict)}>{c.verdict}</Badge></td>
                <td className="max-w-[260px]"><Mono>{c.rules.join(" ") || "-"}</Mono></td>
                <td className="w-28"><div className="flex items-center gap-1"><div className="h-1.5 rounded bg-neon" style={{ width: `${(c.ms / max) * 60 + 2}px` }} /><span className="font-mono">{c.ms}</span></div></td>
                <td>{c.ok ? <CheckCircle2 className="h-4 w-4 text-ok" aria-label="expected" /> : <XCircle className="h-4 w-4 text-crit" aria-label="unexpected" />}</td></tr>))}</tbody></table></div>
          <div className="mt-3 space-y-1">{b.hypotheses.map((h) => (
            <div key={h.q} className="flex items-center gap-2 text-xs">{h.holds ? <CheckCircle2 className="h-4 w-4 text-ok" /> : <XCircle className="h-4 w-4 text-crit" />}<span>{h.q}</span></div>))}</div>
        </>)}
    </Card>);
}
