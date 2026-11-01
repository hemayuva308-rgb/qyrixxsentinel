"use client";
import { useMemo } from "react";
import { api, S } from "@/lib/api";
import type { Proof, Verify } from "@/lib/types";
import { Badge, Card, Empty, ErrorBox, Loading, Mono, labelTone, usePoll, verdictTone } from "./ui";

// Every figure here is computed from the production proof chain returned by the backend. Nothing is estimated.
export default function ForensicInsights() {
  const ch = usePoll(() => api<{ chain: Proof[]; verify: Verify }>(`${S}/proofs`), 6000);
  const chain = ch.data?.chain ?? [];
  const decisions = useMemo(() => chain.filter((r) => (r.kind ?? "gate_decision") === "gate_decision"), [chain]);

  const dests = useMemo(() => {
    const m = new Map<string, number>();
    decisions.forEach((r) => r.verdict === "BLOCK" && r.blocked_dest && m.set(r.blocked_dest, (m.get(r.blocked_dest) ?? 0) + 1));
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [decisions]);
  const rules = useMemo(() => {
    const m = new Map<string, number>();
    decisions.forEach((r) => r.rule_ids.forEach((x) => m.set(x, (m.get(x) ?? 0) + 1)));
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [decisions]);
  const buckets = useMemo(() => {           // decisions per minute over the last 30 minutes of activity
    if (!decisions.length) return [];
    const end = Date.parse(decisions[decisions.length - 1].ts);
    const out = Array.from({ length: 30 }, () => ({ a: 0, b: 0 }));
    decisions.forEach((r) => { const i = 29 - Math.floor((end - Date.parse(r.ts)) / 60000); if (i >= 0 && i < 30) out[i][r.verdict === "BLOCK" ? "b" : "a"]++; });
    return out;
  }, [decisions]);
  const last = decisions[decisions.length - 1];
  const maxB = Math.max(1, ...buckets.map((x) => x.a + x.b));
  const maxD = Math.max(1, ...dests.map((d) => d[1]));
  const maxR = Math.max(1, ...rules.map((d) => d[1]));

  if (ch.loading) return <Card title="FORENSIC ANALYSIS"><Loading /></Card>;
  if (ch.error) return <Card title="FORENSIC ANALYSIS"><ErrorBox msg={ch.error} retry={ch.reload} /></Card>;
  if (!decisions.length) return <Card title="FORENSIC ANALYSIS"><Empty text="No data - no gate decisions recorded yet" /></Card>;

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="LATEST DECISION PATH" right={<Badge t={verdictTone(last.verdict)}>{last.verdict}</Badge>}>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {(last.lineage ?? []).slice().reverse().map((l) => { const [id, lab] = l.split(":"); return <span key={l} className="flex items-center gap-2"><Badge t={labelTone(lab)}>{id.slice(0, 8)} {lab}</Badge><span className="text-mute">→</span></span>; })}
          {!(last.lineage ?? []).length && <><Badge t="warn">no lineage</Badge><span className="text-mute">→</span></>}
          <Badge t="neon">{last.method ?? ""} {last.tool}</Badge><span className="text-mute">→</span>
          <Badge t={verdictTone(last.verdict)}>GATE {last.verdict}</Badge>
          {last.verdict === "BLOCK" && last.blocked_dest && <><span className="text-crit">✕</span><Mono>{last.blocked_dest}</Mono></>}
        </div>
        <p className="mt-3 text-xs text-mute">record #{last.n} · {new Date(last.ts).toLocaleString()} · {last.rule_ids.join(", ") || "all checks passed"}</p>
      </Card>

      <Card title="DECISION ACTIVITY (LAST 30 MIN OF ACTIVITY)">
        <div className="flex h-28 items-end gap-[3px]" role="img" aria-label="Allowed and blocked decisions per minute">
          {buckets.map((x, i) => (
            <div key={i} className="flex flex-1 flex-col justify-end" title={`${x.a} allowed, ${x.b} blocked`}>
              <div className="rounded-t-sm bg-crit/80" style={{ height: `${(x.b / maxB) * 100}%` }} />
              <div className="bg-ok/70" style={{ height: `${(x.a / maxB) * 100}%` }} />
            </div>))}
        </div>
        <p className="mt-2 text-[11px] text-mute"><span className="text-crit">■</span> blocked <span className="ml-2 text-ok">■</span> allowed · {decisions.length} decisions in chain</p>
      </Card>

      <Card title="EXFILTRATION PATHS (BLOCKED DESTINATIONS)">
        {!dests.length ? <Empty text="No data - no blocked destinations" /> : (
          <ul className="space-y-2">{dests.map(([d, n]) => (
            <li key={d} className="text-xs"><div className="flex justify-between gap-2"><Mono>{d}</Mono><span className="font-mono text-crit">{n}</span></div>
              <div className="mt-1 h-1.5 rounded bg-white/5"><div className="h-full rounded bg-gradient-to-r from-warn to-crit" style={{ width: `${(n / maxD) * 100}%` }} /></div></li>))}</ul>)}
        <p className="mt-2 text-[11px] text-mute">Redacted destinations from BLOCK records. None of these were contacted.</p>
      </Card>

      <Card title="POLICY RULES TRIGGERED">
        {!rules.length ? <Empty text="No data - no rules triggered" /> : (
          <ul className="space-y-2">{rules.map(([r, n]) => (
            <li key={r} className="grid grid-cols-[200px_1fr_32px] items-center gap-2 text-xs"><Mono>{r}</Mono>
              <div className="h-1.5 rounded bg-white/5"><div className="h-full rounded bg-neon/70" style={{ width: `${(n / maxR) * 100}%` }} /></div>
              <span className="text-right font-mono">{n}</span></li>))}</ul>)}
      </Card>
    </div>);
}
