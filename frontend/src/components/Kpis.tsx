"use client";
import type { Status } from "@/lib/types";
import { Badge } from "./ui";

const dot = (s: string) => (s === "available" ? "ok" : "warn") as "ok" | "warn";
export default function Kpis({ s }: { s: Status | null }) {
  const m = (label: string, v: string | number | null, sub?: string) => (
    <div className="rounded-xl border border-white/10 bg-card/80 p-3"><div className="text-[10px] tracking-[.18em] text-mute">{label}</div>
      <div className="mt-1 font-mono text-2xl">{v ?? "No data"}</div>{sub && <div className="text-[11px] text-mute">{sub}</div>}</div>);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {s ? (["api", "gate", "provenance", "proof"] as const).map((k) => <Badge key={k} t={dot(s[k])}>● {k.toUpperCase()}: {s[k]}</Badge>) : null}
        {s && <Badge t={s.ai_provider === "available" ? "ok" : "warn"}>● AI: {s.ai_provider === "available" ? s.ai_providers.join("+") : "fallback heuristic"}</Badge>}
        {s?.persistence && <Badge t={s.persistence === "postgres" ? "ok" : s.persistence === "down" ? "crit" : "warn"}>● STORAGE: {s.persistence === "postgres" ? "PostgreSQL" : s.persistence === "down" ? "DOWN (fail closed)" : "in-memory"}</Badge>}
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {m("DECISIONS", s?.decisions ?? null)}{m("BLOCKED", s?.blocked ?? null)}{m("ALLOWED", s?.allowed ?? null)}
        {m("EXTERNAL CALLS", s?.external_calls ?? null, `real egress · ${s?.executions ?? 0} grant executions`)}
        {m("AVG LATENCY", s?.avg_latency_ms != null ? `${s.avg_latency_ms} ms` : null, s?.p95_ms != null ? `p95 ${s.p95_ms} ms` : "measured only")}
      </div>
    </div>);
}
