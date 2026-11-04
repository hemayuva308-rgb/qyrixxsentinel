import { AlertTriangle, Check } from "lucide-react";
import { INTEGRATIONS } from "@/lib/home-content";
import { CARD, Heading, Section } from "./ui";

function Card({ d }: { d: (typeof INTEGRATIONS)[keyof typeof INTEGRATIONS] }) {
  return (
    <article className={`reveal ${CARD} flex flex-col p-6 sm:p-8`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <span aria-hidden className="flex h-12 min-w-12 items-center justify-center rounded-xl border border-qx-blue/15 bg-gradient-to-br from-qx-ice to-white px-2 font-mono text-sm font-bold tracking-tight text-qx-blue">{d.mark}</span>
          <h3 className="text-xl font-semibold tracking-tight text-qx-ink">{d.name}</h3>
        </div>
        <div className="text-right"><span className="inline-flex rounded-full border border-amber-200 bg-amber-50 px-2.5 py-0.5 font-mono text-[10.5px] font-semibold uppercase tracking-[.1em] text-amber-900">{d.status}</span>
          <p className="mt-1 text-xs text-qx-mute">{d.sub}</p></div>
      </div>
      <p className="mt-5 text-[15px] leading-relaxed text-qx-body">{d.text}</p>
      <ul className="mt-4 flex flex-wrap gap-2" aria-label={`${d.name} components`}>{d.tags.map((t) => <li key={t} className="rounded-full border border-qx-line bg-qx-mist px-3 py-1 font-mono text-xs text-qx-ink">{t}</li>)}</ul>
      <ul className="mt-5 space-y-2.5">{d.points.map((p) => <li key={p} className="flex gap-2.5 text-sm text-qx-body"><Check className="mt-0.5 h-4 w-4 shrink-0 text-qx-blue" aria-hidden />{p}</li>)}</ul>
      <p className="mt-6 flex gap-2.5 rounded-xl border border-amber-200 bg-amber-50/70 px-3.5 py-3 text-sm leading-relaxed text-amber-950">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-700" aria-hidden /><span><b className="font-semibold">Limits.</b> {d.limits}</span></p>
    </article>);
}

export default function IntegrationsSection() {
  return (
    <Section id="integrations" tone="mist" labelledBy="int-h">
      <Heading id="int-h" eyebrow="Integrations" title="Built for the agent and automation ecosystem."
        lead="Two integrations exist today, both at prototype stage. Their status is shown as it is." />
      <div className="mt-12 grid gap-6 lg:grid-cols-2">
        <Card d={INTEGRATIONS.mcp} />
        <Card d={INTEGRATIONS.n8n} />
      </div>
      <p className="reveal mt-8 max-w-3xl text-sm leading-relaxed text-qx-body">
        <b className="font-semibold text-qx-ink">Network isolation is part of the design.</b> An adapter mediates the actions that pass through it. If an agent or workflow can reach a tool or the internet directly, it can bypass Sentinel, so the protected workload must have no direct route out.</p>
    </Section>);
}
