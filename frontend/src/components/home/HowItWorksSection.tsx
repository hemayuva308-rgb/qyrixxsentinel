import { CheckCircle2, HelpCircle, XCircle } from "lucide-react";
import { OUTCOMES, STEPS } from "@/lib/home-content";
import { CARD, Heading, Section } from "./ui";

const OUT = {
  allow: { icon: CheckCircle2, ring: "border-emerald-200", chip: "bg-emerald-50 text-emerald-800 border-emerald-200", ic: "text-emerald-600" },
  block: { icon: XCircle, ring: "border-rose-200", chip: "bg-rose-50 text-rose-800 border-rose-200", ic: "text-rose-600" },
  inconclusive: { icon: HelpCircle, ring: "border-amber-200", chip: "bg-amber-50 text-amber-900 border-amber-200", ic: "text-amber-600" },
} as const;

export default function HowItWorksSection() {
  return (
    <Section id="how" tone="ice" labelledBy="how-h">
      <Heading id="how-h" eyebrow="How it works" title="Four steps between a request and a verified outcome." />
      <ol className="relative mt-12 grid gap-5 md:grid-cols-2 lg:grid-cols-4">
        {STEPS.map((s, i) => (
          <li key={s.n} className="reveal relative" style={{ ["--d" as string]: `${i * 90}ms` }}>
            <div className={`${CARD} h-full p-6`}>
              <span className="font-mono text-sm font-semibold text-qx-blue">{s.n}</span>
              <h3 className="mt-3 text-lg font-semibold tracking-tight text-qx-ink">{s.t}</h3>
              <p className="mt-2 text-[15px] leading-relaxed text-qx-body">{s.d}</p>
            </div>
            {i < STEPS.length - 1 && <span aria-hidden className="absolute -right-3 top-1/2 hidden h-px w-6 bg-qx-blue/40 lg:block" />}
          </li>))}
      </ol>

      <div className="reveal mt-14">
        <h3 className="text-sm font-semibold uppercase tracking-[.14em] text-qx-ink">Three possible outcomes</h3>
        <p className="mt-1 text-sm text-qx-body">Illustrative examples of how an outcome is described. They are not recorded results.</p>
        <ul className="mt-5 grid gap-4 md:grid-cols-3">
          {OUTCOMES.map((o) => {
            const v = OUT[o.kind];
            return (
              <li key={o.kind} className={`qx-card rounded-2xl border bg-white p-5 shadow-qx-card ${v.ring}`}>
                <div className="flex items-center justify-between gap-3">
                  <span className="flex items-center gap-2 text-[15px] font-semibold text-qx-ink"><v.icon className={`h-5 w-5 ${v.ic}`} aria-hidden />{o.t}</span>
                  <span className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold tracking-[.08em] ${v.chip}`}>{o.tag}</span>
                </div>
                <p className="mt-3 text-sm leading-relaxed text-qx-body">{o.d}</p>
              </li>);
          })}
        </ul>
      </div>
    </Section>);
}
