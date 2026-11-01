import type { Metadata } from "next";
import { Container, PageHero, SectionHead, Tag } from "@/components/site/primitives";
import { FaqList, FinalCta, PricingCards } from "@/components/site/blocks";
import { FAQ } from "@/lib/site-content";

export const metadata: Metadata = { title: "Pricing", description: "Proposed launch pricing for QYRIX SENTINEL." };

const UNITS = [
  ["Gate evaluation (security check)", "Yes - proposed billable unit", "One ALLOW or BLOCK decision on a proposed action."],
  ["Blocked request", "Counted as one check", "A BLOCK is a completed evaluation; blocking is the product working."],
  ["Verified tool execution", "No separate charge (proposed)", "Execution through a grant; the evaluation was already counted."],
  ["Successful execution", "No separate charge (proposed)", "The adapter returned a result."],
  ["Skill inspection", "Not counted", "Inspector analysis of text."],
  ["Proof verification / export", "Not counted", "A verified forensic report export is a proposed paid add-on (₹500)."],
];

export default function Pricing() {
  return (
    <>
      <PageHero eyebrow="Pricing" title={<>Pay for <span className="text-gradient">decisions</span>, not seats.</>}
        lead="Proposed launch pricing. Billing, metering and quotas are not live in this build; plans are offered through a sales conversation and a written agreement." />
      <section className="py-16 sm:py-20"><Container><PricingCards /></Container></section>
      <section className="border-t border-site-line bg-site-mist py-16 sm:py-24" aria-labelledby="units">
        <Container className="grid gap-10 lg:grid-cols-[1fr_1.6fr]">
          <div>
            <SectionHead id="units" eyebrow="Billing definitions" title="What exactly is a check?" lead="These terms are not interchangeable. The proposed billable event is one Gate evaluation; duplicate submissions would be de-duplicated server-side with idempotency keys once metering exists." />
            <div className="reveal mt-6"><Tag tone="amber">Metering not implemented</Tag></div>
          </div>
          <div className="reveal overflow-hidden rounded-3xl border border-site-line bg-white">
            <table className="w-full text-left text-sm">
              <thead className="bg-site-mist font-mono text-[11px] uppercase tracking-[.14em] text-site-mute"><tr><th className="px-5 py-3">Event</th><th className="px-5 py-3">Billable</th><th className="hidden px-5 py-3 md:table-cell">Definition</th></tr></thead>
              <tbody>{UNITS.map(([a, b, c]) => (
                <tr key={a} className="border-t border-site-line align-top"><td className="px-5 py-3 font-medium text-site-ink">{a}</td><td className="px-5 py-3 text-site-mute">{b}</td><td className="hidden px-5 py-3 text-site-mute md:table-cell">{c}</td></tr>))}</tbody>
            </table>
          </div>
        </Container>
      </section>
      <section className="py-16 sm:py-24" aria-labelledby="more">
        <Container className="grid gap-10 lg:grid-cols-[1fr_1.6fr]">
          <div><SectionHead id="more" eyebrow="Additional options" title="Beyond the plans." />
            <ul className="reveal mt-6 space-y-3 text-[15px] text-site-mute">
              <li><b className="text-site-ink">Pay-as-you-go checks</b> above the plan allowance (rate to be confirmed).</li>
              <li><b className="text-site-ink">Verified forensic report export</b>: proposed ₹500 per report, generated only from real proof data. A verifiable report is not automatically legally admissible proof.</li>
              <li><b className="text-site-ink">Private deployment licence</b> for on-premise installs.</li>
            </ul></div>
          <div className="reveal"><FaqList items={FAQ.filter((f) => /check|on-premise|legal|demo/i.test(f.q))} /></div>
        </Container>
      </section>
      <FinalCta />
    </>);
}
