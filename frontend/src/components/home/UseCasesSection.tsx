import { USE_CASES } from "@/lib/home-content";
import { CARD, Heading, IconTile, Section } from "./ui";

export default function UseCasesSection() {
  return (
    <Section id="use-cases" labelledBy="uc-h">
      <Heading id="uc-h" eyebrow="Use cases" title="Where an execution boundary helps." center
        lead="What the platform helps control in each case, and how far support extends today." />
      <ul className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {USE_CASES.map((u, i) => (
          <li key={u.t} className={`reveal ${CARD} flex flex-col p-6`} style={{ ["--d" as string]: `${(i % 3) * 70}ms` }}>
            <IconTile icon={u.icon} />
            <h3 className="mt-5 text-lg font-semibold tracking-tight text-qx-ink">{u.t}</h3>
            <p className="mt-2 flex-1 text-[15px] leading-relaxed text-qx-body">{u.d}</p>
            <p className="mt-4 border-t border-qx-line pt-3 font-mono text-[11px] uppercase tracking-[.08em] text-qx-mute">{u.note}</p>
          </li>))}
      </ul>
    </Section>);
}
