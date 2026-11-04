import { STATUS } from "@/lib/home-content";
import { CARD, Heading, Section, StatusChip } from "./ui";

export default function ProductStatusSection() {
  return (
    <Section id="status" labelledBy="status-h">
      <Heading id="status-h" eyebrow="Product status" title="Where things stand, plainly."
        lead="We would rather you know the maturity of each part now. Known findings are tracked openly in the integration documentation." />
      <ul className="mt-12 grid gap-4 sm:grid-cols-2">
        {STATUS.map((s, i) => (
          <li key={s.t} className={`reveal ${CARD} flex flex-col gap-3 p-6`} style={{ ["--d" as string]: `${(i % 2) * 80}ms` }}>
            <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="text-[16px] font-semibold tracking-tight text-qx-ink">{s.t}</h3>
              <StatusChip kind={s.s}>{s.s}</StatusChip></div>
            <p className="text-[15px] leading-relaxed text-qx-body">{s.d}</p>
          </li>))}
      </ul>
    </Section>);
}
