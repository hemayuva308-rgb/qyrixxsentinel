import { PROBLEMS } from "@/lib/home-content";
import { CARD, Heading, IconTile, Section } from "./ui";

export default function TrustProblemSection() {
  return (
    <Section id="problem" tone="mist" labelledBy="problem-h">
      <Heading id="problem-h" eyebrow="The problem" title="AI agents need more than trust. They need controlled execution."
        lead="Once an agent can call tools, the question is no longer only what it says, but what it is allowed to do." />
      <ul className="mt-12 grid gap-5 md:grid-cols-3">
        {PROBLEMS.map((p, i) => (
          <li key={p.t} className={`reveal ${CARD} p-6`} style={{ ["--d" as string]: `${i * 90}ms` }}>
            <IconTile icon={p.icon} />
            <h3 className="mt-5 text-lg font-semibold tracking-tight text-qx-ink">{p.t}</h3>
            <p className="mt-2 text-[15px] leading-relaxed text-qx-body">{p.d}</p>
          </li>))}
      </ul>
    </Section>);
}
