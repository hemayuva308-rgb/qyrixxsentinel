import { PLATFORM } from "@/lib/home-content";
import { CARD, Heading, IconTile, Section } from "./ui";

export default function PlatformOverview() {
  return (
    <Section id="platform" labelledBy="platform-h">
      <div aria-hidden className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-qx-line to-transparent" />
      <Heading id="platform-h" eyebrow="Platform" title="One security layer. Every protected execution." center
        lead="Five building blocks work together on the actions that go through a supported integration. Other agents, actions and protocols are not covered automatically." />
      {/* 6-column grid: three cards on the first row, two wider cards on the second; equal sizes within a row. */}
      <ul className="mt-14 grid gap-5 sm:grid-cols-2 lg:grid-cols-6">
        {PLATFORM.map((p, i) => (
          <li key={p.t} className={`reveal ${CARD} group relative flex flex-col p-6 ${i < 3 ? "lg:col-span-2" : "lg:col-span-3"} ${i === 4 ? "sm:col-span-2" : ""}`} style={{ ["--d" as string]: `${i * 70}ms` }}>
            <div className="flex items-center justify-between">
              <IconTile icon={p.icon} />
              <span aria-hidden className="font-mono text-xs text-qx-mute">0{i + 1}</span>
            </div>
            <h3 className="mt-5 text-lg font-semibold tracking-tight text-qx-ink">{p.t}</h3>
            <p className="mt-2 text-[15px] leading-relaxed text-qx-body">{p.d}</p>
            <span aria-hidden className="absolute inset-x-6 bottom-0 h-px origin-left scale-x-0 bg-gradient-to-r from-qx-blue to-qx-sky transition-transform duration-500 group-hover:scale-x-100" />
          </li>))}
      </ul>
    </Section>);
}
