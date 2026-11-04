import { CAPABILITIES } from "@/lib/home-content";
import { CARD, Heading, IconTile, Section, StatusChip } from "./ui";

export default function SecurityCapabilities() {
  return (
    <Section id="capabilities" labelledBy="cap-h">
      <Heading id="cap-h" eyebrow="Security capabilities" title="Security should be enforced, not merely suggested."
        lead="Each capability carries its current status in this repository. The labels describe implementation state, not a security certification." />
      <ul className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {CAPABILITIES.map((c, i) => (
          <li key={c.t} className={`reveal ${CARD} flex gap-4 p-5`} style={{ ["--d" as string]: `${(i % 3) * 70}ms` }}>
            <IconTile icon={c.icon} tone="slate" />
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5"><h3 className="text-[15px] font-semibold leading-snug text-qx-ink">{c.t}</h3><StatusChip kind={c.s}>{c.s}</StatusChip></div>
              <p className="mt-1.5 text-sm leading-relaxed text-qx-body">{c.d}</p>
            </div>
          </li>))}
      </ul>
      <p className="reveal mt-8 max-w-3xl rounded-xl border border-qx-line bg-qx-mist px-4 py-3 text-sm leading-relaxed text-qx-body">
        <b className="font-semibold text-qx-ink">What this does not claim.</b> Sentinel reduces specific risks on the paths it controls. It does not claim complete protection against prompt injection, data exfiltration, SSRF, credential theft or any other attack class.</p>
    </Section>);
}
