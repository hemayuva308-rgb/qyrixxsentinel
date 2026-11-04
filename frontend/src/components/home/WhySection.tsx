import { Check, Minus } from "lucide-react";
import { WHY_ROWS } from "@/lib/home-content";
import { Heading, Section } from "./ui";

export default function WhySection() {
  return (
    <Section id="why" tone="mist" labelledBy="why-h">
      <Heading id="why-h" eyebrow="Why Qyrix Sentinel" title="Built around the execution boundary."
        lead="A design philosophy, not a benchmark. The left column describes a generic convention-only setup, not any named product." />
      <div className="reveal mt-12 overflow-hidden rounded-2xl border border-qx-line bg-white shadow-qx-card">
        <table className="block w-full text-left text-sm sm:table">
          <caption className="sr-only">A convention-only setup compared with the execution-boundary approach</caption>
          <thead className="sr-only sm:not-sr-only sm:table-header-group"><tr className="bg-qx-mist text-xs uppercase tracking-[.12em] text-qx-mute">
            <th scope="col" className="px-6 py-3.5 font-semibold"><span className="sr-only">Topic</span></th>
            <th scope="col" className="px-6 py-3.5 font-semibold">Convention-only setup</th>
            <th scope="col" className="bg-qx-ice/70 px-6 py-3.5 font-semibold text-qx-blue">Execution-boundary approach</th></tr></thead>
          <tbody className="block sm:table-row-group">{WHY_ROWS.map((r) => (
            <tr key={r.k} className="block space-y-3 border-t border-qx-line p-4 first:border-t-0 sm:table-row sm:space-y-0 sm:p-0 sm:first:border-t">
              <th scope="row" className="block text-[13px] font-semibold text-qx-ink sm:table-cell sm:w-1/5 sm:px-6 sm:py-4">{r.k}</th>
              <td data-label="Convention-only setup" className="block text-qx-body before:mb-1 before:block before:font-mono before:text-[10px] before:uppercase before:tracking-[.1em] before:text-qx-mute before:content-[attr(data-label)] sm:table-cell sm:px-6 sm:py-4 sm:before:hidden"><span className="flex gap-2"><Minus className="mt-0.5 h-4 w-4 shrink-0 text-qx-mute" aria-hidden />{r.a}</span></td>
              <td data-label="Execution-boundary approach" className="block rounded-lg bg-qx-ice/50 p-3 font-medium text-qx-ink before:mb-1 before:block before:font-mono before:text-[10px] before:uppercase before:tracking-[.1em] before:text-qx-blue before:content-[attr(data-label)] sm:table-cell sm:rounded-none sm:bg-qx-ice/40 sm:px-6 sm:py-4 sm:before:hidden"><span className="flex gap-2"><Check className="mt-0.5 h-4 w-4 shrink-0 text-qx-blue" aria-hidden />{r.b}</span></td></tr>))}</tbody>
        </table>
      </div>
    </Section>);
}
