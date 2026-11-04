import { EVIDENCE, EVIDENCE_ROWS } from "@/lib/home-content";
import { Heading, Section } from "./ui";

const TONE = { slate: "border-slate-200 bg-slate-50 text-slate-800", blue: "border-qx-blue/25 bg-qx-ice text-qx-blue", amber: "border-amber-200 bg-amber-50 text-amber-900" } as const;

export default function EvidenceSection() {
  return (
    <Section id="evidence" tone="navy" labelledBy="ev-h">
      <div aria-hidden className="site-grid-dark absolute inset-0 opacity-60" />
      <div aria-hidden className="absolute -right-32 top-0 h-96 w-96 rounded-full bg-qx-blue/25 blur-3xl" />
      <div className="relative">
        <Heading id="ev-h" dark eyebrow="Evidence & verification" title="Security claims deserve evidence."
          lead="Qyrix Sentinel separates what an integration says about itself from what an independent observer can show. Missing evidence is reported as missing." />

        <ul className="mt-12 grid gap-5 md:grid-cols-3">
          {EVIDENCE.map((e, i) => (
            <li key={e.id} className="reveal rounded-2xl border border-white/10 bg-white/[.05] p-6 backdrop-blur" style={{ ["--d" as string]: `${i * 90}ms` }}>
              <span className={`inline-flex rounded-full border px-3 py-1 font-mono text-xs font-bold tracking-[.1em] ${TONE[e.tone]}`}>{e.id}</span>
              <h3 className="mt-4 text-lg font-semibold tracking-tight text-white">{e.t}</h3>
              <p className="mt-2 text-[15px] leading-relaxed text-slate-300">{e.d}</p>
            </li>))}
        </ul>

        <div className="reveal mt-10 overflow-hidden rounded-2xl border border-white/10 bg-white/[.04]">
          <table className="block w-full text-left text-sm sm:table">
            <caption className="sr-only">Comparison of E1 adapter-reported evidence and E3 independently observed evidence</caption>
            <thead className="sr-only sm:not-sr-only sm:table-header-group"><tr className="border-b border-white/10 text-xs uppercase tracking-[.12em] text-slate-400">
              <th scope="col" className="px-6 py-3 font-semibold"><span className="sr-only">Property</span></th>
              <th scope="col" className="px-6 py-3 font-semibold text-slate-200">E1 · adapter-reported</th>
              <th scope="col" className="px-6 py-3 font-semibold text-qx-sky">E3 · independently observed</th></tr></thead>
            <tbody className="block sm:table-row-group">{EVIDENCE_ROWS.map((r) => (
              <tr key={r.k} className="block space-y-3 border-t border-white/10 p-4 first:border-t-0 sm:table-row sm:space-y-0 sm:p-0 sm:first:border-t">
                <th scope="row" className="block text-[13px] font-semibold text-white sm:table-cell sm:px-6 sm:py-3.5 sm:font-medium sm:text-slate-300">{r.k}</th>
                <td data-label="E1 · adapter-reported" className="block text-slate-200 before:mb-0.5 before:block before:font-mono before:text-[10px] before:uppercase before:tracking-[.1em] before:text-slate-400 before:content-[attr(data-label)] sm:table-cell sm:px-6 sm:py-3.5 sm:before:hidden">{r.e1}</td>
                <td data-label="E3 · independently observed" className="block text-slate-200 before:mb-0.5 before:block before:font-mono before:text-[10px] before:uppercase before:tracking-[.1em] before:text-qx-sky before:content-[attr(data-label)] sm:table-cell sm:px-6 sm:py-3.5 sm:before:hidden">{r.e3}</td></tr>))}</tbody>
          </table>
        </div>
        <p className="reveal mt-6 max-w-3xl text-sm leading-relaxed text-slate-300">
          <b className="font-semibold text-white">About this page.</b> It shows no proof records, verification results or percentages. An enforcement claim needs independent observation <i>and</i> complete evidence; adapter self-reports alone never qualify.</p>
      </div>
    </Section>);
}
