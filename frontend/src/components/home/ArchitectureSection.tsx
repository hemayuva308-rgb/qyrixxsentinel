"use client";
import { useRef, useState } from "react";
import { ARCH_FLOW, ARCH_OBSERVER } from "@/lib/home-content";
import { Heading, Section } from "./ui";

const ALL = [...ARCH_FLOW, ARCH_OBSERVER];
const OBS = ALL.length - 1;
const TICKS: Record<number, string> = { 1: "reports (E1)", 2: "signed claims", 4: "observes path" };   // what the Observer receives from which stage

/** Interactive architecture. Tabs (roving tabindex, arrow keys, Home/End); selecting a stage highlights the path up to it. */
export default function ArchitectureSection() {
  const [active, setActive] = useState(2);                       // start on the Gate: the authorization authority
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const node = ALL[active];
  const onObserver = active === OBS;

  function move(to: number) { const n = (to + ALL.length) % ALL.length; setActive(n); refs.current[n]?.focus(); }
  function onKey(e: React.KeyboardEvent) {
    const k = e.key;
    if (k === "ArrowRight" || k === "ArrowDown") { e.preventDefault(); move(active + 1); }
    else if (k === "ArrowLeft" || k === "ArrowUp") { e.preventDefault(); move(active - 1); }
    else if (k === "Home") { e.preventDefault(); move(0); }
    else if (k === "End") { e.preventDefault(); move(ALL.length - 1); }
  }
  const btn = (i: number, n: (typeof ALL)[number], extra = "") => {
    const on = i === active, passed = onObserver ? i < OBS : i <= active;
    return (
      <button type="button" role="tab" id={`arch-tab-${n.id}`} aria-selected={on} aria-controls="arch-panel" tabIndex={on ? 0 : -1}
        ref={(el) => { refs.current[i] = el; }} onClick={() => setActive(i)} onKeyDown={onKey}
        className={`group relative z-10 flex w-full items-start gap-4 rounded-xl text-left lg:flex-col lg:items-center lg:gap-3 lg:text-center ${extra}`}>
        <span className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border transition duration-300 ${on ? "border-qx-blue bg-qx-blue text-white shadow-[0_14px_30px_-12px_rgba(37,99,235,.75)]" : passed ? "border-qx-blue/40 bg-qx-ice text-qx-blue" : "border-qx-line bg-white text-qx-body group-hover:border-qx-blue/40 group-hover:text-qx-blue"}`}>
          <n.icon className="h-6 w-6" aria-hidden /></span>
        <span className="block pt-1 lg:pt-0">
          <span className={`block text-[14.5px] font-semibold leading-snug ${on ? "text-qx-blue" : "text-qx-ink"}`}>{n.label}</span>
          <span className="mt-0.5 block text-xs leading-snug text-qx-mute">{n.sub}</span>
        </span>
      </button>);
  };

  return (
    <Section id="architecture" labelledBy="arch-h">
      <div aria-hidden className="site-grid absolute inset-0 opacity-60" />
      <div className="relative">
        <Heading id="arch-h" eyebrow="Architecture" title="From agent intent to controlled execution."
          lead="Select a stage to see what it does and what it does not do. The highlighted line shows the path from the agent to that stage." />

        <div className="reveal qx-glass mt-12 rounded-[28px] p-5 sm:p-8">
          <div role="tablist" aria-label="Execution path stages" aria-orientation="horizontal">
            <div className="grid lg:grid-cols-6">
              {ARCH_FLOW.map((n, i) => (
                <div key={n.id} className="relative pb-7 last:pb-0 lg:pb-0">
                  {btn(i, n)}
                  {i < ARCH_FLOW.length - 1 && (
                    <span aria-hidden data-on={!onObserver && i < active ? "true" : "false"}
                      className="qx-conn absolute left-7 top-[4.25rem] bottom-1 w-px -translate-x-1/2 lg:left-[calc(50%+2.25rem)] lg:right-[calc(-50%+2.25rem)] lg:top-7 lg:bottom-auto lg:h-px lg:w-auto lg:translate-x-0" />)}
                </div>))}
            </div>

            {/* Observer: an evidence layer beside the path. It receives from stages; it is not in the decision path. */}
            <div className="mt-6 lg:mt-2">
              <div aria-hidden className="hidden grid-cols-6 lg:grid">
                {ALL.slice(0, 6).map((_, i) => (
                  <div key={i} className="flex flex-col items-center">
                    {TICKS[i] ? (<><span className="qx-conn h-8 w-px" data-on={onObserver ? "true" : "false"} />
                      <span className="mt-1 font-mono text-[10px] uppercase tracking-[.08em] text-qx-mute">{TICKS[i]}</span></>) : <span className="h-8" />}
                  </div>))}
              </div>
              <div className="lg:mt-2">{btn(OBS, ARCH_OBSERVER, `rounded-2xl border border-dashed p-4 lg:flex-row lg:justify-center lg:text-left ${onObserver ? "border-qx-blue bg-qx-ice/70" : "border-qx-line bg-white/70 hover:border-qx-blue/40"}`)}</div>
            </div>
          </div>

          <div id="arch-panel" role="tabpanel" aria-labelledby={`arch-tab-${node.id}`} tabIndex={0}
            className="mt-7 rounded-2xl border border-qx-line bg-white p-5 shadow-qx-card sm:p-7">
            <div className="flex flex-wrap items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-qx-ice text-qx-blue"><node.icon className="h-5 w-5" aria-hidden /></span>
              <h3 className="text-xl font-semibold tracking-tight text-qx-ink">{node.label}</h3>
              {node.badge && <span className={`rounded-full border px-2.5 py-0.5 font-mono text-[10.5px] font-semibold uppercase tracking-[.1em] ${node.id === "observer" ? "border-slate-200 bg-slate-50 text-slate-700" : "border-qx-blue/25 bg-qx-ice text-qx-blue"}`}>{node.badge}</span>}
            </div>
            <p className="mt-4 max-w-3xl text-base leading-relaxed text-qx-ink/90">{node.text}</p>
            <p className="mt-4 max-w-3xl border-l-2 border-amber-300 pl-4 text-sm leading-relaxed text-qx-body"><b className="font-semibold text-qx-ink">Limit.</b> {node.limit}</p>
          </div>
        </div>
      </div>
    </Section>);
}
