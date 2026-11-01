"use client";
import { useEffect, useRef, useState } from "react";
import { Bot, FileSearch, GitBranch, Link2, ShieldCheck } from "lucide-react";
import { useInView, useSvgPlayback } from "./motion";
import { WORKFLOW } from "@/lib/site-content";

/** Pauses CSS loops (flow-dash, pulse-soft) inside children when off-screen. */
export function PauseOffscreen({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  const [ref, inView] = useInView<HTMLDivElement>("40px");
  return <div ref={ref} data-paused={!inView} className={className}>{children}</div>;
}

/* ---------------- Section 3: the execution security gap ---------------- */
export function GapDiagram() {
  const [ref, inView] = useInView<HTMLDivElement>();
  const svg = useSvgPlayback(inView);
  return (
    <div ref={ref} data-paused={!inView}>
      <ol className="space-y-2 sm:hidden" aria-label="The execution security gap">
        {[["AI agent", "reads an instruction", "bg-site-blue"], ["Tool request", "built from that instruction", "bg-site-blue"],
          ["No checkpoint", "nothing evaluates the action", "bg-rose-500"], ["Unsafe action executes", "the damage is done", "bg-rose-500"],
          ["Monitoring alert", "arrives after execution", "bg-amber-500"]].map(([t, d, c], i) => (
          <li key={t} className={`flex items-center gap-3 rounded-2xl border p-3 ${i === 2 ? "border-dashed border-rose-300 bg-rose-50" : "border-site-line bg-white"}`}>
            <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${c}`} /><div><p className="text-sm font-semibold text-site-ink">{t}</p><p className="text-xs text-site-mute">{d}</p></div>
          </li>))}
      </ol>
      <svg ref={svg} viewBox="0 0 640 250" className="hidden h-auto w-full sm:block" role="img" aria-labelledby="gap-t gap-d" style={{ fontFamily: "inherit" }}>
        <title id="gap-t">The execution security gap</title>
        <desc id="gap-d">An agent turns an instruction into a tool request. With no checkpoint before execution, the unsafe action runs, and a monitoring alert can only be raised afterwards.</desc>
        <path d="M86 92 H554" stroke="#CBD5E6" strokeWidth="1.5" />
        <path d="M86 92 H554" stroke="#E11D48" strokeOpacity=".55" strokeWidth="1.5" className="flow-dash" />
        {[["AI agent", 56, "#1F5BFF"], ["Tool request", 222, "#1F5BFF"], ["Unsafe action", 584, "#E11D48"]].map(([t, x, c]) => (
          <g key={t as string}>
            <circle cx={x as number} cy="92" r="30" fill="#fff" stroke="#E2E8F2" strokeWidth="1.5" />
            <circle cx={x as number} cy="92" r="9" fill={c as string} opacity=".9" />
            <text x={x as number} y="146" fontSize="12.5" fontWeight="600" fill="#0B1630" textAnchor="middle">{t}</text>
          </g>))}
        <rect x="300" y="52" width="200" height="80" rx="16" fill="#FFF1F2" stroke="#E11D48" strokeDasharray="5 6" className="pulse-soft" />
        <text x="400" y="88" fontSize="12" fontWeight="800" fill="#BE123C" textAnchor="middle" letterSpacing="1.6">NO CHECKPOINT</text>
        <text x="400" y="106" fontSize="11" fill="#9F1239" textAnchor="middle">nothing evaluates the action</text>
        <circle r="6" fill="#E11D48">
          <animateMotion dur="4.5s" repeatCount="indefinite" path="M86 92 H554" />
        </circle>
        <path d="M554 196 H86" stroke="#E2E8F2" strokeWidth="1.5" markerEnd="none" />
        <g transform="translate(584 196)">
          <circle r="16" fill="#FFFBEB" stroke="#F59E0B" />
          <path d="M-5 3 h10 M-4 3 v-5 a4 4 0 0 1 8 0 v5 M-1.5 6 h3" stroke="#B45309" strokeWidth="1.6" fill="none" strokeLinecap="round" />
        </g>
        <text x="556" y="230" fontSize="11.5" fill="#55627A" textAnchor="end">Monitoring alert arrives <tspan fontWeight="700" fill="#B45309">after</tspan> execution</text>
        <text x="56" y="200" fontSize="11" fill="#55627A" fontFamily="ui-monospace,monospace">time →</text>
      </svg>
    </div>);
}

/* ---------------- Section 4: the checkpoint ---------------- */
export function CheckpointDiagram() {
  const [ref, inView] = useInView<HTMLDivElement>();
  const svg = useSvgPlayback(inView);
  const checks = ["Destination", "Action", "Data", "Authentication", "Provenance"];
  return (
    <div ref={ref} data-paused={!inView}>
      <svg ref={svg} viewBox="0 0 720 300" className="h-auto w-full" role="img" aria-labelledby="cp-t cp-d" style={{ fontFamily: "inherit" }}>
        <title id="cp-t">QYRIX SENTINEL as a checkpoint</title>
        <desc id="cp-d">Agent requests pass through the QYRIX SENTINEL layer, which checks destination, action, data, authentication and provenance. Approved requests reach the tool; others are blocked.</desc>
        <path d="M110 150 H250" stroke="#67E8F9" strokeOpacity=".35" strokeWidth="1.5" className="flow-dash" />
        <path d="M470 150 C530 150 540 86 600 86" fill="none" stroke="#22D3EE" strokeWidth="1.5" className="flow-dash" />
        <path d="M470 150 C530 150 540 214 600 214" fill="none" stroke="#FB7185" strokeOpacity=".7" strokeWidth="1.5" strokeDasharray="3 6" />
        <g><circle cx="70" cy="150" r="40" fill="#fff" fillOpacity=".06" stroke="#fff" strokeOpacity=".2" />
          <text x="70" y="146" fontSize="11" fontWeight="700" fill="#fff" textAnchor="middle" letterSpacing="1.2">AI</text>
          <text x="70" y="161" fontSize="11" fontWeight="700" fill="#fff" textAnchor="middle" letterSpacing="1.2">AGENT</text></g>
        <rect x="250" y="40" width="220" height="220" rx="24" fill="#fff" fillOpacity=".06" stroke="#67E8F9" strokeOpacity=".45" />
        <text x="360" y="72" fontSize="12" fontWeight="800" fill="#fff" textAnchor="middle" letterSpacing="2">QYRIX SENTINEL</text>
        {checks.map((c, i) => (
          <g key={c}>
            <rect x="276" y={88 + i * 32} width="168" height="24" rx="12" fill="#fff" fillOpacity=".06" stroke="#fff" strokeOpacity=".14" />
            <circle cx="292" cy={100 + i * 32} r="4" fill="#22D3EE">
              <animate attributeName="opacity" values=".25;1;.25" dur="2.5s" begin={`${i * 0.25}s`} repeatCount="indefinite" />
            </circle>
            <text x="304" y={104 + i * 32} fontSize="11" fill="#E2E8F0">{c}</text>
          </g>))}
        <g><rect x="600" y="60" width="104" height="52" rx="14" fill="#06B6D4" fillOpacity=".14" stroke="#22D3EE" />
          <text x="652" y="83" fontSize="11" fontWeight="800" fill="#A5F3FC" textAnchor="middle" letterSpacing="1">APPROVED</text>
          <text x="652" y="99" fontSize="10.5" fill="#CFFAFE" textAnchor="middle">tool executes</text></g>
        <g><rect x="600" y="188" width="104" height="52" rx="14" fill="#E11D48" fillOpacity=".14" stroke="#FB7185" />
          <text x="652" y="211" fontSize="11" fontWeight="800" fill="#FECDD3" textAnchor="middle" letterSpacing="1">BLOCKED</text>
          <text x="652" y="227" fontSize="10.5" fill="#FFE4E6" textAnchor="middle">before execution</text></g>
        <circle r="5" fill="#22D3EE"><animateMotion dur="3.6s" repeatCount="indefinite" path="M110 150 H470 C530 150 540 86 600 86" /></circle>
        <circle r="5" fill="#FB7185" opacity="0"><set attributeName="opacity" to="1" begin="1.8s" /><animateMotion dur="3.6s" begin="1.8s" repeatCount="indefinite" path="M110 150 H470 C530 150 540 214 600 214" /></circle>
      </svg>
    </div>);
}

/* ---------------- Section 6: scroll-driven workflow ---------------- */
const STEP_ICONS = [FileSearch, GitBranch, ShieldCheck, Link2];
export function WorkflowScroll() {
  const [active, setActive] = useState(0);
  const refs = useRef<(HTMLDivElement | null)[]>([]);
  useEffect(() => {
    if (!("IntersectionObserver" in window)) return;
    const io = new IntersectionObserver((es) => {
      for (const e of es) if (e.isIntersecting) setActive(Number((e.target as HTMLElement).dataset.i));
    }, { rootMargin: "-45% 0px -45% 0px" });
    refs.current.forEach((r) => r && io.observe(r));
    return () => io.disconnect();
  }, []);
  return (
    <div className="grid gap-10 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:gap-16">
      <div className="hidden lg:block">
        <div className="sticky top-28 rounded-[28px] border border-site-line bg-white p-8 shadow-soft">
          <p className="font-mono text-[11px] uppercase tracking-[.2em] text-site-mute">Trust-to-execution pipeline</p>
          <div className="relative mt-6">
            <span aria-hidden className="absolute bottom-6 left-6 top-6 w-px bg-site-line" />
            <span aria-hidden className="absolute left-6 top-6 w-px bg-gradient-to-b from-site-blue to-site-cyan transition-[height] duration-700 ease-out"
              style={{ height: `calc(${(active / (WORKFLOW.length - 1)) * 100}% - ${active === WORKFLOW.length - 1 ? 48 : 24}px)` }} />
            {WORKFLOW.map((w, i) => {
              const Icon = STEP_ICONS[i]; const on = i <= active;
              return (
                <div key={w.k} className="relative flex items-center gap-4 py-4">
                  <span className={`relative z-10 grid h-12 w-12 place-items-center rounded-2xl border transition-all duration-500 ${i === active ? "scale-105 border-site-blue bg-site-blue text-white shadow-ring" : on ? "border-site-blue/30 bg-site-blue/[.06] text-site-blue" : "border-site-line bg-white text-site-mute"}`}>
                    <Icon className="h-5 w-5" /></span>
                  <div><p className={`font-mono text-[11px] font-semibold tracking-[.18em] transition-colors ${on ? "text-site-blue" : "text-site-mute"}`}>{String(i + 1).padStart(2, "0")} · {w.k}</p>
                    <p className={`text-sm font-medium transition-colors ${i === active ? "text-site-ink" : "text-site-mute"}`}>{w.t}</p></div>
                </div>);
            })}
          </div>
          <div className="mt-6 rounded-2xl bg-site-mist p-4 font-mono text-[11.5px] leading-relaxed text-site-mute">
            evaluate → <span className="text-site-ink">grant</span> → execute(gate_evaluation_id, grant_id) → <span className="text-site-ink">proof</span>
          </div>
        </div>
      </div>
      <div className="space-y-6 lg:space-y-0">
        {WORKFLOW.map((w, i) => {
          const Icon = STEP_ICONS[i];
          return (
            <div key={w.k} data-i={i} ref={(el) => { refs.current[i] = el; }} className="lg:flex lg:min-h-[52vh] lg:items-center">
              <div className={`reveal relative w-full rounded-3xl border bg-white p-6 transition-all duration-500 sm:p-8 ${i === active ? "lg:border-site-blue/30 lg:shadow-lift" : "border-site-line lg:opacity-60"}`}>
                <div className="flex items-center gap-3">
                  <span className="grid h-10 w-10 place-items-center rounded-xl bg-site-blue/[.08] text-site-blue lg:hidden"><Icon className="h-5 w-5" /></span>
                  <p className="font-mono text-xs font-semibold tracking-[.2em] text-site-blue">STEP {i + 1} · {w.k}</p>
                </div>
                <h3 className="mt-3 text-2xl font-semibold tracking-tight text-site-ink">{w.t}</h3>
                <p className="mt-3 leading-relaxed text-site-mute">{w.d}</p>
              </div>
            </div>);
        })}
      </div>
    </div>);
}

/* ---------------- Section 7: data-flow between modules ---------------- */
const FLOW = [
  { n: "Inspector", icon: FileSearch, art: "findings{ domains, commands, secrets }" },
  { n: "Provenance", icon: GitBranch, art: "lineage[ id:EFFECTIVE_TRUST ]" },
  { n: "Execution Gate", icon: ShieldCheck, art: "verdict + rule_ids + grant" },
  { n: "Verifiable Proof", icon: Link2, art: "sha256(prev ‖ record)" },
];
export function DataFlow() {
  const [ref, inView] = useInView<HTMLDivElement>();
  return (
    <div ref={ref} data-paused={!inView} className="relative">
      <div className="grid gap-4 md:grid-cols-4 md:gap-0">
        {FLOW.map((f, i) => {
          const Icon = f.icon;
          return (
            <div key={f.n} className="reveal relative md:px-3" style={{ ["--d" as string]: `${i * 110}ms` }}>
              {i < FLOW.length - 1 && (
                <svg aria-hidden className="absolute left-1/2 top-[calc(100%-4px)] h-8 w-2 -translate-x-1/2 md:left-[calc(100%-12px)] md:top-[42px] md:h-2 md:w-6 md:translate-x-0" viewBox="0 0 24 8" preserveAspectRatio="none">
                  <path d="M0 4 H24" stroke="#1F5BFF" strokeWidth="2" className="flow-dash" vectorEffect="non-scaling-stroke" />
                </svg>)}
              <div className="group rounded-3xl border border-white/10 bg-white/[.04] p-5 transition duration-500 hover:border-cyan-300/40 hover:bg-white/[.07]">
                <div className="flex items-center gap-3">
                  <span className="grid h-11 w-11 place-items-center rounded-2xl bg-gradient-to-br from-site-blue to-site-cyan text-white shadow-[0_10px_30px_-10px_rgba(6,182,212,.7)] transition-transform duration-500 group-hover:-rotate-6 group-hover:scale-105">
                    <Icon className="h-5 w-5" /></span>
                  <div><p className="font-mono text-[10.5px] tracking-[.18em] text-cyan-300">0{i + 1}</p><p className="font-semibold text-white">{f.n}</p></div>
                </div>
                <div className="mt-4 rounded-xl border border-white/10 bg-black/20 px-3 py-2 font-mono text-[11px] text-cyan-100">
                  <span className="text-slate-500">emits </span>{f.art}</div>
              </div>
            </div>);
        })}
      </div>
    </div>);
}

/* ---------------- Section 8: proof preview (ILLUSTRATIVE) ---------------- */
const SAMPLE = [
  { n: 1, v: "BLOCK", r: "R1_DEST_NOT_APPROVED", h: "8f2c…41aa", p: "0000…0000" },
  { n: 2, v: "ALLOW", r: "-", h: "1b9e…07c3", p: "8f2c…41aa" },
  { n: 3, v: "EXECUTED", r: "-", h: "c47a…9d10", p: "1b9e…07c3" },
];
export function ProofPreview() {
  return (
    <div className="relative">
      <div className="flex items-center gap-2"><span className="rounded-full border border-amber-300/60 bg-amber-50 px-2.5 py-0.5 font-mono text-[10.5px] font-bold tracking-[.16em] text-amber-800">ILLUSTRATIVE EXAMPLE</span>
        <span className="text-xs text-site-mute">Structure only; hashes are shortened placeholders.</span></div>
      <div className="mt-5 flex flex-col items-stretch gap-3 md:flex-row md:items-center">
        {SAMPLE.map((s, i) => (
          <div key={s.n} className="reveal flex flex-1 flex-col items-stretch gap-3 md:flex-row md:items-center" style={{ ["--d" as string]: `${i * 120}ms` }}>
            <div className="flex-1 rounded-2xl border border-site-line bg-white p-4 shadow-soft transition duration-500 hover:-translate-y-0.5 hover:shadow-lift">
              <div className="flex items-center justify-between font-mono text-[11px]"><span className="text-site-mute">record #{s.n}</span>
                <span className={`font-bold ${s.v === "BLOCK" ? "text-rose-600" : s.v === "ALLOW" ? "text-cyan-700" : "text-site-blue"}`}>{s.v}</span></div>
              <dl className="mt-3 space-y-1 font-mono text-[11px]">
                <div className="flex justify-between gap-2"><dt className="text-site-mute">rule</dt><dd className="truncate text-site-ink">{s.r}</dd></div>
                <div className="flex justify-between gap-2"><dt className="text-site-mute">prev</dt><dd className="text-site-ink">{s.p}</dd></div>
                <div className="flex justify-between gap-2"><dt className="text-site-mute">hash</dt><dd className="text-site-blue">{s.h}</dd></div>
              </dl>
            </div>
            {i < SAMPLE.length - 1 && <span aria-hidden className="self-center font-mono text-site-blue/60 md:rotate-0">→</span>}
          </div>))}
      </div>
    </div>);
}

export function AgentBadge() {
  return <span className="inline-flex items-center gap-1.5 rounded-full border border-site-line bg-white px-3 py-1 text-xs font-medium text-site-mute shadow-sm"><Bot className="h-3.5 w-3.5 text-site-blue" />Built for agents that call real tools</span>;
}
