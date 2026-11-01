"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, CircleDashed, FileSearch, GitBranch, Link2, Loader2, Play, RotateCcw, ShieldCheck, ShieldX, Terminal } from "lucide-react";
import { RULE_HELP } from "@/lib/rules";
import { lineageSteps, runDemo, SCENARIOS, type DemoRun, type ScenarioId } from "@/lib/demo";
import { prefersReducedMotion } from "./motion";

const STAGES = [
  { key: "instruction", label: "Instruction", icon: Terminal },
  { key: "inspector", label: "Skill Inspector", icon: FileSearch },
  { key: "provenance", label: "Trust Provenance", icon: GitBranch },
  { key: "gate", label: "Execution Gate", icon: ShieldCheck },
  { key: "decision", label: "Decision & execution", icon: CheckCircle2 },
  { key: "evidence", label: "Verifiable Proof", icon: Link2 },
] as const;

const labelCls = (l: string) => l === "TRUSTED" ? "border-cyan-400/40 bg-cyan-400/10 text-cyan-200"
  : l === "UNTRUSTED" ? "border-rose-400/40 bg-rose-500/10 text-rose-200" : "border-amber-300/40 bg-amber-400/10 text-amber-200";
const Pill = ({ children, cls }: { children: React.ReactNode; cls: string }) =>
  <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 font-mono text-[10.5px] font-semibold tracking-wide ${cls}`}>{children}</span>;
const Mono = ({ children }: { children: React.ReactNode }) => <code className="break-all font-mono text-[11.5px] text-slate-200">{children}</code>;

function List({ k, v, cls }: { k: string; v: string[]; cls: string }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs"><span className="w-24 shrink-0 text-slate-400">{k}</span>
      {v.length ? v.map((x) => <Pill key={x} cls={cls}>{x}</Pill>) : <span className="text-slate-500">none</span>}</div>);
}

export default function LiveDemo({ compact = false }: { compact?: boolean }) {
  const [active, setActive] = useState<ScenarioId | null>(null);
  const [run, setRun] = useState<DemoRun | null>(null);
  const [shown, setShown] = useState(0);              // number of stages revealed (only ever > 0 after a backend response)
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const gen = useRef(0);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const ctl = useRef<AbortController | null>(null);
  const clear = () => { timers.current.forEach(clearTimeout); timers.current = []; };
  useEffect(() => () => { clear(); ctl.current?.abort(); }, []);

  const start = useCallback(async (id: ScenarioId) => {
    const my = ++gen.current; clear(); ctl.current?.abort(); ctl.current = new AbortController();
    setActive(id); setRun(null); setShown(0); setErr(null); setBusy(true);
    try {
      const r = await runDemo(id, ctl.current.signal);
      if (my !== gen.current) return;
      setRun(r); setBusy(false);
      if (prefersReducedMotion()) { setShown(STAGES.length); return; }
      STAGES.forEach((_, i) => timers.current.push(setTimeout(() => my === gen.current && setShown(i + 1), 120 + i * 430)));
    } catch (e) {
      if (my !== gen.current || (e as Error).name === "AbortError") return;
      setBusy(false); setErr((e as Error).message || "Demo backend unavailable");
    }
  }, []);
  const reset = () => { gen.current++; clear(); ctl.current?.abort(); setActive(null); setRun(null); setShown(0); setErr(null); setBusy(false); };

  const lin = run ? lineageSteps(run) : [];
  const fillers = run ? run.provenance.steps.length - lin.length - (run.followup ? 1 : 0) : 0;
  const verdict = run?.gate.verdict;
  const pct = (shown / STAGES.length) * 100;

  return (
    <div className="relative overflow-hidden rounded-[28px] border border-white/10 bg-site-deep text-slate-100 shadow-[0_40px_80px_-40px_rgba(6,14,36,.8)]">
      <div aria-hidden className="site-grid-dark absolute inset-0 opacity-60" />
      <div aria-hidden className="absolute -right-24 -top-24 h-72 w-72 rounded-full bg-site-blue/25 blur-3xl" />
      <div className="relative">
        {/* header */}
        <div className="flex flex-wrap items-center gap-3 border-b border-white/10 px-5 py-4 sm:px-7">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-300/40 bg-amber-300/10 px-2.5 py-1 font-mono text-[10.5px] font-bold tracking-[.16em] text-amber-200">SIMULATED DEMO</span>
          <span className="text-xs text-slate-400">Real Gate decisions on fixed fixtures · isolated sandbox · no network, files or commands</span>
          {run && <span className="ml-auto font-mono text-[11px] text-slate-400">external calls: <b className="text-white">{run.external_calls}</b> · {run.elapsed_ms} ms server time</span>}
        </div>
        {/* controls */}
        <div className="flex flex-wrap gap-2 px-5 pt-5 sm:px-7" role="group" aria-label="Demo scenarios">
          {SCENARIOS.map((s) => {
            const on = active === s.id;
            const atk = s.id !== "safe";
            return (
              <button key={s.id} type="button" onClick={() => start(s.id)} aria-pressed={on} disabled={busy && on}
                className={`group inline-flex items-center gap-2 rounded-full border px-4 py-2 text-[13px] font-semibold transition duration-300 ease-out active:scale-[.98] disabled:cursor-wait
                  ${on ? (atk ? "border-rose-400/60 bg-rose-500/15 text-white" : "border-cyan-300/60 bg-cyan-400/15 text-white")
                       : "border-white/15 bg-white/[.04] text-slate-200 hover:border-white/30 hover:bg-white/[.08]"}`}>
                {busy && on ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className={`h-3.5 w-3.5 ${atk ? "text-rose-300" : "text-cyan-300"}`} />}
                {compact ? s.short : s.label}
              </button>);
          })}
          <button type="button" onClick={reset} disabled={!active && !err}
            className="inline-flex items-center gap-2 rounded-full border border-white/10 px-4 py-2 text-[13px] font-semibold text-slate-300 transition hover:text-white disabled:opacity-40">
            <RotateCcw className="h-3.5 w-3.5" />Reset Demo</button>
        </div>

        <div className="grid gap-6 p-5 sm:p-7 lg:grid-cols-[220px_1fr]">
          {/* stage rail */}
          <ol className="relative hidden lg:block" aria-label="Pipeline stages">
            <span aria-hidden className="absolute bottom-3 left-[15px] top-3 w-px bg-white/10" />
            <span aria-hidden className="absolute left-[15px] top-3 w-px bg-gradient-to-b from-cyan-300 to-site-blue transition-[height] duration-500 ease-out" style={{ height: `calc(${pct}% - 12px)` }} />
            {STAGES.map((s, i) => {
              const done = i < shown; const Icon = s.icon;
              const waiting = busy && i === 0;
              return (
                <li key={s.key} className="relative flex items-center gap-3 py-2.5">
                  <span className={`relative z-10 grid h-8 w-8 place-items-center rounded-full border transition-colors duration-500
                    ${done ? (s.key === "decision" && verdict === "BLOCK" ? "border-rose-400/70 bg-[#3a1024] text-rose-200" : "border-cyan-300/60 bg-[#0b2a45] text-cyan-200") : "border-white/15 bg-site-deep text-slate-500"}`}>
                    {waiting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Icon className="h-3.5 w-3.5" />}
                  </span>
                  <span className={`text-[13px] font-medium transition-colors duration-500 ${done ? "text-white" : "text-slate-500"}`}>{s.label}</span>
                </li>);
            })}
          </ol>

          {/* stage content */}
          <div className="min-h-[420px]" aria-live="polite" aria-busy={busy}>
            {!active && !err && (
              <div className="grid h-full min-h-[420px] place-items-center rounded-2xl border border-dashed border-white/10 p-8 text-center">
                <div><CircleDashed className="mx-auto h-8 w-8 text-slate-500" />
                  <p className="mt-3 text-sm font-medium text-slate-200">Choose a scenario to send it through the Gate.</p>
                  <p className="mx-auto mt-1 max-w-sm text-xs text-slate-400">Each run creates a fresh isolated sandbox on the server. Results appear only after the backend returns its decision.</p></div>
              </div>)}
            {busy && (
              <div className="grid min-h-[420px] place-items-center rounded-2xl border border-white/10 bg-white/[.02]">
                <div className="text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-cyan-300" />
                  <p className="mt-3 text-sm text-slate-300">Sending scenario to the isolated sandbox…</p>
                  <p className="mt-1 font-mono text-[11px] text-slate-500">awaiting backend decision · nothing is shown until it arrives</p></div>
              </div>)}
            {err && (
              <div role="alert" className="flex items-start gap-3 rounded-2xl border border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-100">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div><b>No result.</b> {err}. The demo shows only real backend decisions, so nothing is displayed when the backend is unavailable.</div>
              </div>)}
            {run && (
              <div className="space-y-3">
                <StageCard show={shown > 0} n={1} title="Instruction received" right={<Pill cls={labelCls(run.instruction.declared_label)}>{run.instruction.declared_label}</Pill>}>
                  <p className="text-xs text-slate-400">source: <Mono>{run.instruction.source}</Mono> · {run.scenario.title}</p>
                  <blockquote className="mt-2 rounded-lg border-l-2 border-white/20 bg-white/[.03] px-3 py-2 text-[13px] italic text-slate-200">“{run.instruction.text}”</blockquote>
                  <p className="mt-2 text-xs text-slate-400">Proposed action: <Mono>{run.action.method} {run.action.dest}{run.action.data ? `  data=${run.action.data}` : ""}</Mono></p>
                </StageCard>

                <StageCard show={shown > 1} n={2} title="Skill Inspector findings">
                  <div className="space-y-1.5">
                    <List k="domains" v={run.inspection.domains} cls="border-white/15 text-slate-200" />
                    <List k="unapproved" v={run.inspection.unapproved} cls="border-rose-400/40 bg-rose-500/10 text-rose-200" />
                    <List k="commands" v={run.inspection.commands} cls="border-amber-300/40 text-amber-200" />
                    <List k="secret refs" v={run.inspection.secrets} cls="border-rose-400/40 text-rose-200" />
                  </div>
                  <p className="mt-2 text-xs text-slate-400">Advisory classifier ({run.inspection.classification.provider}): <b className="text-slate-200">{run.inspection.classification.label}</b>
                    {" "}· advisory only, never authorises execution.</p>
                </StageCard>

                <StageCard show={shown > 2} n={3} title="Trust provenance & lineage" right={<span className="font-mono text-[11px] text-slate-400">window {run.provenance.memory_limit} steps</span>}>
                  <ol className="space-y-1.5">
                    {lin.map((s, i) => (
                      <li key={s.id} className="flex flex-wrap items-center gap-2 text-xs">
                        {i > 0 && <span aria-hidden className="text-slate-500">↳</span>}
                        <Mono>{s.id.slice(0, 8)}</Mono><span className="text-slate-400">{s.source}</span>
                        {s.declared_label !== s.label && <><Pill cls={labelCls(s.declared_label)}>declared {s.declared_label}</Pill><span className="text-slate-500">→</span></>}
                        <Pill cls={labelCls(s.label)}>{s.label}</Pill>
                      </li>))}
                  </ol>
                  {fillers > 0 && <p className="mt-2 text-xs text-slate-400">{fillers} routine TRUSTED steps ran in between. The derived step still inherits its ancestor&apos;s trust: trust can only go down.</p>}
                </StageCard>

                <StageCard show={shown > 3} n={4} title="Execution Gate evaluation" right={<span className="font-mono text-[11px] text-slate-400">{run.gate.latency_ms} ms</span>}>
                  <p className="text-xs text-slate-400">Checks destination · action · data · auth · provenance with deterministic policy.</p>
                  {run.gate.rules.length === 0 ? <p className="mt-2 text-sm text-cyan-200">All deterministic checks passed.</p> : (
                    <ul className="mt-2 space-y-1.5">{run.gate.rules.map((r) => (
                      <li key={r} className="text-xs"><Pill cls="border-rose-400/50 bg-rose-500/15 text-rose-200">{r}</Pill> <span className="text-slate-300">{RULE_HELP[r] ?? ""}</span></li>))}</ul>)}
                </StageCard>

                <StageCard show={shown > 4} n={5} title="Decision" tone={verdict === "ALLOW" ? "allow" : "block"}>
                  <div className="flex flex-wrap items-center gap-3">
                    <span className={`inline-flex items-center gap-2 rounded-xl px-3 py-1.5 text-lg font-extrabold tracking-[.18em] ${verdict === "ALLOW" ? "bg-cyan-400/15 text-cyan-200" : "bg-rose-500/15 text-rose-200"}`}>
                      {verdict === "ALLOW" ? <ShieldCheck className="h-5 w-5" /> : <ShieldX className="h-5 w-5" />}{verdict}</span>
                    <span className="text-xs text-slate-300">{run.execution.adapter_invoked
                      ? <>Grant <Mono>{run.gate.grant_id?.slice(0, 12)}…</Mono> consumed → sandbox adapter returned <Mono>{String(run.execution.result?.status)}</Mono> (simulated)</>
                      : <>No grant issued. The adapter was never called.</>}</span>
                  </div>
                  {run.followup && (
                    <p className="mt-3 rounded-lg border border-cyan-300/20 bg-cyan-400/[.06] px-3 py-2 text-xs text-cyan-100">
                      Independent safe task after the block: <b>{run.followup.gate.verdict}</b>{run.followup.execution.adapter_invoked ? " → completed in the sandbox" : ""}. A blocked attack does not stop legitimate work.</p>)}
                </StageCard>

                <StageCard show={shown > 5} n={6} title="Verifiable proof" right={<Pill cls="border-amber-300/40 bg-amber-300/10 text-amber-200">{run.proof.verify.status}</Pill>}>
                  <div className="space-y-1">
                    {run.proof.chain.map((p) => (
                      <div key={p.n} className="grid grid-cols-[28px_1fr] items-center gap-2 text-[11px] sm:grid-cols-[28px_250px_1fr]">
                        <span className="font-mono text-slate-500">#{p.n}</span>
                        <span className={`font-mono font-semibold ${p.verdict === "BLOCK" ? "text-rose-300" : p.verdict === "ALLOW" ? "text-cyan-300" : "text-slate-300"}`}>{p.verdict}{p.rule_ids[0] ? ` · ${p.rule_ids[0]}` : ""}</span>
                        <span className="col-span-2 truncate font-mono text-slate-400 sm:col-span-1">{p.hash.slice(0, 24)}… ← {p.prev.slice(0, 8)}…</span>
                      </div>))}
                  </div>
                  <p className="mt-2 text-xs text-slate-400">{run.proof.verify.length} hash-linked records, chain intact. <b className="text-slate-200">PARTIAL_UNANCHORED</b>: internally consistent, no external anchor. This is not shown as a full PASS. Demo evidence is kept separate from the production audit chain.</p>
                </StageCard>
              </div>)}
          </div>
        </div>
      </div>
    </div>);
}

function StageCard({ show, n, title, right, tone, children }: { show: boolean; n: number; title: string; right?: React.ReactNode; tone?: "allow" | "block"; children: React.ReactNode }) {
  if (!show) return null;
  const border = tone === "allow" ? "border-cyan-300/40" : tone === "block" ? "border-rose-400/50" : "border-white/10";
  return (
    <section className={`pop rounded-2xl border ${border} bg-white/[.035] p-4 backdrop-blur-sm`} aria-label={title}>
      <header className="mb-2 flex items-center gap-2">
        <span className="grid h-5 w-5 place-items-center rounded-full bg-white/10 font-mono text-[10px] text-slate-300">{n}</span>
        <h4 className="text-[13px] font-semibold text-white">{title}</h4><span className="ml-auto">{right}</span>
      </header>
      {children}
    </section>);
}
