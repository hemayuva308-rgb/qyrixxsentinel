"use client";
import { useEffect, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, Fingerprint, Hammer, Loader2, ShieldCheck, ShieldX, XCircle } from "lucide-react";
import { lineageSteps, runDemo, SCENARIOS, type DemoRun, type ScenarioId } from "@/lib/demo";
import { RULE_HELP } from "@/lib/rules";
import { verifyInBrowser, type BrowserVerify } from "@/lib/verify";
import type { Step } from "@/lib/types";

const CATEGORIES: { k: string; rules: string[] }[] = [
  { k: "Destination", rules: ["R1_DEST_NOT_APPROVED", "R9_SSRF_BLOCKED", "R15_REDIRECT_LIMIT", "R16_REDIRECT_INVALID"] },
  { k: "Data", rules: ["R2_SECRET_EXFIL", "R12_SECRET_TO_EXTERNAL"] },
  { k: "Provenance", rules: ["R3_UNTRUSTED_LINEAGE", "R13_LINEAGE_MISSING", "LINEAGE_CYCLE_DETECTED"] },
  { k: "Action / tool", rules: ["R5_COMMAND_INJECTION", "R8_UNSUPPORTED_TOOL", "R10_PATH_NOT_ALLOWED"] },
  { k: "Authorisation", rules: ["R4_APPROVAL_SCOPE_MISMATCH", "R6_APPROVAL_REPLAY", "R7_APPROVAL_REQUIRED", "R14_APPROVAL_EXPIRED"] },
  { k: "Evidence health", rules: ["R0_FAIL_CLOSED", "R11_PROOF_DEGRADED"] },
];
const trustColor = (l: string) => l === "TRUSTED" ? "#22D3EE" : l === "UNTRUSTED" ? "#FB7185" : "#FCD34D";

function PathGraph({ run }: { run: DemoRun }) {
  const lin = lineageSteps(run);
  const blocked = run.gate.verdict === "BLOCK";
  const host = (() => { try { return new URL(run.action.dest.replace(/^hxxp/, "http").replace(/\[\.\]/g, ".")).hostname; } catch { return run.action.dest.slice(0, 28); } })();
  const nodes: { label: string; sub: string; color: string }[] = [
    ...lin.map((s: Step) => ({ label: s.source.length > 20 ? s.source.slice(0, 19) + "…" : s.source, sub: s.declared_label !== s.label ? `${s.declared_label} → ${s.label}` : s.label, color: trustColor(s.label) })),
    { label: "AI agent", sub: `${run.action.method} ${run.action.tool}`, color: "#93C5FD" },
    { label: "Execution Gate", sub: run.gate.verdict, color: blocked ? "#FB7185" : "#22D3EE" },
    { label: host, sub: blocked ? "never contacted" : "sandbox adapter", color: blocked ? "#64748B" : "#22D3EE" },
  ];
  const W = 760, PAD = 78, step = (W - 2 * PAD) / (nodes.length - 1);
  return (
    <svg viewBox={`0 0 ${W} 150`} className="h-auto w-full min-w-[560px]" role="img" aria-label={`Path: ${nodes.map((n) => n.label).join(" to ")}. ${blocked ? "Blocked at the gate; the destination was never contacted." : "Allowed."}`}>
      {nodes.slice(0, -1).map((n, i) => {
        const x1 = PAD + i * step, x2 = PAD + (i + 1) * step;
        const cut = blocked && i === nodes.length - 2;
        return (
          <g key={i}>
            <line x1={x1 + 14} y1="56" x2={x2 - 14} y2="56" stroke={cut ? "#FB7185" : nodes[i].color} strokeOpacity={cut ? .5 : .7} strokeWidth="2" strokeDasharray={cut ? "3 6" : "5 6"} className={cut ? "" : "flow-dash"} />
            {cut && <g transform={`translate(${(x1 + x2) / 2} 56)`}><circle r="11" fill="#1F0A14" stroke="#FB7185" /><path d="M-4 -4 L4 4 M4 -4 L-4 4" stroke="#FB7185" strokeWidth="2" strokeLinecap="round" /></g>}
          </g>);
      })}
      {nodes.map((n, i) => (
        <g key={i} transform={`translate(${PAD + i * step} 56)`}>
          {/* positioning and entrance animation live on separate groups: a CSS transform would override the SVG one */}
          <g className="pop" style={{ ["--d" as string]: `${i * 90}ms`, transformBox: "fill-box", transformOrigin: "center" }}>
            <circle r="14" fill="#0B1630" stroke={n.color} strokeWidth="2" />
            <circle r="4.5" fill={n.color} />
            <text y="36" textAnchor="middle" fontSize="11" fontWeight="600" fill="#E2E8F0">{n.label}</text>
            <text y="51" textAnchor="middle" fontSize="9.5" fill={n.color} fontFamily="ui-monospace,monospace">{n.sub}</text>
          </g>
        </g>))}
    </svg>);
}

export default function ForensicExplorer() {
  const [sc, setSc] = useState<ScenarioId>("direct");
  const [run, setRun] = useState<DemoRun | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [bv, setBv] = useState<BrowserVerify | null>(null);
  const [tv, setTv] = useState<BrowserVerify | null>(null);
  const gen = useRef(0);

  async function load(id: ScenarioId) {
    const my = ++gen.current; setSc(id); setBusy(true); setErr(null); setBv(null); setTv(null);
    try { const r = await runDemo(id); if (my === gen.current) setRun(r); }
    catch (e) { if (my === gen.current) { setRun(null); setErr((e as Error).message); } }
    finally { if (my === gen.current) setBusy(false); }
  }
  useEffect(() => { load("direct"); }, []);

  async function verify() { if (run) setBv(await verifyInBrowser(run.proof.chain)); }
  async function tamper() {
    if (!run) return;
    const copy = JSON.parse(JSON.stringify(run.proof.chain));
    copy[0].verdict = copy[0].verdict === "BLOCK" ? "ALLOW" : "BLOCK";
    setTv(await verifyInBrowser(copy));
  }

  // Backend timestamps carry microseconds; Date() keeps only milliseconds, so combine both for a meaningful timeline.
  const micros = (ts: string) => Math.floor(Date.parse(ts) / 1000) * 1e6 + Number((ts.match(/\.(\d+)/)?.[1] ?? "0").padEnd(6, "0").slice(0, 6));
  const t0 = run?.proof.chain[0] ? micros(run.proof.chain[0].ts) : 0;
  const followId = run?.followup?.gate.gate_evaluation_id;
  return (
    <div className="overflow-hidden rounded-[28px] border border-white/10 bg-site-deep text-slate-100 shadow-[0_40px_80px_-40px_rgba(6,14,36,.8)]">
      <div className="flex flex-wrap items-center gap-2 border-b border-white/10 px-5 py-4 sm:px-7">
        <span className="rounded-full border border-amber-300/40 bg-amber-300/10 px-2.5 py-1 font-mono text-[10.5px] font-bold tracking-[.16em] text-amber-200">SIMULATED DEMO</span>
        <span className="rounded-full border border-cyan-300/30 bg-cyan-300/10 px-2.5 py-1 font-mono text-[10.5px] font-bold tracking-[.16em] text-cyan-200">REAL GATE EVALUATION</span>
        <div className="ml-auto flex flex-wrap gap-1.5" role="tablist" aria-label="Forensic case">
          {SCENARIOS.map((s) => (
            <button key={s.id} role="tab" aria-selected={sc === s.id} onClick={() => load(s.id)}
              className={`rounded-full px-3 py-1.5 text-xs font-semibold transition ${sc === s.id ? "bg-white text-site-ink" : "text-slate-300 hover:bg-white/10"}`}>{s.short}</button>))}
        </div>
      </div>

      <div className="p-5 sm:p-7" aria-live="polite" aria-busy={busy}>
        {busy && !run && <div className="grid h-80 place-items-center"><Loader2 className="h-6 w-6 animate-spin text-cyan-300" /></div>}
        {err && <div role="alert" className="flex gap-2 rounded-2xl border border-rose-400/40 bg-rose-500/10 p-4 text-sm text-rose-100"><AlertTriangle className="h-4 w-4" />No data: {err}</div>}
        {run && (
          <div className={`space-y-5 transition-opacity duration-300 ${busy ? "opacity-50" : ""}`}>
            {/* summary */}
            <div className="grid gap-3 md:grid-cols-5">
              {[["Agent action", `${run.action.method} · ${run.action.tool}`], ["Origin", `${run.instruction.source}`], ["Declared trust", run.instruction.declared_label],
                ["Destination", run.action.dest], ["Operation data", run.action.data ?? "none"]].map(([k, v]) => (
                <div key={k} className="min-w-0 rounded-2xl border border-white/10 bg-white/[.03] p-3">
                  <p className="font-mono text-[10px] uppercase tracking-[.16em] text-slate-400">{k}</p>
                  <p className="mt-1 truncate font-mono text-[12px] text-white" title={v}>{v}</p></div>))}
            </div>

            {/* path */}
            <section className="rounded-2xl border border-white/10 bg-black/20 p-4" aria-label="Provenance and exfiltration path">
              <div className="flex items-center justify-between"><h4 className="text-sm font-semibold">Trust provenance → execution path</h4>
                <span className="font-mono text-[10.5px] text-slate-400">from real lineage ids</span></div>
              <div className="mt-2 overflow-x-auto" data-paused={busy}><PathGraph run={run} /></div>
            </section>

            <div className="grid gap-5 lg:grid-cols-2">
              {/* policy */}
              <section className="rounded-2xl border border-white/10 bg-white/[.03] p-4" aria-label="Policy evaluation">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-semibold">Policy evaluation</h4>
                  <span className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-extrabold tracking-[.16em] ${run.gate.verdict === "ALLOW" ? "bg-cyan-400/15 text-cyan-200" : "bg-rose-500/15 text-rose-200"}`}>
                    {run.gate.verdict === "ALLOW" ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldX className="h-3.5 w-3.5" />}{run.gate.verdict}</span>
                </div>
                <ul className="mt-3 space-y-1.5">
                  {CATEGORIES.map((c) => {
                    const hit = run.gate.rules.filter((r) => c.rules.includes(r));
                    return (
                      <li key={c.k} className="flex items-start gap-2 text-xs">
                        {hit.length ? <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-300" /> : <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-300" />}
                        <span className="w-28 shrink-0 text-slate-300">{c.k}</span>
                        <span className={hit.length ? "text-rose-200" : "text-slate-500"}>{hit.length ? hit.map((h) => `${h} - ${RULE_HELP[h] ?? ""}`).join(" ") : "no rule triggered"}</span>
                      </li>);
                  })}
                </ul>
                <p className="mt-3 text-[11px] text-slate-400">Advisory classifier: <b className="text-slate-200">{run.inspection.classification.label}</b> ({run.inspection.classification.provider}). Not an input to the decision.</p>
              </section>

              {/* timeline */}
              <section className="rounded-2xl border border-white/10 bg-white/[.03] p-4" aria-label="Event timeline">
                <h4 className="text-sm font-semibold">Event timeline</h4>
                <ol className="relative mt-3 space-y-2.5 border-l border-white/10 pl-4">
                  {run.proof.chain.map((p) => (
                    <li key={p.n} className="relative text-xs">
                      <span className={`absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full ${p.verdict === "BLOCK" ? "bg-rose-400" : p.verdict === "ALLOW" ? "bg-cyan-300" : "bg-site-blue"}`} />
                      <span className="font-mono text-slate-500">+{(Math.max(0, micros(p.ts) - t0) / 1000).toFixed(3)} ms</span>{" "}
                      <b className="text-slate-100">{p.verdict}</b> <span className="text-slate-400">{p.kind === "execution" ? "execution event" : `gate decision · ${p.method ?? ""} ${p.tool}`}{p.gate_evaluation_id && p.gate_evaluation_id === followId ? " · independent safe task" : ""}</span>
                      {p.rule_ids.length > 0 && <span className="text-rose-200"> · {p.rule_ids.join(", ")}</span>}
                    </li>))}
                </ol>
              </section>
            </div>

            {/* evidence */}
            <section className="rounded-2xl border border-white/10 bg-white/[.03] p-4" aria-label="Evidence records">
              <div className="flex flex-wrap items-center gap-2">
                <h4 className="text-sm font-semibold">Evidence records</h4>
                <span className="font-mono text-[10.5px] text-slate-400">server: {run.proof.verify.status}</span>
                <div className="ml-auto flex flex-wrap gap-2">
                  <button onClick={verify} className="inline-flex items-center gap-1.5 rounded-full border border-cyan-300/40 bg-cyan-300/10 px-3 py-1.5 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-300/20"><Fingerprint className="h-3.5 w-3.5" />Verify in your browser</button>
                  <button onClick={tamper} className="inline-flex items-center gap-1.5 rounded-full border border-white/15 px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:bg-white/10"><Hammer className="h-3.5 w-3.5" />Tamper a copy</button>
                </div>
              </div>
              {(bv || tv) && (
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  {bv && <p className={`rounded-lg border px-3 py-2 text-xs ${bv.status === "FAIL" ? "border-rose-400/40 bg-rose-500/10 text-rose-100" : "border-amber-300/40 bg-amber-300/10 text-amber-100"}`}>
                    Recomputed in this browser with WebCrypto SHA-256: <b>{bv.status}</b>. {bv.checked} records link correctly; no external anchor, so not PASS.</p>}
                  {tv && <p className="rounded-lg border border-rose-400/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-100">
                    Copy with record #1 verdict flipped: <b>{tv.status}</b> at record #{tv.brokenAt}. The original evidence is unchanged.</p>}
                </div>)}
              <div className="mt-3 overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-[11.5px]">
                  <thead className="font-mono text-[10px] uppercase tracking-[.14em] text-slate-500"><tr><th className="py-1.5">#</th><th>event</th><th>rule</th><th>lineage</th><th>data</th><th>hash</th></tr></thead>
                  <tbody>{run.proof.chain.map((p) => (
                    <tr key={p.n} className="border-t border-white/5 align-top">
                      <td className="py-1.5 font-mono text-slate-500">{p.n}</td>
                      <td className={`font-mono font-semibold ${p.verdict === "BLOCK" ? "text-rose-300" : p.verdict === "ALLOW" ? "text-cyan-300" : "text-slate-200"}`}>{p.verdict}</td>
                      <td className="font-mono text-slate-300">{p.rule_ids.join(" ") || "-"}</td>
                      <td className="font-mono text-slate-400">{p.lineage?.map((l) => l.slice(0, 8) + ":" + l.split(":")[1]).join(" ") || "-"}</td>
                      <td className="font-mono text-slate-400">{p.data ?? "-"}</td>
                      <td className="font-mono text-site-blue/90">{p.hash.slice(0, 16)}…</td>
                    </tr>))}</tbody>
                </table>
              </div>
            </section>
          </div>)}
      </div>
    </div>);
}
