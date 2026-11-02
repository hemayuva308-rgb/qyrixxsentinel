"use client";
import { useState } from "react";
import { Ban, Play, Zap } from "lucide-react";
import { api, S } from "@/lib/api";
import { RULE_HELP } from "@/lib/rules";
import type { Approval, ExecResult, GateResult, Step } from "@/lib/types";
import { Badge, Btn, Card, Mono, labelTone, useToast, verdictTone } from "./ui";

// Two-step controlled execution: (1) the Gate evaluates and, on ALLOW, issues a single-use grant;
// (2) execution sends ONLY gate_evaluation_id + grant_id. The server reloads the immutable parameters.
export default function GateChecker({ steps, approvals, onDone }: { steps: Step[]; approvals: Approval[]; onDone: () => void }) {
  const toast = useToast();
  const [f, setF] = useState({ tool: "http", method: "GET", dest: "https://api.render.com/v1/services", cmd: "", data: "", approval_id: "" });
  const [lin, setLin] = useState<string[]>([]);
  const [busy, setBusy] = useState<"eval" | "exec" | "revoke" | null>(null);
  const [res, setRes] = useState<GateResult | null>(null);
  const [ex, setEx] = useState<ExecResult | null>(null);
  const set = (k: string, v: string) => setF((x) => ({ ...x, [k]: v }));
  const usable = approvals.filter((a) => a.status === "approved" && !a.used);

  async function run() {
    setBusy("eval"); setEx(null);
    try {
      const r = await api<GateResult>(`${S}/gate/evaluate`, { method: "POST", body: { ...f, approval_id: f.approval_id || null, lineage: lin } });
      setRes(r); onDone();
      toast(r.verdict === "ALLOW" ? "ok" : "err", `Gate: ${r.verdict}${r.rules.length ? " - " + r.rules[0] : ""}`);
    } catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); }
  }
  async function execute() {
    if (!res?.grant_id) return;
    const real = f.tool === "http";
    if (real && !confirm(`Execute with grant ${res.grant_id.slice(0, 12)}…?\nA REAL outbound ${f.method} request will be made to ${f.dest} (DNS-validated, IP-pinned, redirects not followed).`)) return;
    setBusy("exec");
    try {
      const r = await api<ExecResult>("tools/execute", { method: "POST", body: { gate_evaluation_id: res.gate_evaluation_id, grant_id: res.grant_id } });
      setEx(r); setRes({ ...res, grant_id: null }); onDone();
      toast(r.executed ? "ok" : "err", r.executed ? "Executed through grant" : "Adapter refused / failed");
    } catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); }
  }
  async function revoke() {
    if (!res?.grant_id || !confirm(`Revoke grant ${res.grant_id.slice(0, 12)}…? It can never be executed afterwards.`)) return;
    setBusy("revoke");
    try { await api(`${S}/grants/${res.grant_id}/revoke`, { method: "POST" }); setRes({ ...res, grant_id: null }); onDone(); toast("ok", "Grant revoked (recorded in the proof chain)"); }
    catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); }
  }
  return (
    <Card title="EXECUTION GATE">
      <form onSubmit={(e) => { e.preventDefault(); run(); }} className="space-y-2.5">
        <div className="grid grid-cols-2 gap-2">
          <div><label htmlFor="tool">Tool</label><select id="tool" value={f.tool} onChange={(e) => set("tool", e.target.value)}>
            <option>http</option><option>file.read</option><option>shell</option></select></div>
          <div><label htmlFor="method">Method</label><select id="method" value={f.method} onChange={(e) => set("method", e.target.value)}>
            {["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].map((m) => <option key={m}>{m}</option>)}</select></div>
        </div>
        <div><label htmlFor="dest">Destination (URL or path)</label><input id="dest" value={f.dest} maxLength={2048} onChange={(e) => set("dest", e.target.value)} /></div>
        <div><label htmlFor="cmd">Command (optional)</label><input id="cmd" value={f.cmd} maxLength={4096} onChange={(e) => set("cmd", e.target.value)} /></div>
        <div><label htmlFor="data">Data / body (optional)</label><textarea id="data" rows={2} value={f.data} maxLength={65536} onChange={(e) => set("data", e.target.value)} /></div>
        <div>
          <label>Lineage (provenance steps this action derives from)</label>
          <div className="flex max-h-24 flex-wrap gap-1 overflow-auto">
            {steps.length === 0 && <span className="text-xs text-mute">no steps yet - add one in Provenance (missing lineage is treated as unverified)</span>}
            {steps.slice(-12).map((s) => (
              <button type="button" key={s.id} aria-pressed={lin.includes(s.id)} title={s.id} onClick={() => setLin((x) => x.includes(s.id) ? x.filter((i) => i !== s.id) : [...x, s.id])}
                className={`rounded border px-1.5 py-0.5 font-mono text-[11px] ${lin.includes(s.id) ? "border-neon bg-neon/15 text-neon" : "border-white/10 text-mute"}`}>{s.id.slice(0, 8)} {s.label}</button>))}
          </div>
        </div>
        <div><label htmlFor="apr">Approval (approved, unused)</label><select id="apr" value={f.approval_id} onChange={(e) => set("approval_id", e.target.value)}>
          <option value="">none</option>{usable.map((a) => <option key={a.id} value={a.id}>{a.id} - {a.scope.method} {a.scope.dest}</option>)}</select></div>
        <Btn type="submit" loading={busy === "eval"}><Play className="h-3.5 w-3.5" />CHECK SECURITY</Btn>
      </form>
      {res && (
        <div className={`mt-4 rounded-xl border p-3 ${res.verdict === "ALLOW" ? "border-ok/40 bg-ok/5" : "border-crit/40 bg-crit/5"}`} aria-live="polite">
          <div className="flex flex-wrap items-center gap-2"><Badge t={verdictTone(res.verdict)}>{res.verdict}</Badge>
            <span className="font-mono text-xs text-mute">{res.latency_ms} ms - external calls: {res.external_calls}</span></div>
          {res.rules.length === 0 ? <p className="mt-2 text-sm text-ok">All deterministic checks passed.</p> : (
            <ul className="mt-2 space-y-1.5">{res.rules.map((r) => (
              <li key={r} className="text-sm"><Badge t="crit">{r}</Badge> <span className="text-mute">{RULE_HELP[r] ?? ""}</span></li>))}</ul>)}
          {res.lineage.length > 0 && <p className="mt-2 flex flex-wrap gap-1 text-xs text-mute">lineage: {res.lineage.map((l) => { const [id, lab] = l.split(":");
            return <Badge key={l} t={labelTone(lab)}>{id.slice(0, 8)} {lab}</Badge>; })}</p>}
          <p className="mt-1 text-xs text-mute">evaluation <Mono>{res.gate_evaluation_id.slice(0, 13)}…</Mono>{res.proof && <> · proof #{res.proof.n} <Mono>{res.proof.hash.slice(0, 16)}…</Mono></>}</p>
          {res.grant_id && (
            <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-white/10 pt-3">
              <Btn kind="ghost" loading={busy === "exec"} onClick={execute}><Zap className="h-3.5 w-3.5" />EXECUTE WITH GRANT</Btn>
              <Btn kind="danger" loading={busy === "revoke"} onClick={revoke} title="admin only"><Ban className="h-3.5 w-3.5" />REVOKE</Btn>
              <span className="text-[11px] text-mute">single-use grant <Mono>{res.grant_id.slice(0, 12)}…</Mono>, expires {res.grant_expires_at ? new Date(res.grant_expires_at).toLocaleTimeString() : "-"}</span>
            </div>)}
        </div>)}
      {ex && (
        <div className="mt-3 rounded-xl border border-neon/30 bg-neon/5 p-3 text-xs" aria-live="polite">
          <div className="flex items-center gap-2"><Badge t={ex.executed ? "neon" : "warn"}>{ex.executed ? "EXECUTED" : "EXECUTION FAILED"}</Badge>
            <span className="font-mono text-mute">adapter {ex.adapter} · external calls {ex.external_calls} · proof #{ex.proof_start.n}{ex.proof_result ? `→#${ex.proof_result.n}` : ""}</span></div>
          <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-bg2 p-2 font-mono text-[11px] text-ink/80">{JSON.stringify(ex.result, null, 2)}</pre>
        </div>)}
    </Card>);
}
