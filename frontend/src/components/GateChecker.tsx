"use client";
import { useState } from "react";
import { Play } from "lucide-react";
import { api, S } from "@/lib/api";
import { RULE_HELP } from "@/lib/rules";
import type { Approval, GateResult, Step } from "@/lib/types";
import { Badge, Btn, Card, Mono, useToast, verdictTone } from "./ui";

export default function GateChecker({ steps, approvals, onDone }: { steps: Step[]; approvals: Approval[]; onDone: () => void }) {
  const toast = useToast();
  const [f, setF] = useState({ tool: "http", method: "GET", dest: "https://api.render.com/v1/services", cmd: "", data: "", approval_id: "", execute: false });
  const [lin, setLin] = useState<number[]>([]);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<GateResult | null>(null);
  const set = (k: string, v: string | boolean) => setF((x) => ({ ...x, [k]: v }));
  const usable = approvals.filter((a) => a.status === "approved" && !a.used);

  async function run() {
    if (f.execute && !confirm("EXECUTE is on: if the gate returns ALLOW, a REAL outbound HTTP request is made to " + f.dest + ". Continue?")) return;
    setBusy(true);
    try {
      const r = await api<GateResult>(`${S}/gate/evaluate`, { method: "POST", body: { ...f, approval_id: f.approval_id || null, lineage: lin } });
      setRes(r); onDone();
      toast(r.verdict === "ALLOW" ? "ok" : "err", `Gate: ${r.verdict}${r.rules.length ? " - " + r.rules[0] : ""}`);
    } catch (e) { toast("err", (e as Error).message); } finally { setBusy(false); }
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
          <div className="flex max-h-20 flex-wrap gap-1 overflow-auto">
            {steps.length === 0 && <span className="text-xs text-mute">no steps yet - add one in Provenance (missing lineage is treated as unverified)</span>}
            {steps.slice(-12).map((s) => (
              <button type="button" key={s.id} aria-pressed={lin.includes(s.id)} onClick={() => setLin((x) => x.includes(s.id) ? x.filter((i) => i !== s.id) : [...x, s.id])}
                className={`rounded border px-1.5 py-0.5 font-mono text-[11px] ${lin.includes(s.id) ? "border-neon bg-neon/15 text-neon" : "border-white/10 text-mute"}`}>#{s.id} {s.label}</button>))}
          </div>
        </div>
        <div><label htmlFor="apr">Approval (approved, unused)</label><select id="apr" value={f.approval_id} onChange={(e) => set("approval_id", e.target.value)}>
          <option value="">none</option>{usable.map((a) => <option key={a.id} value={a.id}>{a.id} - {a.scope.method} {a.scope.dest}</option>)}</select></div>
        <label className="flex items-center gap-2 !mb-0 text-xs"><input type="checkbox" className="!w-auto" checked={f.execute} onChange={(e) => set("execute", e.target.checked)} />
          execute for real if ALLOW (DNS-validated, IP-pinned request)</label>
        <Btn type="submit" loading={busy}><Play className="h-3.5 w-3.5" />CHECK SECURITY</Btn>
      </form>
      {res && (
        <div className={`mt-4 rounded-xl border p-3 ${res.verdict === "ALLOW" ? "border-ok/40 bg-ok/5" : "border-crit/40 bg-crit/5"}`} aria-live="polite">
          <div className="flex items-center gap-2"><Badge t={verdictTone(res.verdict)}>{res.verdict}</Badge>
            <span className="font-mono text-xs text-mute">{res.latency_ms} ms - external calls: {res.external_calls}{res.executed ? ` - executed (status ${res.exec_status})` : ""}</span></div>
          {res.rules.length === 0 ? <p className="mt-2 text-sm text-ok">All deterministic checks passed.</p> : (
            <ul className="mt-2 space-y-1.5">{res.rules.map((r) => (
              <li key={r} className="text-sm"><Badge t="crit">{r}</Badge> <span className="text-mute">{RULE_HELP[r] ?? ""}</span></li>))}</ul>)}
          {res.lineage.length > 0 && <p className="mt-2 text-xs text-mute">lineage: <Mono>{res.lineage.join(", ")}</Mono></p>}
          {res.proof && <p className="mt-1 text-xs text-mute">proof #{res.proof.n}: <Mono>{res.proof.hash.slice(0, 20)}...</Mono></p>}
        </div>)}
    </Card>);
}
