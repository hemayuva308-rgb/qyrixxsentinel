"use client";
import { useState } from "react";
import { Anchor as AnchorIcon, Download, FileSearch, Hammer } from "lucide-react";
import { api, S } from "@/lib/api";
import type { AnchorInfo, Approval, Proof, Status, Step, Verify } from "@/lib/types";
import { Badge, Btn, Card, Empty, ErrorBox, Loading, Mono, useToast, usePoll, verdictTone } from "./ui";

function download(name: string, obj: unknown) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" })); a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
function chainLabel(v: Verify | null): [string, "ok" | "warn" | "crit" | "mute"] {
  if (!v) return ["PENDING", "mute"];
  if (!v.valid) return ["FAIL", "crit"];
  return v.status === "PASS" ? ["PASS", "ok"] : ["PARTIAL_UNANCHORED", "warn"];   // PASS only with a verified RFC 3161 anchor on the head
}

export default function ChainPanel({ status }: { status: Status | null }) {
  const toast = useToast();
  const ch = usePoll(() => api<{ chain: Proof[]; verify: Verify }>(`${S}/proofs`), 6000);
  const [v, setV] = useState<Verify | null>(null); const [t, setT] = useState<Verify | null>(null); const [at, setAt] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const an = usePoll(() => api<AnchorInfo>(`${S}/proofs/anchors`), 15000);
  async function anchorHead() {
    setBusy("a");
    try { const a = await api<{ n: number; serial: string | null }>(`${S}/proofs/anchor`, { method: "POST" }); toast("ok", `Anchored record #${a.n} (TSA serial ${a.serial ?? "-"})`); an.reload(); verify(); }
    catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); }
  }
  const cur = v ?? ch.data?.verify ?? null; const [label, tone] = chainLabel(cur);
  async function verify() { setBusy("v"); try { setV(await api<Verify>(`${S}/proofs/verify`)); setAt(new Date().toLocaleTimeString()); } catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); } }
  async function tamper() { setBusy("t"); try { setT(await api<Verify>(`${S}/proofs/tamper`, { method: "POST" })); } catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); } }
  async function exportBundle() {
    setBusy("e");
    try { download(`qyrix-proof-bundle-${Date.now()}.json`, await api(`${S}/proofs/export`)); toast("ok", "Bundle exported - verify offline with backend/scripts/verify_proof.py"); }
    catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); }
  }
  async function snapshot() {
    setBusy("s");
    try {
      const [s, pr, pv, ap] = await Promise.all([api<Status>(`${S}/status`), api(`${S}/proofs`), api<{ steps: Step[] }>(`${S}/provenance`), api<{ approvals: Approval[] }>(`${S}/approvals`)]);
      download(`forensic-snapshot-${Date.now()}.json`, { generated_at: new Date().toISOString(), status: s, proofs: pr, provenance: pv.steps, approvals: ap.approvals }); toast("ok", "Snapshot downloaded");
    } catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); }
  }
  return (
    <Card title="CHAIN VERIFICATION & EVIDENCE" right={<Badge t={tone}>{label}</Badge>}>
      <div className="grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
        <div><div className="text-mute">Integrity</div><b>{cur ? (cur.valid ? "chain intact" : `broken at #${cur.broken_at}`) : "-"}</b></div>
        <div><div className="text-mute">Events</div><b className="font-mono">{cur?.length ?? "-"}</b></div>
        <div><div className="text-mute">Anchor</div><b>{cur?.anchor_status ?? status?.anchor_status ?? "-"}</b></div>
        <div><div className="text-mute">Last verified (this session)</div><b>{at ?? "not yet"}</b></div>
      </div>
      <p className="mt-2 text-[11px] text-mute">Canonical-JSON SHA-256 hash chain = tamper-evident, not tamper-proof. PASS only when an RFC 3161 timestamp token (verified against the configured TSA CA) covers the current head; otherwise PARTIAL_UNANCHORED.</p>
      <div className="mt-2 rounded-lg border border-white/10 bg-bg2 p-2 text-[11px]">
        <div className="flex flex-wrap items-center gap-2"><Badge t={an.data?.configured ? "neon" : "warn"}>{an.data ? (an.data.configured ? "TSA CONFIGURED" : "ANCHORING NOT CONFIGURED") : "…"}</Badge>
          <span className="text-mute">{an.data?.configured ? <Mono>{an.data.tsa_url}</Mono> : an.data?.problem}</span>
          {cur?.anchored_through ? <span className="text-mute">anchored through #{cur.anchored_through}</span> : null}</div>
        {an.data?.anchors.slice(-3).reverse().map((a) => (
          <p key={a.id} className="mt-1 text-mute">#{a.n} <Mono>{a.head_hash.slice(0, 16)}…</Mono> · {a.gen_time ?? "-"} · serial {a.serial ?? "-"} · <Mono>{a.tsa_url}</Mono></p>))}
        {cur?.anchor_detail && <p className="mt-1 text-mute">{cur.anchor_detail}</p>}
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <Btn kind="ghost" loading={busy === "v"} onClick={verify}><FileSearch className="h-3.5 w-3.5" />VERIFY CHAIN</Btn>
        <Btn kind="ghost" loading={busy === "t"} onClick={tamper}><Hammer className="h-3.5 w-3.5" />SIMULATE TAMPER (COPY)</Btn>
        <Btn kind="ghost" loading={busy === "e"} onClick={exportBundle} disabled={!ch.data?.chain.length}><Download className="h-3.5 w-3.5" />EXPORT PROOF BUNDLE</Btn>
        <Btn kind="ghost" loading={busy === "s"} onClick={snapshot}><Download className="h-3.5 w-3.5" />FORENSIC SNAPSHOT</Btn>
        <Btn kind="ghost" loading={busy === "a"} onClick={anchorHead} disabled={!ch.data?.chain.length} title="admin only; requires a configured RFC 3161 TSA"><AnchorIcon className="h-3.5 w-3.5" />ANCHOR HEAD (RFC 3161)</Btn>
      </div>
      {t && <p className="mt-2 rounded-lg border border-white/10 bg-bg2 p-2 text-xs">Tamper simulation on a copy: chain <b className={t.valid ? "text-crit" : "text-ok"}>{t.valid ? "NOT detected (!)" : `detected - broken at #${t.broken_at}`}</b>. The real chain was not modified.</p>}
      <div className="mt-3 max-h-80 space-y-1.5 overflow-auto">
        {ch.loading ? <Loading /> : ch.error ? <ErrorBox msg={ch.error} retry={ch.reload} /> : !ch.data?.chain.length ? <Empty text="Chain is empty" /> :
          [...ch.data.chain].reverse().map((p) => (
            <div key={p.n} className="grid grid-cols-[40px_150px_1fr] items-center gap-2 rounded-lg border border-white/5 bg-bg2 px-2 py-1.5 text-[11px]">
              <Mono>#{p.n}</Mono><Badge t={verdictTone(p.verdict)}>{p.verdict}</Badge>
              <div className="min-w-0"><Mono>{p.hash.slice(0, 24)}...</Mono> <span className="text-mute">prev {p.prev.slice(0, 10)}... {p.kind === "execution" ? "exec " : ""}{p.rule_ids.join(" ")}</span></div></div>))}
      </div>
    </Card>);
}
