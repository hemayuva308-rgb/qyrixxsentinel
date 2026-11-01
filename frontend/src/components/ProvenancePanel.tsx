"use client";
import { useState } from "react";
import { api, S } from "@/lib/api";
import type { Step } from "@/lib/types";
import { Badge, Btn, Card, Empty, ErrorBox, Loading, Mono, labelTone, useToast } from "./ui";

export default function ProvenancePanel({ steps, error, loading, reload }: { steps: Step[] | null; error: string | null; loading: boolean; reload: () => void }) {
  const toast = useToast();
  const [f, setF] = useState({ label: "untrusted", text: "" });
  const [parents, setParents] = useState("");
  const [busy, setBusy] = useState(false);
  async function add() {
    if (!f.text.trim()) return toast("err", "Describe the instruction source");
    const ps = parents.split(",").map((x) => x.trim()).filter(Boolean).map(Number);
    if (ps.some((n) => !Number.isInteger(n) || n < 1)) return toast("err", "Parents must be step ids, e.g. 3,4");
    setBusy(true);
    try { const s = await api<Step>(`${S}/provenance/step`, { method: "POST", body: { source: "operator-console", label: f.label, text: f.text, parents: ps } });
      toast("ok", `Step #${s.id} labelled ${s.label}${s.tainted ? " (tainted)" : ""}`); setF({ ...f, text: "" }); setParents(""); reload(); }
    catch (e) { toast("err", (e as Error).message); } finally { setBusy(false); }
  }
  const n = steps?.length ?? 0;
  return (
    <Card title="TRUST PROVENANCE" right={<Badge>{n}/50 memory</Badge>}>
      <div className="grid grid-cols-[120px_1fr] gap-2">
        <select aria-label="label" value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })}><option>approved</option><option>untrusted</option><option>unverified</option></select>
        <input aria-label="source text" placeholder="instruction / source description" value={f.text} maxLength={500} onChange={(e) => setF({ ...f, text: e.target.value })} />
      </div>
      <div className="mt-2 flex gap-2"><input aria-label="parents" placeholder="parent step ids (optional): 3,4" value={parents} onChange={(e) => setParents(e.target.value)} />
        <Btn kind="ghost" loading={busy} onClick={add}>ADD</Btn></div>
      <div className="mt-3 h-1.5 overflow-hidden rounded bg-white/10"><div className="h-full bg-neon" style={{ width: `${(n / 50) * 100}%` }} /></div>
      <div className="mt-3 max-h-56 space-y-1.5 overflow-auto">
        {loading ? <Loading /> : error ? <ErrorBox msg={error} retry={reload} /> : !n ? <Empty text="No provenance steps" /> : [...steps!].reverse().map((s) => (
          <div key={s.id} className="flex items-start gap-2 text-xs"><Mono>#{s.id}</Mono><Badge t={labelTone(s.label)}>{s.label}</Badge>
            {s.tainted && <Badge t="crit">tainted</Badge>}<span className="text-mute">{s.text}{s.parents.length ? ` <- ${s.parents.join(",")}` : ""}</span></div>))}
      </div>
    </Card>);
}
