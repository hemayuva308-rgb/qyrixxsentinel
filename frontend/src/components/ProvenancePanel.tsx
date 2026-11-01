"use client";
import { useState } from "react";
import { api, S } from "@/lib/api";
import type { Step } from "@/lib/types";
import { Badge, Btn, Card, Empty, ErrorBox, Loading, Mono, labelTone, useToast } from "./ui";

export default function ProvenancePanel({ steps, error, loading, reload }: { steps: Step[] | null; error: string | null; loading: boolean; reload: () => void }) {
  const toast = useToast();
  const [f, setF] = useState({ label: "UNTRUSTED", text: "" });
  const [parents, setParents] = useState("");
  const [busy, setBusy] = useState(false);
  async function add() {
    if (!f.text.trim()) return toast("err", "Describe the instruction source");
    const ps = parents.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean)
      .map((p) => steps?.find((s) => s.id === p || s.id.startsWith(p))?.id ?? p);
    if (ps.some((p) => !/^[0-9a-f-]{8,36}$/.test(p))) return toast("err", "Parents must be step ids (UUID or 8-char prefix shown in the list)");
    setBusy(true);
    try { const s = await api<Step>(`${S}/provenance/step`, { method: "POST", body: { source: "operator-console", label: f.label, text: f.text, parents: ps } });
      toast("ok", `Step ${s.id.slice(0, 8)} -> effective ${s.label}${s.declared_label !== s.label ? ` (declared ${s.declared_label}, lowered by lineage)` : ""}`); setF({ ...f, text: "" }); setParents(""); reload(); }
    catch (e) { toast("err", (e as Error).message); } finally { setBusy(false); }
  }
  const n = steps?.length ?? 0;
  return (
    <Card title="TRUST PROVENANCE" right={<Badge>{n}/50 memory</Badge>}>
      <div className="grid grid-cols-[120px_1fr] gap-2">
        <select aria-label="label" value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })}><option>TRUSTED</option><option>UNTRUSTED</option><option>UNVERIFIED</option></select>
        <input aria-label="source text" placeholder="instruction / source description" value={f.text} maxLength={500} onChange={(e) => setF({ ...f, text: e.target.value })} />
      </div>
      <div className="mt-2 flex gap-2"><input aria-label="parents" placeholder="parent step ids (optional): 8-char prefixes, comma separated" value={parents} onChange={(e) => setParents(e.target.value)} />
        <Btn kind="ghost" loading={busy} onClick={add}>ADD</Btn></div>
      <div className="mt-3 h-1.5 overflow-hidden rounded bg-white/10"><div className="h-full bg-neon" style={{ width: `${(n / 50) * 100}%` }} /></div>
      <div className="mt-3 max-h-56 space-y-1.5 overflow-auto">
        {loading ? <Loading /> : error ? <ErrorBox msg={error} retry={reload} /> : !n ? <Empty text="No provenance steps" /> : [...steps!].reverse().map((s) => (
          <div key={s.id} className="flex flex-wrap items-start gap-2 text-xs"><span title={s.id}><Mono>{s.id.slice(0, 8)}</Mono></span>
            {s.declared_label !== s.label && <Badge t={labelTone(s.declared_label)}>declared {s.declared_label}</Badge>}<Badge t={labelTone(s.label)}>{s.label}</Badge>
            {s.unknown_parents?.length > 0 && <Badge t="warn">unknown parent</Badge>}
            <span className="text-mute">{s.text}{s.parents.length ? ` <- ${s.parents.map((p) => p.slice(0, 8)).join(",")}` : ""}</span></div>))}
      </div>
    </Card>);
}
