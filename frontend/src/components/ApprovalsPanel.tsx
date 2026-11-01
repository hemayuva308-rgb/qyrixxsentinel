"use client";
import { useState } from "react";
import { Check, X } from "lucide-react";
import { api, S } from "@/lib/api";
import type { Approval } from "@/lib/types";
import { Badge, Btn, Card, Empty, ErrorBox, Loading, Mono, useToast } from "./ui";

const tone = { pending: "warn", approved: "ok", denied: "crit" } as const;

export default function ApprovalsPanel({ items, error, loading, role, reload }: { items: Approval[] | null; error: string | null; loading: boolean; role: string; reload: () => void }) {
  const toast = useToast();
  const [f, setF] = useState({ method: "DELETE", dest: "https://api.render.com/v1/services/1", data: "" });
  const [busy, setBusy] = useState<string | null>(null);
  async function create() {
    if (!f.dest.trim()) return toast("err", "Destination is required");
    setBusy("new");
    try { const a = await api<Approval>(`${S}/approvals`, { method: "POST", body: { tool: "http", ...f, requested_by: "operator-console" } }); toast("ok", `Approval ${a.id} requested`); reload(); }
    catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); }
  }
  async function decide(a: Approval, d: "approve" | "deny") {
    if (!confirm(`${d.toUpperCase()} ${a.id}?\n${a.scope.method} ${a.scope.dest}\nThis approval is exact-scope, single-use and expires at ${a.expires_at}.`)) return;
    setBusy(a.id);
    try { await api(`${S}/approvals/${a.id}/${d}`, { method: "POST" }); toast("ok", `${a.id} ${d}d`); reload(); }
    catch (e) { toast("err", (e as Error).message); } finally { setBusy(null); }
  }
  return (
    <Card title="APPROVALS" right={<Badge t="warn">{items?.filter((a) => a.status === "pending").length ?? 0} pending</Badge>}>
      <div className="mb-3 grid grid-cols-[90px_1fr] gap-2">
        <select aria-label="method" value={f.method} onChange={(e) => setF({ ...f, method: e.target.value })}>{["DELETE", "POST", "PUT", "GET"].map((m) => <option key={m}>{m}</option>)}</select>
        <input aria-label="destination" value={f.dest} onChange={(e) => setF({ ...f, dest: e.target.value })} />
      </div>
      <Btn kind="ghost" onClick={create} loading={busy === "new"}>REQUEST APPROVAL</Btn>
      <div className="mt-3 max-h-72 space-y-2 overflow-auto">
        {loading ? <Loading /> : error ? <ErrorBox msg={error} retry={reload} /> : !items?.length ? <Empty text="No approval requests" /> : items.map((a) => (
          <div key={a.id} className="rounded-lg border border-white/10 bg-bg2 p-2.5">
            <div className="flex items-center justify-between"><Mono>{a.id}</Mono>
              <Badge t={tone[a.status]}>{a.status.toUpperCase()}{a.used ? " - USED" : ""}</Badge></div>
            <p className="mt-1 text-xs text-mute"><b className="text-ink">{a.scope.method}</b> <Mono>{a.scope.dest}</Mono></p>
            <p className="text-[11px] text-mute">expires {new Date(a.expires_at).toLocaleTimeString()}{a.decided_by ? ` - decided by ${a.decided_by}` : ""}</p>
            {a.status === "pending" && (
              <div className="mt-2 flex gap-2">
                <Btn kind="primary" disabled={role !== "admin"} loading={busy === a.id} onClick={() => decide(a, "approve")} title={role !== "admin" ? "admin role required" : ""}><Check className="h-3.5 w-3.5" />Approve</Btn>
                <Btn kind="danger" disabled={role !== "admin"} loading={busy === a.id} onClick={() => decide(a, "deny")}><X className="h-3.5 w-3.5" />Deny</Btn>
              </div>)}
          </div>))}
      </div>
    </Card>);
}
