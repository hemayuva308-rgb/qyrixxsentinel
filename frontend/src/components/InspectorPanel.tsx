"use client";
import { useState } from "react";
import { api, S } from "@/lib/api";
import type { Inspect } from "@/lib/types";
import { Badge, Btn, Card, useToast } from "./ui";

export default function InspectorPanel() {
  const toast = useToast();
  const [text, setText] = useState("");
  const [r, setR] = useState<Inspect | null>(null);
  const [busy, setBusy] = useState(false);
  async function run() {
    if (!text.trim()) return toast("err", "Paste a skill / README / config excerpt");
    setBusy(true);
    try { setR(await api<Inspect>(`${S}/inspect`, { method: "POST", body: { text } })); } catch (e) { toast("err", (e as Error).message); } finally { setBusy(false); }
  }
  const row = (k: string, v: string[], t: "crit" | "warn" | "neon") => (
    <div className="flex flex-wrap items-center gap-1 text-xs"><span className="w-24 text-mute">{k}</span>{v.length ? v.map((x) => <Badge key={x} t={t}>{x}</Badge>) : <span className="text-mute">none</span>}</div>);
  return (
    <Card title="SKILL INSPECTOR">
      <textarea aria-label="content to inspect" rows={3} placeholder="Paste skill / README / config text" value={text} maxLength={100000} onChange={(e) => setText(e.target.value)} />
      <div className="mt-2"><Btn kind="ghost" loading={busy} onClick={run}>INSPECT</Btn></div>
      {r && (
        <div className="mt-3 space-y-1.5">
          {row("domains", r.domains, "neon")}{row("unapproved", r.unapproved, "crit")}{row("commands", r.commands, "warn")}{row("secret refs", r.secrets, "crit")}
          <div className="mt-2 rounded-lg border border-white/10 bg-bg2 p-2 text-xs">
            <Badge t={r.classification.label === "benign" ? "ok" : "crit"}>{r.classification.label}</Badge>
            <span className="ml-2 text-mute">{r.classification.explanation}</span>
            <p className="mt-1 text-[11px] text-mute">source: {r.classification.source} - advisory only, never authorises an action</p>
            <p className="mt-1 text-[11px] text-mute" data-testid="ai-meta">
              {r.classification.provider === "heuristic" ? <Badge t="warn">NO LIVE AI - HEURISTIC ONLY</Badge> : <Badge t="ok">LIVE: {r.classification.provider.toUpperCase()}</Badge>}
              <span className="ml-2">provider: {r.classification.provider} | model: {r.classification.model ?? "none"} | latency: {r.classification.latency_ms} ms</span>
            </p>
            {r.classification.attempts.some((x) => !x.ok) && (
              <ul className="mt-1 list-disc pl-4 text-[11px] text-mute">
                {r.classification.attempts.filter((x) => !x.ok).map((x) => <li key={x.provider}>{x.provider}: {x.error} ({x.ms} ms)</li>)}
              </ul>)}
          </div>
        </div>)}
    </Card>);
}
