"use client";
import { useState } from "react";
import { AlertOctagon, CheckCircle2, HelpCircle, PlayCircle, ShieldAlert } from "lucide-react";
import Navbar from "@/components/Navbar";
import { api, S } from "@/lib/api";
import { Badge, Btn, Card, Empty, ErrorBox, Mono, usePoll, useToast } from "@/components/ui";

type Cev = {
  correlation_id: string; adapter: string; adapter_label: string; test_fixture: boolean; channel: string; expected: string;
  decision_verdict: string | null; decision_rules: string[] | null; gate_evaluation_id: string | null; decision_proof_hash: string | null;
  adapter_reported_forwarded: boolean | null; observed: { channel: string; ts: string; evidence: string }[];
  telemetry: { armed: boolean; positive_control: boolean; window_closed: boolean }; window_ms: number;
  result: string; reasons: string[]; ts?: string; hash?: string; n?: number; proof?: { seq: number; hash: string }; observed_at?: string;
};
type Demo = { channel: string; honest: Cev; broken: Cev; chain_verify: { valid: boolean; length?: number; anchor_status?: string } };
type Conf = Record<string, { runs: number; ENFORCEMENT_VERIFIED: number; BYPASS_DETECTED: number; UNAUTHORIZED_EXECUTION: number; INCONCLUSIVE: number; conformance_rate: number | null }>;
type Integ = { id: string; label: string; status: string; notes: string; capabilities: Record<string, boolean | string[]> | null };

const RESULT = {
  ENFORCEMENT_VERIFIED: { t: "ok" as const, icon: CheckCircle2, text: "Decision enforced: no side effect observed" },
  BYPASS_DETECTED: { t: "crit" as const, icon: AlertOctagon, text: "BLOCKED action was executed anyway" },
  UNAUTHORIZED_EXECUTION: { t: "crit" as const, icon: ShieldAlert, text: "Side effect without a matching authorization" },
  INCONCLUSIVE: { t: "warn" as const, icon: HelpCircle, text: "Telemetry insufficient: NOT counted as verified" },
};
const res = (r: string) => RESULT[r as keyof typeof RESULT] ?? RESULT.INCONCLUSIVE;
const short = (h?: string | null) => (h ? h.slice(0, 16) + "…" : "-");

function Outcome({ x, title }: { x: Cev; title: string }) {
  const r = res(x.result); const Icon = r.icon; const bad = x.result === "BYPASS_DETECTED" || x.result === "UNAUTHORIZED_EXECUTION";
  return (
    <div className={`rounded-2xl border p-4 ${bad ? "border-crit/60 bg-crit/10" : x.result === "ENFORCEMENT_VERIFIED" ? "border-ok/40 bg-ok/5" : "border-warn/40 bg-warn/5"}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-semibold">{title}</div>
        {x.test_fixture && <Badge t="warn">CONTROLLED TEST FIXTURE</Badge>}
      </div>
      <div className="mt-1 text-xs text-mute">{x.adapter_label}</div>
      <div className={`mt-3 flex items-center gap-2 text-lg font-semibold ${bad ? "text-crit" : x.result === "ENFORCEMENT_VERIFIED" ? "text-ok" : "text-warn"}`}>
        <Icon className="h-6 w-6" aria-hidden />{x.result}</div>
      <p className="text-xs text-mute">{r.text}{bad ? " — critical security alert raised" : ""}</p>
      <dl className="mt-3 grid grid-cols-[150px_1fr] gap-x-3 gap-y-1.5 text-xs">
        <dt className="text-mute">Expected decision</dt><dd><Badge t="crit">{x.expected}</Badge></dd>
        <dt className="text-mute">Gate decision</dt><dd><Badge t={x.decision_verdict === "BLOCK" ? "crit" : "warn"}>{x.decision_verdict ?? "none"}</Badge> <Mono>{(x.decision_rules ?? []).join(" ")}</Mono></dd>
        <dt className="text-mute">Observed execution</dt><dd>{x.observed.length ? <Badge t="crit">{x.observed.length} side effect(s) on {x.observed[0].channel} canary</Badge> : <Badge t="ok">none in {x.window_ms} ms window</Badge>}</dd>
        <dt className="text-mute">Adapter self-report</dt><dd><Mono>{x.adapter_reported_forwarded === null ? "-" : x.adapter_reported_forwarded ? "forwarded" : "not forwarded"}</Mono> <span className="text-mute">(never trusted)</span></dd>
        <dt className="text-mute">Observer health</dt><dd><Mono>positive control {x.telemetry.positive_control ? "passed" : "FAILED"} · window {x.telemetry.window_closed ? "closed" : "open"}</Mono></dd>
        <dt className="text-mute">Correlation ID</dt><dd><Mono>{x.correlation_id}</Mono></dd>
        <dt className="text-mute">Timestamp</dt><dd><Mono>{x.observed_at ?? x.ts ?? "-"}</Mono></dd>
        <dt className="text-mute">Decision proof</dt><dd><Mono>{short(x.decision_proof_hash)}</Mono></dd>
        <dt className="text-mute">Reconciliation proof</dt><dd><Mono>{x.proof ? `#${x.proof.seq} ${short(x.proof.hash)}` : `${x.n ? "#" + x.n + " " : ""}${short(x.hash)}`}</Mono></dd>
        <dt className="text-mute">Reasons</dt><dd><Mono>{x.reasons.join(" ")}</Mono></dd>
      </dl>
    </div>);
}

export default function Enforcement() {
  const toast = useToast();
  const [demo, setDemo] = useState<Demo | null>(null); const [busy, setBusy] = useState(false);
  const [channel, setChannel] = useState<"http" | "file">("http");
  const rs = usePoll(() => api<{ results: Cev[]; conformance: Conf; window_ms: number }>(`${S}/cev/results`), 5000);
  const ig = usePoll(() => api<{ integrations: Integ[]; test_fixtures_enabled: boolean }>(`${S}/integrations`), 30000);
  async function run() {
    setBusy(true);
    try { setDemo(await api<Demo>(`${S}/cev/demo`, { method: "POST", body: { channel } })); rs.reload(); toast("ok", "Canary sent through both adapters"); }
    catch (e) { toast("err", (e as Error).message); } finally { setBusy(false); }
  }
  return (
    <>
      <Navbar />
      <main className="mx-auto max-w-[1500px] space-y-4 px-4 py-5">
        <div><h1 className="text-xl font-semibold tracking-wide">Continuous Enforcement Verification</h1>
          <p className="text-sm text-mute">A decision says what should happen. An observer outside the Gate's decision path checks what did happen (in v1.5 it runs inside the backend process, so it detects a misbehaving adapter, not a compromised backend). Missing telemetry is never reported as verified.</p></div>
        {rs.error && <ErrorBox msg={`Backend: ${rs.error}`} retry={rs.reload} />}
        <Card title="SIGNATURE DEMO · SAME BLOCK, TWO INTEGRATIONS" right={
          <div className="flex items-center gap-2">
            <select aria-label="Canary channel" value={channel} onChange={(e) => setChannel(e.target.value as "http" | "file")} className="rounded-lg border border-white/10 bg-bg2 px-2 py-1 text-xs">
              <option value="http">HTTP canary</option><option value="file">File canary (write)</option></select>
            <Btn loading={busy} disabled={ig.data ? !ig.data.test_fixtures_enabled : false} onClick={run} title={ig.data && !ig.data.test_fixtures_enabled ? "test fixtures disabled on this server" : ""}><PlayCircle className="h-3.5 w-3.5" />RUN CANARY</Btn>
          </div>}>
          {ig.data && !ig.data.test_fixtures_enabled && <p className="mb-2 text-xs text-warn">Test fixtures are disabled on this server (set QYRIX_CEV_TEST_FIXTURES=1 in an evaluation environment).</p>}
          {!demo ? <Empty text="Send one harmless must-block canary through an honest adapter and a deliberately broken one" /> : (
            <>
              <div className="grid gap-4 lg:grid-cols-2">
                <Outcome x={demo.honest} title="Integration A — honest adapter" />
                <Outcome x={demo.broken} title="Integration B — deliberately broken adapter" />
              </div>
              <p className="mt-3 text-xs">Evidence: hash chain <Badge t={demo.chain_verify.valid ? "ok" : "crit"}>{demo.chain_verify.valid ? "VERIFIED" : "INVALID"}</Badge>
                <span className="ml-2 text-mute">Hash-chain integrity shows the records were not altered after writing. It does not by itself prove an event happened; that evidence comes from the observer.</span></p>
            </>)}
        </Card>
        <div className="grid gap-4 xl:grid-cols-3">
          <Card title="ADAPTER CONFORMANCE (FROM THE PROOF CHAIN)" className="xl:col-span-1">
            {!rs.data || Object.keys(rs.data.conformance).length === 0 ? <Empty text="No canary results yet" /> : (
              <table className="w-full text-left text-xs"><thead className="text-mute"><tr><th className="py-1">Adapter</th><th>Runs</th><th>Verified</th><th>Bypass</th><th>Inconcl.</th><th>Rate</th></tr></thead>
                <tbody>{Object.entries(rs.data.conformance).map(([k, v]) => (
                  <tr key={k} className="border-t border-white/5"><td className="py-1.5"><Mono>{k}</Mono></td><td>{v.runs}</td><td>{v.ENFORCEMENT_VERIFIED}</td><td className={v.BYPASS_DETECTED + v.UNAUTHORIZED_EXECUTION ? "text-crit" : ""}>{v.BYPASS_DETECTED + v.UNAUTHORIZED_EXECUTION}</td><td>{v.INCONCLUSIVE}</td>
                    <td><Badge t={v.conformance_rate === null ? "warn" : v.conformance_rate === 100 ? "ok" : "crit"}>{v.conformance_rate === null ? "n/a" : v.conformance_rate + "%"}</Badge></td></tr>))}</tbody></table>)}
            <p className="mt-2 text-[11px] text-mute">Rate = verified ÷ decided runs. Inconclusive runs are excluded and never counted as success.</p>
          </Card>
          <Card title="RECENT RECONCILIATIONS" className="xl:col-span-2">
            {!rs.data?.results.length ? <Empty text="No reconciliations recorded" /> : (
              <div className="max-h-[360px] overflow-auto"><table className="w-full text-left text-xs"><thead className="sticky top-0 bg-card text-mute"><tr><th className="py-1">Time</th><th>Adapter</th><th>Channel</th><th>Decision</th><th>Observed</th><th>Result</th><th>Correlation</th></tr></thead>
                <tbody>{rs.data.results.map((r) => (
                  <tr key={r.correlation_id} className="border-t border-white/5"><td className="py-1.5"><Mono>{(r.ts ?? "").slice(11, 19)}</Mono></td><td><Mono>{r.adapter}</Mono>{r.test_fixture && <span className="ml-1 text-warn">(fixture)</span>}</td><td>{r.channel}</td>
                    <td><Badge t={r.decision_verdict === "BLOCK" ? "crit" : "warn"}>{r.decision_verdict ?? "none"}</Badge></td><td>{r.observed.length}</td>
                    <td><Badge t={res(r.result).t}>{r.result}</Badge></td><td><Mono>{r.correlation_id.slice(0, 18)}…</Mono></td></tr>))}</tbody></table></div>)}
          </Card>
        </div>
        <Card title="UNIVERSAL ADAPTER REGISTRY (qyrix-adapter-contract/v1)">
          {!ig.data ? <Empty text="Loading integrations" /> : (
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">{ig.data.integrations.map((i) => (
              <div key={i.id} className="rounded-xl border border-white/10 bg-bg2 p-3">
                <div className="flex items-center justify-between gap-2"><span className="text-sm font-semibold">{i.label}</span>
                  <Badge t={i.status === "BUILT" ? "ok" : i.status === "TEST_FIXTURE" ? "warn" : "mute"}>{i.status}</Badge></div>
                <p className="mt-1 text-[11px] text-mute">{i.notes}</p>
                {i.capabilities && <p className="mt-1 text-[11px]"><Mono>{Object.entries(i.capabilities).map(([k, v]) => `${k}:${Array.isArray(v) ? v.join("+") || "-" : v ? "yes" : "no"}`).join(" · ")}</Mono></p>}
              </div>))}</div>)}
        </Card>
      </main>
    </>);
}
