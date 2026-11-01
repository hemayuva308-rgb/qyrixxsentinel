"use client";
import { api, S } from "@/lib/api";
import type { Approval, Status, Step } from "@/lib/types";
import Navbar from "@/components/Navbar";
import Kpis from "@/components/Kpis";
import GateChecker from "@/components/GateChecker";
import ApprovalsPanel from "@/components/ApprovalsPanel";
import ProvenancePanel from "@/components/ProvenancePanel";
import InspectorPanel from "@/components/InspectorPanel";
import DecisionFeed from "@/components/DecisionFeed";
import { ErrorBox, usePoll } from "@/components/ui";

export default function Dashboard() {
  const st = usePoll(() => api<Status>(`${S}/status`), 4000);
  const pv = usePoll(() => api<{ steps: Step[] }>(`${S}/provenance`), 6000);
  const ap = usePoll(() => api<{ approvals: Approval[] }>(`${S}/approvals`), 4000);
  const refresh = () => { st.reload(); pv.reload(); ap.reload(); };
  return (
    <>
      <Navbar />
      <main className="mx-auto max-w-[1500px] space-y-4 px-4 py-5">
        <div><h1 className="text-xl font-semibold tracking-wide">Operations Dashboard</h1>
          <p className="text-sm text-mute">Deterministic default-deny gate in front of agent tools. Every number here is measured by the backend.</p></div>
        {st.error && <ErrorBox msg={`Backend: ${st.error}`} retry={st.reload} />}
        <Kpis s={st.data} />
        <div className="grid gap-4 xl:grid-cols-3">
          <div className="space-y-4"><GateChecker steps={pv.data?.steps ?? []} approvals={ap.data?.approvals ?? []} onDone={refresh} />
            <InspectorPanel /></div>
          <div className="space-y-4"><DecisionFeed items={st.data?.recent} />
            <ProvenancePanel steps={pv.data?.steps ?? null} error={pv.error} loading={pv.loading} reload={refresh} /></div>
          <div className="space-y-4"><ApprovalsPanel items={ap.data?.approvals ?? null} error={ap.error} loading={ap.loading} role={st.data?.role ?? ""} reload={refresh} /></div>
        </div>
      </main>
    </>);
}
