"use client";
import { api, S } from "@/lib/api";
import type { Status } from "@/lib/types";
import Navbar from "@/components/Navbar";
import Kpis from "@/components/Kpis";
import BenchmarkPanel from "@/components/BenchmarkPanel";
import ChainPanel from "@/components/ChainPanel";
import ThreatAlert from "@/components/ThreatAlert";
import DecisionFeed from "@/components/DecisionFeed";
import { Badge, ErrorBox, usePoll } from "@/components/ui";

export default function Forensic() {
  const st = usePoll(() => api<Status>(`${S}/status`), 4000);
  return (
    <>
      <Navbar />
      <main className="mx-auto max-w-[1500px] space-y-4 px-4 py-5">
        <header className="flex flex-wrap items-center gap-3">
          <div><h1 className="text-xl font-semibold tracking-[.2em]">QYRIX SENTINEL <span className="text-neon">LAB</span></h1>
            <p className="text-xs tracking-[.2em] text-mute">AI SECURITY INTELLIGENCE &amp; FORENSIC ANALYSIS</p></div>
          <Badge t="neon">FORENSIC ANALYSIS MODE</Badge>
          {st.data && <Badge t={st.data.proof === "available" ? "ok" : "crit"}>EVIDENCE CHAIN: {st.data.proof === "available" ? "INTACT" : "BROKEN"}</Badge>}
          {st.data?.demo_mode && <Badge t="warn">DEMO/EVAL MODE</Badge>}
        </header>
        {st.error && <ErrorBox msg={`Backend: ${st.error}`} retry={st.reload} />}
        <Kpis s={st.data} />
        <ThreatAlert recent={st.data?.recent} />
        <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
          <BenchmarkPanel demo={!!st.data?.demo_mode} onDone={st.reload} />
          <div className="space-y-4"><ChainPanel status={st.data} /><DecisionFeed items={st.data?.recent} /></div>
        </div>
      </main>
    </>);
}
