import type { Metadata } from "next";
import { Activity, GitBranch, Link2, ShieldCheck, Waypoints } from "lucide-react";
import ForensicExplorer from "@/components/site/ForensicExplorer";
import { ButtonLink, Container, PageHero, SectionHead, Tag } from "@/components/site/primitives";
import { FinalCta } from "@/components/site/blocks";

export const metadata: Metadata = { title: "Forensic Lab", description: "Explore real Gate decisions, provenance paths and verifiable evidence on fixed sandbox scenarios." };

const LAB = [
  { icon: Activity, t: "Decision feed & latest block", d: "Every decision from the production proof chain, newest first, with rule IDs and blocked destinations." },
  { icon: GitBranch, t: "Provenance & path analysis", d: "Trust-annotated lineage behind each action, and the destinations agents tried to reach." },
  { icon: ShieldCheck, t: "10-case benchmark", d: "3 safe, 3 direct, 2 transformed, 2 delayed. Measured prevention, false positives, task completion and latency." },
  { icon: Link2, t: "Chain verification & export", d: "Verify the chain, simulate tampering on a copy, export a proof bundle for offline verification." },
];

export default function ForensicLab() {
  return (
    <>
      <PageHero eyebrow="Global Forensic Lab · public preview" title={<>Follow an action from <span className="text-gradient">source to evidence.</span></>}
        lead="Pick a case. The server evaluates it with the real Gate inside an isolated sandbox, and everything below is drawn from that response. Nothing here is a live production feed.">
        <div className="flex flex-wrap items-center gap-2"><Tag tone="amber">Simulated demo</Tag><Tag tone="cyan">Real gate evaluation</Tag><Tag tone="slate">Fixed fixtures</Tag></div>
      </PageHero>
      <section className="py-14 sm:py-20" aria-label="Forensic explorer"><Container><div className="reveal"><ForensicExplorer /></div></Container></section>
      <section className="border-t border-site-line bg-site-mist py-16 sm:py-24" aria-labelledby="lab">
        <Container className="grid gap-10 lg:grid-cols-[1fr_1.5fr]">
          <div>
            <SectionHead id="lab" eyebrow="Inside the product" title="The full lab runs on your own evidence." lead="After sign-in, the Global Forensic Lab works on the production proof chain of your deployment, not on demo fixtures." />
            <div className="reveal mt-6 flex flex-wrap gap-3"><ButtonLink href="/forensic" kind="primary" arrow>Open the lab (sign-in)</ButtonLink></div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {LAB.map((l, i) => (
              <div key={l.t} className="reveal rounded-3xl border border-site-line bg-white p-5" style={{ ["--d" as string]: `${i * 80}ms` }}>
                <l.icon className="h-5 w-5 text-site-blue" /><h3 className="mt-3 font-semibold text-site-ink">{l.t}</h3><p className="mt-1.5 text-sm leading-relaxed text-site-mute">{l.d}</p></div>))}
            <div className="reveal flex items-start gap-3 rounded-3xl border border-dashed border-site-line p-5 text-sm text-site-mute sm:col-span-2"><Waypoints className="mt-0.5 h-5 w-5 shrink-0 text-site-mute" />
              Live WebSocket streaming is not implemented; the authenticated lab polls the API every few seconds.</div>
          </div>
        </Container>
      </section>
      <FinalCta />
    </>);
}
