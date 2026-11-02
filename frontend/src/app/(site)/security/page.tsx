import type { Metadata } from "next";
import { Lock, Network, ServerCog, ShieldCheck } from "lucide-react";
import { SECURITY_GATES } from "@/lib/security-status";
import { ButtonLink, Container, PageHero, SectionHead, Tag } from "@/components/site/primitives";
import { FinalCta } from "@/components/site/blocks";

export const metadata: Metadata = { title: "Security", description: "Security architecture, boundaries, controls and current limitations of QYRIX SENTINEL." };

const BOUNDARIES = [
  { icon: Network, t: "Network boundary", d: "Docker Compose publishes only the web container on 127.0.0.1. The API sits on an internal-only network with no route to the internet; outbound tool access is an explicit opt-in." },
  { icon: Lock, t: "Credential boundary", d: "Operator tokens live in an httpOnly, SameSite=Strict cookie. The Next.js server proxies API calls with a CSRF header check; no token reaches client JavaScript." },
  { icon: ShieldCheck, t: "Execution boundary", d: "Only the controlled adapter can act, only for a single-use grant, only with server-stored parameters. Evaluation is side-effect free." },
  { icon: ServerCog, t: "Runtime hardening", d: "Read-only container filesystems, all Linux capabilities dropped, no-new-privileges, non-root backend user." },
];
const tone = { TESTED: "cyan", PARTIAL: "amber", "NOT IMPLEMENTED": "rose" } as const;

export default function Security() {
  return (
    <>
      <PageHero eyebrow="Security" title={<>Fail closed. <span className="text-gradient">Prove it.</span></>}
        lead="How QYRIX SENTINEL is built to enforce, what is tested, and what is not done yet. We list the gaps on purpose." />
      <section className="py-16 sm:py-24" aria-labelledby="bounds">
        <Container>
          <SectionHead id="bounds" eyebrow="Architecture boundaries" title="Four boundaries an attacker has to cross." />
          <div className="mt-10 grid gap-4 md:grid-cols-2">
            {BOUNDARIES.map((b, i) => (
              <div key={b.t} className="reveal rounded-3xl border border-site-line bg-white p-6 shadow-soft" style={{ ["--d" as string]: `${i * 80}ms` }}>
                <b.icon className="h-6 w-6 text-site-blue" /><h3 className="mt-4 text-lg font-semibold text-site-ink">{b.t}</h3><p className="mt-2 text-sm leading-relaxed text-site-mute">{b.d}</p></div>))}
          </div>
        </Container>
      </section>
      <section className="border-t border-site-line bg-site-mist py-16 sm:py-24" aria-labelledby="sg">
        <Container>
          <SectionHead id="sg" eyebrow="Security gates SG-01 – SG-08" title="Status of every control, as of this build."
            lead="TESTED means an automated test was executed in the repository. PARTIAL means part of the control is missing. Evidence is in the repository under security/ and docs/." />
          <div className="reveal mt-10 overflow-hidden rounded-3xl border border-site-line bg-white">
            <table className="w-full text-left text-sm">
              <thead className="bg-site-mist font-mono text-[11px] uppercase tracking-[.14em] text-site-mute"><tr><th className="px-5 py-3">Gate</th><th className="px-5 py-3">Status</th><th className="hidden px-5 py-3 md:table-cell">In place</th><th className="hidden px-5 py-3 lg:table-cell">Open</th></tr></thead>
              <tbody>{SECURITY_GATES.map((g) => (
                <tr key={g.id} className="border-t border-site-line align-top">
                  <td className="px-5 py-4"><p className="font-mono text-xs font-bold text-site-ink">{g.id}</p><p className="text-site-ink">{g.name}</p></td>
                  <td className="px-5 py-4"><Tag tone={tone[g.status]}>{g.status}</Tag></td>
                  <td className="hidden px-5 py-4 text-site-mute md:table-cell">{g.done}</td>
                  <td className="hidden px-5 py-4 text-site-mute lg:table-cell">{g.open}</td>
                </tr>))}</tbody>
            </table>
          </div>
        </Container>
      </section>
      <section className="py-16 sm:py-24" aria-labelledby="limits">
        <Container className="grid gap-10 lg:grid-cols-2">
          <SectionHead id="limits" eyebrow="Known limitations" title="What this build does not claim." />
          <ul className="reveal space-y-3 text-[15px] leading-relaxed text-site-mute">
            <li>• <b className="text-site-ink">Single tenant.</b> No organisations, tenant isolation, usage metering or quotas. Provenance, approvals, evaluations and grants persist in PostgreSQL when configured (in memory otherwise).</li>
            <li>• <b className="text-site-ink">Evidence anchoring.</b> RFC 3161 anchoring is implemented and tested against a local TSA; anchoring with a public TSA has not been verified yet. Without a verified anchor, verification reports PARTIAL_UNANCHORED.</li>
            <li>• <b className="text-site-ink">Tool coverage.</b> HTTP and file read execute through the adapter; shell never executes.</li>
            <li>• <b className="text-site-ink">AI provider.</b> Meta Llama live calls are not verified here; the classifier is advisory regardless.</li>
            <li>• <b className="text-site-ink">Benchmark scope.</b> The 10-case benchmark measures those synthetic cases only.</li>
            <li>• <b className="text-site-ink">Content-Security-Policy</b> is enforced but still allows inline scripts (framework bootstrap).</li>
            <li>• <b className="text-site-ink">Not production-certified.</b> No third-party audit, penetration test or certification is claimed.</li>
          </ul>
        </Container>
        <Container className="mt-10"><ButtonLink href="/docs" kind="ghost" arrow>Read the documentation</ButtonLink></Container>
      </section>
      <FinalCta />
    </>);
}
