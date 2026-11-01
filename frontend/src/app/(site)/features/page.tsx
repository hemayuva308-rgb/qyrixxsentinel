import type { Metadata } from "next";
import { Bot, FileSearch, GitBranch, Link2, ShieldCheck } from "lucide-react";
import { MODULES } from "@/lib/site-content";
import { RULE_HELP } from "@/lib/rules";
import { ButtonLink, Container, PageHero, SectionHead, Tag } from "@/components/site/primitives";
import { FinalCta } from "@/components/site/blocks";

export const metadata: Metadata = { title: "Features", description: "Skill Inspector, Trust Provenance, Execution Gate and Verifiable Proof - the four modules of QYRIX SENTINEL." };

const ICON = { inspector: FileSearch, provenance: GitBranch, gate: ShieldCheck, proof: Link2 } as const;
const DETAIL: Record<string, string[]> = {
  inspector: ["Normalises base64, hxxp, [.], (.) and percent-encoding before matching", "Extracts domains (linear-time parser), shell commands and secret references",
    "Flags destinations outside the allowlist", "Redacts secrets before storage, proof records or any AI call", "Bounded input (100 KB) and linear-time patterns (no ReDoS)"],
  provenance: ["UUID v4 step ids; every session starts UNVERIFIED", "Effective trust = lowest of own label and all ancestors",
    "Unknown or evicted-and-forgotten parents make a child UNVERIFIED", "50-step working window; trust of evicted steps retained in a bounded index",
    "Cycle detection blocks with LINEAGE_CYCLE_DETECTED", "Trust is not authorisation: TRUSTED actions still face the Gate"],
  gate: ["Default deny: unknown tool, destination, lineage or label blocks", "SSRF defence: private, loopback, link-local, NAT64/6to4/Teredo, userinfo, numeric hosts",
    "Secret-exfiltration and command-injection rules", "Exact-scope, expiring, single-use human approvals for high-impact actions",
    "ALLOW issues a grant bound to the parameter digest; execution accepts only gate_evaluation_id + grant_id", "Every redirect hop needs a fresh decision; max 5 hops"],
  proof: ["Canonical JSON (sorted keys, ASCII) hashed with SHA-256 and linked to the previous record", "Written and fsync'd before execution; write failure blocks",
    "Execution start / result recorded as separate events", "Tampered, missing or reordered records FAIL; empty bundles are rejected",
    "Export bundles and verify offline (CLI) or in the browser (Forensic Lab)", "Optional RFC 3161 timestamp anchoring of the chain head: PASS only when a verified token covers the head, otherwise PARTIAL_UNANCHORED"],
};

export default function Features() {
  return (
    <>
      <PageHero eyebrow="Features" title={<>Four modules. <span className="text-gradient">One enforcement path.</span></>}
        lead="Each module has a narrow job and a concrete output. Together they turn what an agent read into a deterministic, provable decision about what it may do.">
        <div className="flex flex-wrap gap-3"><ButtonLink href="/#demo" kind="blue" arrow>Try the live demo</ButtonLink><ButtonLink href="/how-it-works" kind="ghost">See the full flow</ButtonLink></div>
      </PageHero>
      {MODULES.map((m, i) => {
        const Icon = ICON[m.id];
        return (
          <section key={m.id} id={m.id} className={`scroll-mt-20 py-16 sm:py-24 ${i % 2 ? "bg-site-mist" : ""}`} aria-labelledby={`h-${m.id}`}>
            <Container className={`grid items-start gap-10 lg:grid-cols-2 ${i % 2 ? "lg:[&>*:first-child]:order-2" : ""}`}>
              <div className="reveal">
                <span className="grid h-14 w-14 place-items-center rounded-2xl bg-gradient-to-br from-site-blue to-site-cyan text-white shadow-ring"><Icon className="h-6 w-6" /></span>
                <p className="eyebrow mt-6">Module {m.n}</p>
                <h2 id={`h-${m.id}`} className="mt-2 text-3xl font-semibold tracking-tight text-site-ink sm:text-4xl">{m.name}</h2>
                <p className="mt-4 text-lg leading-relaxed text-site-mute">{m.op}</p>
                <dl className="mt-6 grid gap-3 sm:grid-cols-2">
                  <div className="rounded-2xl border border-site-line bg-white p-4"><dt className="font-mono text-[10.5px] font-semibold uppercase tracking-[.16em] text-site-mute">Input</dt><dd className="mt-1 text-sm text-site-ink">{m.input}</dd></div>
                  <div className="rounded-2xl border border-site-line bg-white p-4"><dt className="font-mono text-[10.5px] font-semibold uppercase tracking-[.16em] text-site-mute">Output</dt><dd className="mt-1 text-sm text-site-ink">{m.out}</dd></div>
                </dl>
              </div>
              <ul className="reveal space-y-2.5 rounded-3xl border border-site-line bg-white p-6 shadow-soft sm:p-8" style={{ ["--d" as string]: "120ms" }}>
                {DETAIL[m.id].map((d) => <li key={d} className="flex gap-3 text-[15px] leading-relaxed text-site-ink/90"><span aria-hidden className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-site-blue" />{d}</li>)}
              </ul>
            </Container>
          </section>);
      })}
      <section className="border-t border-site-line py-16 sm:py-24" aria-labelledby="rules">
        <Container>
          <SectionHead id="rules" eyebrow="Rule catalogue" title="Every BLOCK names its reason." lead="Rule IDs are recorded in the proof chain with each decision." />
          <div className="reveal mt-10 overflow-hidden rounded-3xl border border-site-line">
            <table className="w-full text-left text-sm">
              <thead className="bg-site-mist font-mono text-[11px] uppercase tracking-[.14em] text-site-mute"><tr><th className="px-5 py-3">Rule</th><th className="px-5 py-3">Meaning</th></tr></thead>
              <tbody>{Object.entries(RULE_HELP).map(([k, v]) => (
                <tr key={k} className="border-t border-site-line"><td className="whitespace-nowrap px-5 py-3 font-mono text-xs font-semibold text-site-ink">{k}</td><td className="px-5 py-3 text-site-mute">{v}</td></tr>))}</tbody>
            </table>
          </div>
        </Container>
      </section>
      <section className="bg-site-mist py-16 sm:py-24" aria-labelledby="llama">
        <Container className="grid items-center gap-10 lg:grid-cols-[1fr_1.2fr]">
          <SectionHead id="llama" eyebrow="Meta Llama integration" title="AI explains. Policy decides." />
          <div className="reveal rounded-3xl border border-site-line bg-white p-6 sm:p-8">
            <div className="flex items-center gap-3"><Bot className="h-6 w-6 text-site-violet" /><Tag tone="violet">Advisory only</Tag><Tag tone="amber">Live provider: not verified</Tag></div>
            <ul className="mt-5 space-y-2 text-[15px] text-site-ink/90">
              <li>• Classifies untrusted instruction text and gives a one-sentence evidence explanation.</li>
              <li>• Receives only redacted, bounded (4,000 characters) content as JSON data under a fixed system prompt, with no tools.</li>
              <li>• Replies must match a strict schema; anything else is discarded and the labelled heuristic is used.</li>
              <li>• The Gate has no code path that reads the classification. A test enforces this.</li>
            </ul>
            <p className="mt-4 text-sm text-site-mute">Live calls to the Meta provider have not been verified in this environment; tests use recorded and mocked responses.</p>
          </div>
        </Container>
      </section>
      <FinalCta />
    </>);
}
