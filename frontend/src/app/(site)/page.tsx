import type { Metadata } from "next";
import { CheckCircle2, EyeOff, Hourglass, Shuffle } from "lucide-react";
import HeroFlow from "@/components/site/HeroFlow";
import LiveDemo from "@/components/site/LiveDemo";
import { ButtonLink, Container, SectionHead, Tag } from "@/components/site/primitives";
import { CheckpointDiagram, DataFlow, GapDiagram, ProofPreview, WorkflowScroll } from "@/components/site/visuals";
import { CustomerBento, FaqList, FinalCta, ModuleCards, PricingCards } from "@/components/site/blocks";

export const metadata: Metadata = { title: { absolute: "QYRIX SENTINEL - Secure Every AI Action. Before Execution." } };

const POINTS = ["Inspect risky instructions and skills.", "Track source trust and lineage.",
  "Enforce deterministic ALLOW/BLOCK before tool execution.", "Verify security evidence."];

const RISKS = [
  { icon: EyeOff, t: "Looks trusted", d: "A malicious step hides inside a README, an issue or a skill the agent was told to follow." },
  { icon: Shuffle, t: "Survives transformation", d: "Encoded, defanged or summarised instructions slip past filters that match the original text." },
  { icon: Hourglass, t: "Arrives later", d: "The instruction is read now and acted on twenty steps later, long after the prompt was checked." },
];

export default function Home() {
  return (
    <>
      {/* 2. HERO */}
      <section className="relative overflow-hidden">
        <div aria-hidden className="site-grid absolute inset-0" />
        <div aria-hidden className="absolute -top-48 right-[-10%] h-[36rem] w-[36rem] rounded-full bg-gradient-to-br from-site-blue/20 via-site-cyan/10 to-transparent blur-3xl" />
        <div aria-hidden className="absolute -left-40 top-40 h-80 w-80 rounded-full bg-site-violet/10 blur-3xl" />
        <Container className="relative grid items-center gap-12 pb-16 pt-14 sm:pt-20 lg:grid-cols-[1.05fr_1fr] lg:gap-10 lg:pb-24">
          <div>
            <p className="rise"><Tag>Trust-to-Execution Guard</Tag></p>
            <h1 className="rise mt-6 text-balance text-[2.6rem] font-semibold leading-[1.02] tracking-[-0.045em] text-site-ink sm:text-6xl lg:text-[4.4rem]" style={{ ["--d" as string]: "90ms" }}>
              Secure Every AI Action. <span className="text-gradient">Before Execution.</span></h1>
            <p className="rise mt-6 max-w-xl text-pretty text-lg leading-relaxed text-site-mute sm:text-xl" style={{ ["--d" as string]: "180ms" }}>
              Trust-aware execution security for AI agents, tools, and enterprise workflows.</p>
            <ul className="rise mt-7 grid gap-2.5 sm:grid-cols-2" style={{ ["--d" as string]: "260ms" }}>
              {POINTS.map((p) => <li key={p} className="flex gap-2.5 text-[15px] text-site-ink/90"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-site-cyan" aria-hidden />{p}</li>)}
            </ul>
            <div className="rise mt-9 flex flex-wrap gap-3" style={{ ["--d" as string]: "340ms" }}>
              <ButtonLink href="#demo" kind="blue" arrow>Explore Working Demo</ButtonLink>
              <ButtonLink href="/how-it-works" kind="ghost">View How It Works</ButtonLink>
            </div>
          </div>
          <div className="rise relative mx-auto w-full max-w-[520px]" style={{ ["--d" as string]: "200ms" }}>
            <div aria-hidden className="absolute inset-6 rounded-[40px] bg-gradient-to-br from-site-blue/10 to-site-cyan/10 blur-2xl" />
            <div className="relative rounded-[32px] border border-site-line/80 bg-white/70 p-4 shadow-lift backdrop-blur sm:p-6"><HeroFlow /></div>
          </div>
        </Container>
      </section>

      {/* 3. PROBLEM */}
      <section className="border-y border-site-line bg-site-mist py-20 sm:py-28" aria-labelledby="problem">
        <Container className="grid items-center gap-12 lg:grid-cols-2">
          <div>
            <SectionHead id="problem" eyebrow="The problem" title={<>Detecting a threat after the tool ran is too late.</>}
              lead="AI agents read instructions and invoke tools. If a manipulated instruction reaches a tool, prompt filters and monitoring can raise an alert, but they do not guarantee the final action was safe." />
            <div className="mt-8 grid gap-3 sm:grid-cols-3 lg:grid-cols-1 xl:grid-cols-3">
              {RISKS.map((r, i) => (
                <div key={r.t} className="reveal rounded-2xl border border-site-line bg-white p-4" style={{ ["--d" as string]: `${i * 90}ms` }}>
                  <r.icon className="h-5 w-5 text-rose-500" aria-hidden />
                  <p className="mt-3 font-semibold text-site-ink">{r.t}</p><p className="mt-1 text-sm leading-relaxed text-site-mute">{r.d}</p>
                </div>))}
            </div>
          </div>
          <div className="reveal rounded-[28px] border border-site-line bg-white p-5 shadow-soft sm:p-8"><GapDiagram /></div>
        </Container>
      </section>

      {/* 4. SOLUTION */}
      <section className="relative overflow-hidden bg-site-navy py-20 text-white sm:py-28" aria-labelledby="solution">
        <div aria-hidden className="site-grid-dark absolute inset-0" />
        <div aria-hidden className="absolute -right-40 top-10 h-96 w-96 rounded-full bg-site-cyan/20 blur-3xl" />
        <Container className="relative grid items-center gap-12 lg:grid-cols-[1fr_1.25fr]">
          <SectionHead id="solution" dark eyebrow="The solution" title="One enforceable checkpoint between the agent and every tool."
            lead="QYRIX SENTINEL evaluates each proposed action, checking destination, action, data, authentication and provenance, and decides before execution. An allowed action receives a single-use grant bound to its exact parameters. Everything else is blocked, and the decision is recorded first." />
          <div className="reveal rounded-[28px] border border-white/10 bg-white/[.03] p-4 sm:p-6"><CheckpointDiagram /></div>
        </Container>
      </section>

      {/* 5. MODULES */}
      <section className="py-20 sm:py-28" aria-labelledby="modules">
        <Container>
          <SectionHead id="modules" eyebrow="Four core modules" title="Inspect. Establish trust. Gate. Prove." center
            lead="Four modules, one deterministic path from what the agent read to what it is allowed to do." />
          <div className="mt-14"><ModuleCards /></div>
        </Container>
      </section>

      {/* 6. HOW IT WORKS (scroll narrative) */}
      <section className="border-t border-site-line bg-gradient-to-b from-site-mist to-white py-20 sm:py-28" aria-labelledby="workflow">
        <Container>
          <SectionHead id="workflow" eyebrow="How the workflow works" title="From instruction to verified decision in four steps." />
          <div className="mt-12"><WorkflowScroll /></div>
        </Container>
      </section>

      {/* 7. DATA FLOW */}
      <section className="relative overflow-hidden bg-site-deep py-20 text-white sm:py-28" aria-labelledby="dataflow">
        <div aria-hidden className="site-grid-dark absolute inset-0 opacity-70" />
        <Container className="relative">
          <SectionHead id="dataflow" dark eyebrow="Data flow" title="What each module hands to the next."
            lead="Every stage emits a concrete artifact. The Gate can only decide on what the Inspector found and what Provenance proved, and every decision becomes evidence." />
          <div className="mt-12"><DataFlow /></div>
        </Container>
      </section>

      {/* 8. PROOF PREVIEW */}
      <section className="py-20 sm:py-28" aria-labelledby="proof">
        <Container className="grid items-center gap-12 lg:grid-cols-[1fr_1.4fr]">
          <SectionHead id="proof" eyebrow="Forensic proof" title="Evidence you can verify, not just logs you trust."
            lead={<>Each record stores the rule IDs, lineage and redacted data, and is chained by SHA-256 to the one before. Change or remove one record and verification fails. Without an external anchor the honest result is <b className="text-site-ink">PARTIAL_UNANCHORED</b>, never a full PASS.</>} />
          <div className="rounded-[28px] border border-site-line bg-site-mist p-5 sm:p-8">
            <ProofPreview />
            <div className="mt-6 flex flex-wrap gap-3"><ButtonLink href="/forensic-lab" kind="primary" arrow>Open the Forensic Lab</ButtonLink></div>
          </div>
        </Container>
      </section>

      {/* 9. LIVE DEMO */}
      <section id="demo" className="scroll-mt-20 border-t border-site-line bg-gradient-to-b from-white to-site-mist py-20 sm:py-28" aria-labelledby="demo-h">
        <Container>
          <SectionHead id="demo-h" eyebrow="Interactive demo" title="Run an attack. Watch it stop before execution."
            lead="Each button sends a fixed scenario to an isolated sandbox on the server. The Gate decision you see is the real one; the tool execution is simulated, and nothing touches the production audit chain." />
          <div className="reveal mt-10"><LiveDemo /></div>
        </Container>
      </section>

      {/* 10. CUSTOMERS */}
      <section className="py-20 sm:py-28" aria-labelledby="customers">
        <Container>
          <SectionHead id="customers" eyebrow="Who it is for" title="For teams whose agents touch real systems." />
          <div className="mt-12"><CustomerBento /></div>
        </Container>
      </section>

      {/* 11. PRICING */}
      <section className="border-t border-site-line bg-site-mist py-20 sm:py-28" aria-labelledby="pricing">
        <Container>
          <SectionHead id="pricing" eyebrow="Pricing" title="Start free. Scale with checks, not seats." />
          <div className="mt-10"><PricingCards /></div>
        </Container>
      </section>

      {/* 12. FAQ */}
      <section className="py-20 sm:py-28" aria-labelledby="faq">
        <Container className="grid gap-10 lg:grid-cols-[1fr_1.6fr]">
          <SectionHead id="faq" eyebrow="FAQ" title="Straight answers." lead="Including the limits. We would rather you know them now." />
          <div className="reveal"><FaqList /></div>
        </Container>
      </section>

      {/* 13. FINAL CTA (footer in layout) */}
      <FinalCta />
    </>);
}
