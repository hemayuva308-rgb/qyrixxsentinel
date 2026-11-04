import type { Metadata } from "next";
import { Container, PageHero, SectionHead, ButtonLink } from "@/components/site/primitives";
import { DataFlow } from "@/components/site/visuals";
import { FinalCta } from "@/components/site/blocks";
import LiveDemo from "@/components/site/LiveDemo";

export const metadata: Metadata = { title: "How It Works", description: "Inspect, establish trust, evaluate, authorise or block, execute safely, verify proof." };

const FLOW = [
  ["Inspect", "The agent's instruction, skill or README is normalised and scanned for destinations, commands and secret references. Findings are structured; secrets are redacted."],
  ["Establish trust", "The source is labelled TRUSTED, UNTRUSTED or UNVERIFIED and given a UUID. Each derived step records its parents and inherits the lowest trust on its path."],
  ["Evaluate", "The proposed action (tool, method, destination, data, lineage, approval) is checked by deterministic rules. No DNS lookup or network access happens here."],
  ["Authorise or block", "BLOCK: rule IDs are recorded and no grant exists. ALLOW: the immutable parameters and their digest are stored server-side and a short-lived single-use grant is issued. A required human approval is consumed in the same atomic step."],
  ["Execute safely", "The agent calls POST /api/v1/tools/execute with only gate_evaluation_id and grant_id. The server reloads the parameters, recomputes the digest, consumes the grant, records the start, then runs the controlled adapter (DNS-validated, IP-pinned HTTP, or jailed file read)."],
  ["Verify proof", "Decision, execution start and result are hash-linked records. Export the bundle and verify it offline; tampering, deletion or reordering fails verification."],
];

const CODE = `# 1. evaluate (agent token)
POST /api/v1/sentinel/gate/evaluate
{ "tool": "http", "method": "GET", "dest": "https://api.render.com/v1/services",
  "lineage": ["4c1f…-…"] }
→ { "verdict": "ALLOW", "gate_evaluation_id": "…", "grant_id": "grt_…", "proof": { "n": 12, "hash": "…" } }

# 2. execute - ONLY these two fields are accepted
POST /api/v1/tools/execute
{ "gate_evaluation_id": "…", "grant_id": "grt_…" }
→ { "executed": true, "result": { "status": 200, "pinned_ip": "…" }, "proof_start": {…}, "proof_result": {…} }

# any other field
→ 400 CLIENT_PARAMS_NOT_ALLOWED   (before any lookup, invocation or network access)`;

export default function HowItWorks() {
  return (
    <>
      <PageHero eyebrow="How it works" title={<>From trust to execution, <span className="text-gradient">with nothing in between.</span></>}
        lead="Inspect → Establish Trust → Evaluate → Authorize or Block → Execute Safely → Verify Proof. Each step is deterministic and leaves evidence." />
      <section className="py-16 sm:py-24" aria-labelledby="six">
        <Container>
          <SectionHead id="six" eyebrow="Six steps" title="The enforcement path." />
          <ol className="relative mt-12 space-y-4 before:absolute before:bottom-6 before:left-[27px] before:top-6 before:w-px before:bg-gradient-to-b before:from-site-blue before:to-site-cyan sm:before:left-[31px]">
            {FLOW.map(([t, d], i) => (
              <li key={t} className="reveal relative flex gap-5 sm:gap-7" style={{ ["--d" as string]: `${i * 70}ms` }}>
                <span className="relative z-10 grid h-14 w-14 shrink-0 place-items-center rounded-2xl border border-site-blue/20 bg-white font-mono text-sm font-bold text-site-blue shadow-soft sm:h-16 sm:w-16">{String(i + 1).padStart(2, "0")}</span>
                <div className="flex-1 rounded-3xl border border-site-line bg-white p-5 transition duration-500 hover:shadow-lift sm:p-6">
                  <h3 className="text-xl font-semibold tracking-tight text-site-ink">{t}</h3><p className="mt-2 leading-relaxed text-site-mute">{d}</p></div>
              </li>))}
          </ol>
        </Container>
      </section>
      <section className="relative overflow-hidden bg-site-deep py-16 text-white sm:py-24" aria-labelledby="df">
        <div aria-hidden className="site-grid-dark absolute inset-0" />
        <Container className="relative"><SectionHead id="df" dark eyebrow="Data flow" title="Artifacts handed between modules." /><div className="mt-10"><DataFlow /></div></Container>
      </section>
      <section className="py-16 sm:py-24" aria-labelledby="api">
        <Container className="grid gap-10 lg:grid-cols-[1fr_1.3fr]">
          <div>
            <SectionHead id="api" eyebrow="API sequence" title="Evaluate, then execute with a grant."
              lead="Clients never resend parameters at execution time, so an approved action cannot be swapped for a different one between decision and execution." />
            <div className="reveal mt-6 space-y-3 text-sm text-site-mute">
              <p><b className="text-site-ink">Approvals.</b> A human (admin role) approves an exact scope. Approving is not executing: the agent resubmits to the Gate, which consumes the approval atomically with grant creation.</p>
              <p><b className="text-site-ink">Redirects.</b> A 3xx is returned, never followed. The new target needs a fresh evaluation with <code className="font-mono text-xs">redirect_of</code>; at most 5 hops.</p>
              <p><b className="text-site-ink">Failure.</b> Any error, unknown input or failed proof write ends in BLOCK.</p>
            </div>
            <div className="mt-6"><ButtonLink href="/docs" kind="ghost" arrow>API reference</ButtonLink></div>
          </div>
          <pre className="reveal overflow-x-auto rounded-3xl bg-site-deep p-6 font-mono text-[12.5px] leading-relaxed text-slate-200 shadow-lift"><code>{CODE}</code></pre>
        </Container>
      </section>
      {/* Moved here from the homepage (the new homepage specification has no demo section). Same component, same public sandbox API. */}
      <section id="demo" className="scroll-mt-20 border-t border-site-line bg-gradient-to-b from-white to-site-mist py-20 sm:py-28" aria-labelledby="demo-h">
        <Container>
          <SectionHead id="demo-h" eyebrow="Interactive demo" title="Run an attack. Watch it stop before execution."
            lead="Each button sends a fixed scenario to an isolated sandbox on the server. The Gate decision you see is the real one; the tool execution is simulated, and nothing touches the production audit chain." />
          <div className="reveal mt-10"><LiveDemo /></div>
        </Container>
      </section>
      <FinalCta />
    </>);
}
