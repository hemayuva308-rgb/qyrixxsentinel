import type { Metadata } from "next";
import { Container, PageHero, SectionHead, Tag } from "@/components/site/primitives";

export const metadata: Metadata = { title: "Documentation", description: "API reference and documentation index for QYRIX SENTINEL." };

const API = [
  ["POST", "/api/v1/sentinel/inspect", "any role", "Inspector findings + advisory classification"],
  ["POST", "/api/v1/sentinel/provenance/step", "any role", "Add a step: label, text (redacted), parents (UUIDs) → effective trust"],
  ["GET", "/api/v1/sentinel/provenance", "any role", "50-step window"],
  ["POST", "/api/v1/sentinel/gate/evaluate", "any role", "Deterministic ALLOW/BLOCK; ALLOW returns gate_evaluation_id + grant_id"],
  ["POST", "/api/v1/tools/execute", "any role", "Body must be exactly {gate_evaluation_id, grant_id}"],
  ["POST", "/api/v1/sentinel/approvals", "any role", "Request an exact-scope approval"],
  ["POST", "/api/v1/sentinel/approvals/{id}/{approve|deny}", "admin", "Human decision; does not execute"],
  ["GET", "/api/v1/sentinel/proofs · /proofs/verify · /proofs/export", "any role", "Chain, verification (PASS/FAIL/PARTIAL_UNANCHORED), bundle"],
  ["POST", "/api/v1/sentinel/proofs/verify-bundle", "any role", "Verify an exported bundle; empty → 422 EMPTY_PROOF_BUNDLE"],
  ["GET", "/api/v1/sentinel/status", "any role", "Health, counters, recent records"],
  ["POST", "/api/v1/sentinel/benchmark · /reset", "admin, demo mode", "10-case benchmark (resets state)"],
  ["POST", "/api/v1/demo/run", "public", "Fixed scenario id only; isolated sandbox; rate limited"],
];
const DOCS = ["QYRIX_SENTINEL_FINAL_MASTER_PLAN.md", "ARCHITECTURE.md", "API_SPECIFICATION.md", "SECURITY_DESIGN.md", "DATABASE_DESIGN.md", "SRS.md",
  "IMPLEMENTATION_ROADMAP.md", "IMPLEMENTATION_REPORT.md", "security/threat-model.md", "security/security-gates/SG-01 … SG-08"];

export default function Docs() {
  return (
    <>
      <PageHero eyebrow="Documentation" title="API reference & documents" lead="Bearer-token authentication on every endpoint except health and the public demo. The browser reaches the API only through the web server's proxy." />
      <section className="py-14 sm:py-20" aria-labelledby="ref">
        <Container>
          <SectionHead id="ref" eyebrow="Endpoints" title="API v1" />
          <div className="reveal mt-8 overflow-x-auto rounded-3xl border border-site-line">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="bg-site-mist font-mono text-[11px] uppercase tracking-[.14em] text-site-mute"><tr><th className="px-5 py-3">Method</th><th className="px-5 py-3">Path</th><th className="px-5 py-3">Role</th><th className="px-5 py-3">Purpose</th></tr></thead>
              <tbody>{API.map(([m, p, r, d]) => (
                <tr key={p} className="border-t border-site-line align-top"><td className="px-5 py-3"><Tag tone={m === "GET" ? "cyan" : "blue"}>{m}</Tag></td>
                  <td className="px-5 py-3 font-mono text-xs text-site-ink">{p}</td><td className="px-5 py-3 text-site-mute">{r}</td><td className="px-5 py-3 text-site-mute">{d}</td></tr>))}</tbody>
            </table>
          </div>
        </Container>
      </section>
      <section className="border-t border-site-line bg-site-mist py-14 sm:py-20" aria-labelledby="idx">
        <Container className="grid gap-10 lg:grid-cols-2">
          <div><SectionHead id="idx" eyebrow="In the repository" title="Design documents" lead="Maintained under docs/ and security/ in the source repository and kept in line with the implementation." /></div>
          <ul className="reveal grid gap-2 font-mono text-sm">{DOCS.map((d) => <li key={d} className="rounded-xl border border-site-line bg-white px-4 py-2.5 text-site-ink">{d}</li>)}</ul>
        </Container>
      </section>
      <section className="py-14 sm:py-20" aria-labelledby="run">
        <Container>
          <SectionHead id="run" eyebrow="Run locally" title="Two containers, one command." />
          <pre className="reveal mt-8 overflow-x-auto rounded-3xl bg-site-deep p-6 font-mono text-[13px] leading-relaxed text-slate-200"><code>{`cp .env.example .env          # replace every CHANGE_ME value (openssl rand -hex 32)
docker compose up --build     # web: http://127.0.0.1:3000  (API stays on the internal network)

cd backend && python -m pytest -q
python scripts/verify_proof.py bundle.json    # offline proof verification`}</code></pre>
        </Container>
      </section>
    </>);
}
