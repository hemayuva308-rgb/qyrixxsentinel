import type { Metadata } from "next";
import { Suspense } from "react";
import ContactForm from "@/components/site/ContactForm";
import { Container, PageHero } from "@/components/site/primitives";

export const metadata: Metadata = { title: "Contact", description: "Request access or an enterprise demo of QYRIX SENTINEL." };

export default function Contact() {
  return (
    <>
      <PageHero eyebrow="Contact" title="Talk to us about your agents." lead="Beta access, an enterprise demo, on-premise licensing or a security question. Tell us what your agents touch." />
      <section className="py-14 sm:py-20">
        <Container className="grid gap-10 lg:grid-cols-[1.4fr_1fr]">
          <div className="reveal rounded-3xl border border-site-line bg-white p-6 shadow-soft sm:p-8"><Suspense fallback={null}><ContactForm /></Suspense></div>
          <aside className="reveal space-y-4 text-sm text-site-mute" style={{ ["--d" as string]: "100ms" }}>
            <div className="rounded-3xl border border-site-line bg-site-mist p-6"><h2 className="font-semibold text-site-ink">What to expect</h2>
              <ul className="mt-3 space-y-2"><li>• A walkthrough of attack → block → proof → safe task on your own scenarios.</li><li>• An honest review of current limits (single tenant, unanchored evidence).</li><li>• Proposed pricing; no automated checkout exists.</li></ul></div>
            <div className="rounded-3xl border border-site-line p-6"><h2 className="font-semibold text-site-ink">Try it first</h2><p className="mt-2">The homepage demo and the Forensic Lab run the real Gate in an isolated sandbox. No sign-up needed.</p></div>
          </aside>
        </Container>
      </section>
    </>);
}
