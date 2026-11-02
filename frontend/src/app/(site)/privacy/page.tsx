import type { Metadata } from "next";
import { Container, PageHero, Tag } from "@/components/site/primitives";

export const metadata: Metadata = { title: "Privacy notice (draft)", robots: { index: false } };

export default function Page() {
  return (
    <>
      <PageHero eyebrow="Legal · draft" title="Privacy notice" lead="This is a DRAFT placeholder. It has not been reviewed by counsel and makes no legal commitments."><Tag tone="amber">Draft - pending legal review</Tag></PageHero>
      <section className="py-14"><Container className="max-w-3xl space-y-4 text-[15px] leading-relaxed text-site-mute">
        <p>Final text will be published here after legal review. Until then, nothing on this page should be read as a binding commitment.</p>
        <p><b className="text-site-ink">What this website does today (factual):</b> the public pages set no analytics or advertising cookies. The interactive demo sends only a scenario identifier to the server; the server derives a rate-limit key from your network address in memory and does not store demo runs. The contact form does not transmit or store anything; it opens your email app or copies text. Operator sign-in stores an API token in an httpOnly session cookie for up to 8 hours.</p>
      </Container></section>
    </>);
}
