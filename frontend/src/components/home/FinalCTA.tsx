import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { DEMO_HREF } from "@/lib/home-content";

export default function FinalCTA() {
  return (
    <section id="cta" aria-labelledby="cta-h" className="qx-section relative overflow-hidden bg-qx-ink py-20 text-white sm:py-28">
      <div aria-hidden className="site-grid-dark absolute inset-0 opacity-60" />
      <div aria-hidden className="qx-aurora absolute left-1/2 top-0 h-80 w-[46rem] -translate-x-1/2 rounded-full bg-qx-blue/35 blur-3xl" />
      <div className="relative mx-auto w-full max-w-site px-5 text-center sm:px-8">
        <h2 id="cta-h" className="reveal mx-auto max-w-3xl text-balance text-3xl font-semibold tracking-[-0.03em] sm:text-5xl sm:leading-[1.08]">Put a security boundary between intent and execution.</h2>
        <p className="reveal mx-auto mt-5 max-w-xl text-lg text-slate-300" style={{ ["--d" as string]: "80ms" }}>Build with AI agents. Execute with control. Verify with evidence.</p>
        <div className="reveal mt-9 flex flex-wrap items-center justify-center gap-3" style={{ ["--d" as string]: "160ms" }}>
          <Link href={DEMO_HREF} className="group inline-flex min-h-11 items-center gap-2 rounded-full bg-white px-6 py-3 text-sm font-semibold text-qx-ink transition duration-300 hover:bg-qx-ice active:scale-[.98]">
            Request a Demo<ArrowRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5" aria-hidden /></Link>
          <Link href="#architecture" className="inline-flex min-h-11 items-center rounded-full border border-white/25 bg-white/5 px-6 py-3 text-sm font-semibold text-white transition duration-300 hover:bg-white/10 active:scale-[.98]">Explore the Architecture</Link>
        </div>
        <p className="reveal mt-6 text-xs text-slate-400" style={{ ["--d" as string]: "220ms" }}>The demo request opens a contact page that prepares your message to copy or email. No booking is made automatically.</p>
      </div>
    </section>);
}
