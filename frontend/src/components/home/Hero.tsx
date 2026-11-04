import { ArrowRight } from "lucide-react";
import Link from "next/link";
import { BrandMark } from "@/components/brand/BrandMark";
import { HERO_STEPS } from "@/lib/home-content";

/** Hero. The right-hand composition is an ILLUSTRATION of the protected flow: it contains no live data, and says so. */
export default function Hero() {
  return (
    <section aria-labelledby="hero-h" className="qx-noise relative overflow-hidden bg-white">
      <div aria-hidden className="site-grid absolute inset-0" />
      <div aria-hidden className="qx-aurora absolute -right-40 -top-56 h-[40rem] w-[40rem] rounded-full bg-gradient-to-br from-qx-blue/25 via-qx-sky/20 to-transparent blur-3xl" />
      <div aria-hidden className="qx-aurora absolute -left-48 top-48 h-[30rem] w-[30rem] rounded-full bg-gradient-to-tr from-qx-sky/20 to-transparent blur-3xl" style={{ animationDelay: "-9s" }} />
      <div className="relative mx-auto grid w-full max-w-site items-center gap-14 px-5 pb-20 pt-14 sm:px-8 sm:pt-20 lg:grid-cols-[1.18fr_1fr] lg:gap-8 lg:pb-28 lg:pt-24">
        <div>
          <p className="rise inline-flex items-center gap-2 rounded-full border border-qx-blue/20 bg-white/70 px-3 py-1 font-mono text-[11px] font-semibold uppercase tracking-[.18em] text-qx-blue backdrop-blur">
            <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-qx-blue" />Trust-to-Execution Guard</p>
          <h1 id="hero-h" className="rise mt-6 text-[2.5rem] font-semibold leading-[1.05] tracking-[-0.04em] text-qx-ink sm:text-6xl lg:text-[3.35rem] xl:text-[3.7rem]" style={{ ["--d" as string]: "80ms" }}>
            <span className="block lg:whitespace-nowrap">Trust Every Execution.</span><span className="block bg-gradient-to-r from-qx-ink via-qx-blue to-qx-sky bg-clip-text text-transparent lg:whitespace-nowrap">Verify Every Action.</span></h1>
          <p className="rise mt-6 max-w-xl text-pretty text-base leading-relaxed text-qx-body sm:text-lg" style={{ ["--d" as string]: "160ms" }}>
            AI agents are becoming powerful. Their access to tools, APIs, and external systems needs to be controlled. Qyrix Sentinel adds a deterministic security layer between AI agents and the actions they perform.</p>
          <div className="rise mt-9 flex flex-wrap gap-3" style={{ ["--d" as string]: "240ms" }}>
            <Link href="#platform" className="group inline-flex min-h-11 items-center justify-center gap-2 rounded-full bg-qx-blue px-6 py-3 text-sm font-semibold text-white shadow-[0_10px_28px_-10px_rgba(37,99,235,.8)] transition duration-300 hover:bg-[#1d4fd0] hover:shadow-[0_14px_32px_-10px_rgba(37,99,235,.85)] active:scale-[.98]">
              Explore the Platform<ArrowRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5" aria-hidden /></Link>
            <Link href="#architecture" className="inline-flex min-h-11 items-center justify-center rounded-full border border-qx-line bg-white/80 px-6 py-3 text-sm font-semibold text-qx-ink backdrop-blur transition duration-300 hover:border-qx-blue/40 hover:text-qx-blue active:scale-[.98]">View Architecture</Link>
          </div>
          <p className="rise mt-6 text-xs leading-relaxed text-qx-body" style={{ ["--d" as string]: "320ms" }}>Prototype-stage platform. See <Link href="#status" className="font-medium text-qx-blue underline-offset-2 hover:underline">product status</Link> for what is implemented and what is still being validated.</p>
        </div>

        <div className="rise relative mx-auto w-full max-w-[540px]" style={{ ["--d" as string]: "180ms" }}>
          <div aria-hidden className="absolute inset-4 rounded-[44px] bg-gradient-to-br from-qx-blue/15 to-qx-sky/10 blur-2xl" />
          <figure className="qx-glass relative rounded-[32px] p-5 sm:p-7" aria-label="Illustration of the protected execution flow">
            <figcaption className="flex items-center justify-between gap-3">
              <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[.16em] text-qx-body">Protected execution flow</span>
              <span className="rounded-full border border-amber-200 bg-amber-50 px-2.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[.1em] text-amber-900">Illustration · not live data</span>
            </figcaption>

            {/* Security core with slow orbit */}
            <div className="relative mx-auto mt-6 flex h-52 w-52 items-center justify-center sm:h-60 sm:w-60" aria-hidden>
              <div className="absolute inset-0 rounded-full border border-qx-blue/15" />
              <div className="qx-orbit absolute inset-0"><span className="absolute left-1/2 top-0 h-2.5 w-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-qx-blue shadow-[0_0_14px_rgba(37,99,235,.6)]" /><span className="absolute bottom-[14%] right-[3%] h-2 w-2 rounded-full bg-qx-sky" /></div>
              <div className="absolute inset-7 rounded-full border border-dashed border-qx-blue/25" />
              <div className="qx-orbit-rev absolute inset-7"><span className="absolute left-[8%] top-[22%] h-2 w-2 rounded-full bg-qx-blue/70" /><span className="absolute bottom-0 left-1/2 h-2.5 w-2.5 -translate-x-1/2 translate-y-1/2 rounded-full bg-qx-sky shadow-[0_0_12px_rgba(96,165,250,.7)]" /></div>
              <div className="absolute inset-[3.4rem] rounded-full bg-gradient-to-br from-white to-qx-ice shadow-[0_12px_40px_-12px_rgba(37,99,235,.55)]" />
              <BrandMark size={84} title={null} className="relative drop-shadow-[0_8px_18px_rgba(37,99,235,.35)]" />
            </div>

            <div aria-hidden className="qx-float absolute -left-10 top-28 hidden w-44 rounded-2xl border border-qx-line bg-white/90 p-3 shadow-qx-card backdrop-blur xl:block">
              <p className="font-mono text-[10px] uppercase tracking-[.1em] text-qx-body">Gate · example</p>
              <p className="mt-1 text-sm font-semibold text-qx-ink">Policy evaluated</p>
              <p className="mt-1 font-mono text-[10.5px] text-qx-blue">ALLOW → scoped grant</p></div>
            <div aria-hidden className="qx-float absolute -right-8 top-40 hidden w-44 rounded-2xl border border-qx-line bg-white/90 p-3 shadow-qx-card backdrop-blur xl:block" style={{ animationDelay: "-3.5s" }}>
              <p className="font-mono text-[10px] uppercase tracking-[.1em] text-qx-body">Evidence · example</p>
              <p className="mt-1 text-sm font-semibold text-qx-ink">Record linked</p>
              <p className="mt-1 font-mono text-[10.5px] text-qx-body">E1 until independently observed</p></div>

            <ol className="mt-6 grid gap-2.5 sm:gap-2">
              {HERO_STEPS.map((s, i) => (
                <li key={s.t} className="flex items-center gap-3 rounded-xl border border-qx-line bg-white/80 px-3 py-2.5">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-qx-ice text-qx-blue"><s.icon className="h-4 w-4" aria-hidden /></span>
                  <span className="min-w-0"><span className="block text-[13.5px] font-semibold leading-tight text-qx-ink">{s.t}</span><span className="block text-xs text-qx-body">{s.d}</span></span>
                  <span aria-hidden className="ml-auto font-mono text-[10.5px] text-qx-body">0{i + 1}</span>
                </li>))}
            </ol>
          </figure>
        </div>
      </div>
    </section>);
}
