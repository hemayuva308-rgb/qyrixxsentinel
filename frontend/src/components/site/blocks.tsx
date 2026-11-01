import Link from "next/link";
import { ArrowUpRight, Building2, Check, FileSearch, GitBranch, HeartPulse, Landmark, Link2, Plus, Rocket, ShieldCheck, Store } from "lucide-react";
import { CUSTOMERS, FAQ, MODULES, PLANS } from "@/lib/site-content";
import { ButtonLink, Container, Tag } from "./primitives";

const MOD_ICON = { inspector: FileSearch, provenance: GitBranch, gate: ShieldCheck, proof: Link2 } as const;

export function ModuleCards() {
  return (
    <div className="relative">
      <div aria-hidden className="absolute left-[12%] right-[12%] top-[52px] hidden h-px bg-gradient-to-r from-site-blue/10 via-site-blue/40 to-site-cyan/10 lg:block" />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {MODULES.map((m, i) => {
          const Icon = MOD_ICON[m.id];
          return (
            <Link key={m.id} href={`/features#${m.id}`} style={{ ["--d" as string]: `${i * 90}ms` }}
              className="reveal group relative flex flex-col rounded-3xl border border-site-line bg-white p-6 shadow-soft transition duration-500 ease-out hover:-translate-y-1 hover:border-site-blue/30 hover:shadow-lift focus-visible:-translate-y-1">
              <span aria-hidden className="pointer-events-none absolute inset-0 rounded-3xl opacity-0 transition duration-500 group-hover:opacity-100" style={{ background: "radial-gradient(400px 160px at 50% 0%, rgba(31,91,255,.08), transparent)" }} />
              <div className="relative flex items-center justify-between">
                <span className="grid h-12 w-12 place-items-center rounded-2xl border border-site-blue/15 bg-gradient-to-br from-white to-site-blue/[.08] text-site-blue transition duration-500 group-hover:-rotate-6 group-hover:scale-110 group-hover:border-site-blue/40">
                  <Icon className="h-5 w-5" /></span>
                <span className="font-mono text-xs text-site-mute">{m.n}</span>
              </div>
              <h3 className="relative mt-5 text-lg font-semibold tracking-tight text-site-ink">{m.name}</h3>
              <dl className="relative mt-3 space-y-3 text-sm">
                <div><dt className="font-mono text-[10.5px] font-semibold uppercase tracking-[.16em] text-site-mute">Input</dt><dd className="mt-0.5 text-site-ink/90">{m.input}</dd></div>
                <div><dt className="font-mono text-[10.5px] font-semibold uppercase tracking-[.16em] text-site-mute">Operation</dt><dd className="mt-0.5 leading-relaxed text-site-mute">{m.op}</dd></div>
                <div><dt className="font-mono text-[10.5px] font-semibold uppercase tracking-[.16em] text-site-mute">Output</dt><dd className="mt-0.5 font-medium text-site-ink">{m.out}</dd></div>
              </dl>
              <span className="relative mt-auto inline-flex items-center gap-1 pt-5 text-sm font-semibold text-site-blue">Details<ArrowUpRight className="h-4 w-4 transition-transform duration-300 group-hover:-translate-y-0.5 group-hover:translate-x-0.5" /></span>
            </Link>);
        })}
      </div>
    </div>);
}

const CUST_ICON = [Rocket, Building2, Landmark, HeartPulse, Store];
export function CustomerBento() {
  return (
    <div className="grid gap-4 md:grid-cols-3">
      {CUSTOMERS.map((c, i) => {
        const Icon = CUST_ICON[i];
        const big = "big" in c && c.big;
        return (
          <div key={c.t} style={{ ["--d" as string]: `${i * 80}ms` }}
            className={`reveal group relative overflow-hidden rounded-3xl border p-6 transition duration-500 hover:-translate-y-0.5 ${big ? "border-transparent bg-gradient-to-br from-site-navy to-[#1a3a8f] text-white md:col-span-2 md:p-9" : "border-site-line bg-white hover:shadow-lift"}`}>
            {big && <div aria-hidden className="site-grid-dark absolute inset-0 opacity-50" />}
            <Icon className={`relative h-6 w-6 ${big ? "text-cyan-300" : "text-site-blue"}`} />
            <h3 className={`relative mt-4 font-semibold tracking-tight ${big ? "text-2xl md:text-3xl" : "text-lg text-site-ink"}`}>{c.t}</h3>
            <p className={`relative mt-2 leading-relaxed ${big ? "max-w-md text-slate-300 md:text-lg" : "text-sm text-site-mute"}`}>{c.d}</p>
            {big && <p className="relative mt-6 font-mono text-[11px] uppercase tracking-[.18em] text-slate-400">Use cases · no customer deployments are claimed</p>}
          </div>);
      })}
    </div>);
}

export function PricingCards() {
  return (
    <div>
      <div className="reveal mb-6 flex flex-wrap items-center gap-2"><Tag tone="amber">Proposed launch pricing</Tag>
        <span className="text-sm text-site-mute">Billing is not live yet. Prices and terms will be confirmed in a written agreement.</span></div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {PLANS.map((p, i) => {
          const featured = "featured" in p && p.featured;
          return (
            <div key={p.id} style={{ ["--d" as string]: `${i * 90}ms` }}
              className={`reveal group relative flex flex-col rounded-3xl border p-6 transition duration-500 hover:-translate-y-1 ${featured ? "border-site-blue/40 bg-white shadow-ring" : "border-site-line bg-white shadow-soft hover:shadow-lift"}`}>
              {featured && <span className="absolute -top-3 left-6 rounded-full bg-site-blue px-3 py-1 font-mono text-[10px] font-bold tracking-[.16em] text-white">RECOMMENDED</span>}
              <h3 className="text-sm font-semibold uppercase tracking-[.14em] text-site-mute">{p.name}</h3>
              <p className="mt-4 flex items-baseline gap-1.5"><span className="text-[2.15rem] font-semibold tracking-tight text-site-ink">{p.price}</span><span className="text-sm text-site-mute">{p.per}</span></p>
              <p className="mt-2 text-sm text-site-mute">{p.blurb}</p>
              <ul className="mt-6 space-y-2.5 text-sm">
                {p.f.map((f) => <li key={f} className="flex gap-2.5"><Check className="mt-0.5 h-4 w-4 shrink-0 text-site-cyan" aria-hidden /><span className="text-site-ink/90">{f}</span></li>)}
              </ul>
              <div className="mt-auto pt-7"><ButtonLink href={`/contact?topic=${p.id === "enterprise" ? "enterprise-demo" : "pricing-" + p.id}`} kind={featured ? "blue" : "ghost"} className="w-full">{p.cta}</ButtonLink></div>
            </div>);
        })}
      </div>
    </div>);
}

export function FaqList({ items = FAQ }: { items?: readonly { q: string; a: string }[] }) {
  return (
    <div className="divide-y divide-site-line rounded-3xl border border-site-line bg-white">
      {items.map((f) => (
        <details key={f.q} className="group px-6 py-1 [&_summary::-webkit-details-marker]:hidden">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-4 rounded-lg py-4 text-left text-[15px] font-semibold text-site-ink transition hover:text-site-blue">
            {f.q}
            <Plus aria-hidden className="h-4 w-4 shrink-0 text-site-mute transition-transform duration-300 group-open:rotate-45 group-open:text-site-blue" />
          </summary>
          <p className="fade pb-5 pr-8 text-[15px] leading-relaxed text-site-mute">{f.a}</p>
        </details>))}
    </div>);
}

export function FinalCta() {
  return (
    <section className="relative overflow-hidden bg-site-deep py-24 text-white sm:py-32">
      <div aria-hidden className="site-grid-dark absolute inset-0" />
      <div aria-hidden className="absolute left-1/2 top-0 h-96 w-[60rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-site-blue/30 blur-3xl" />
      <Container className="relative text-center">
        <p className="eyebrow reveal !text-cyan-300">Detection is not prevention</p>
        <h2 className="reveal mx-auto mt-4 max-w-3xl text-balance text-4xl font-semibold tracking-[-0.03em] sm:text-5xl">Put a security checkpoint between your AI and every tool.</h2>
        <div className="reveal mt-10 flex flex-wrap justify-center gap-3" style={{ ["--d" as string]: "120ms" }}>
          <ButtonLink href="/contact?topic=get-started" kind="blue" arrow>Get Started</ButtonLink>
          <ButtonLink href="/contact?topic=enterprise-demo" kind="dark">Request Enterprise Demo</ButtonLink>
        </div>
      </Container>
    </section>);
}
