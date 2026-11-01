import Link from "next/link";
import type { ReactNode } from "react";
import { ArrowRight } from "lucide-react";

export function Container({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`mx-auto w-full max-w-site px-5 sm:px-8 ${className}`}>{children}</div>;
}

export function SectionHead({ eyebrow, title, lead, center = false, dark = false, id }:
  { eyebrow: string; title: ReactNode; lead?: ReactNode; center?: boolean; dark?: boolean; id?: string }) {
  return (
    <div className={`reveal max-w-3xl ${center ? "mx-auto text-center" : ""}`}>
      <p className={`eyebrow ${dark ? "!text-cyan-300" : ""}`}>{eyebrow}</p>
      <h2 id={id} className={`mt-3 text-balance text-3xl font-semibold tracking-[-0.025em] sm:text-[2.6rem] sm:leading-[1.08] ${dark ? "text-white" : "text-site-ink"}`}>{title}</h2>
      {lead && <p className={`mt-4 text-pretty text-base leading-relaxed sm:text-lg ${dark ? "text-slate-300" : "text-site-mute"}`}>{lead}</p>}
    </div>);
}

const btn = {
  primary: "bg-site-ink text-white shadow-[0_8px_24px_-10px_rgba(11,22,48,.6)] hover:bg-site-navy hover:shadow-[0_12px_28px_-10px_rgba(31,91,255,.55)]",
  blue: "bg-site-blue text-white shadow-[0_8px_24px_-10px_rgba(31,91,255,.7)] hover:bg-[#1749d6]",
  ghost: "border border-site-line bg-white text-site-ink hover:border-site-blue/40 hover:text-site-blue",
  dark: "border border-white/15 bg-white/5 text-white hover:bg-white/10",
};
export function ButtonLink({ href, children, kind = "primary", arrow = false, className = "" }:
  { href: string; children: ReactNode; kind?: keyof typeof btn; arrow?: boolean; className?: string }) {
  return (
    <Link href={href} className={`group inline-flex items-center justify-center gap-2 rounded-full px-5 py-2.5 text-sm font-semibold transition duration-300 ease-out active:scale-[.98] ${btn[kind]} ${className}`}>
      {children}{arrow && <ArrowRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5" aria-hidden />}
    </Link>);
}

export function Tag({ children, tone = "blue" }: { children: ReactNode; tone?: "blue" | "amber" | "rose" | "cyan" | "slate" | "violet" }) {
  const t = { blue: "border-site-blue/20 bg-site-blue/[.06] text-site-blue", amber: "border-amber-300/60 bg-amber-50 text-amber-800",
    rose: "border-rose-200 bg-rose-50 text-rose-700", cyan: "border-cyan-200 bg-cyan-50 text-cyan-800",
    slate: "border-site-line bg-site-mist text-site-mute", violet: "border-violet-200 bg-violet-50 text-violet-700" }[tone];
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[10.5px] font-semibold uppercase tracking-[.14em] ${t}`}>{children}</span>;
}

export function PageHero({ eyebrow, title, lead, children }: { eyebrow: string; title: ReactNode; lead: ReactNode; children?: ReactNode }) {
  return (
    <section className="relative overflow-hidden border-b border-site-line bg-gradient-to-b from-site-mist to-white">
      <div aria-hidden className="site-grid absolute inset-0" />
      <div aria-hidden className="absolute -top-40 left-1/2 h-80 w-[44rem] -translate-x-1/2 rounded-full bg-site-blue/10 blur-3xl" />
      <Container className="relative py-16 sm:py-24">
        <p className="eyebrow rise">{eyebrow}</p>
        <h1 className="rise mt-4 max-w-4xl text-balance text-4xl font-semibold tracking-[-0.035em] text-site-ink sm:text-6xl sm:leading-[1.02]" style={{ ["--d" as string]: "80ms" }}>{title}</h1>
        <p className="rise mt-5 max-w-2xl text-pretty text-lg leading-relaxed text-site-mute" style={{ ["--d" as string]: "160ms" }}>{lead}</p>
        {children && <div className="rise mt-8" style={{ ["--d" as string]: "240ms" }}>{children}</div>}
      </Container>
    </section>);
}
