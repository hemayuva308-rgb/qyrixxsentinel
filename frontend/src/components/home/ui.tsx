import type { ReactNode } from "react";
import type { CapStatus } from "@/lib/home-content";

type Tone = "white" | "mist" | "ice" | "navy";
const TONE: Record<Tone, string> = {
  white: "bg-white", mist: "bg-qx-mist border-y border-qx-line", ice: "bg-gradient-to-b from-qx-ice/70 to-white", navy: "bg-qx-ink text-white",
};

/** Page section: consistent vertical rhythm, anchor offset for the sticky header, optional background tone. */
export function Section({ id, tone = "white", labelledBy, children, className = "" }:
  { id?: string; tone?: Tone; labelledBy?: string; children: ReactNode; className?: string }) {
  return (
    <section id={id} aria-labelledby={labelledBy} className={`qx-section relative overflow-hidden py-20 sm:py-28 ${TONE[tone]} ${className}`}>
      <div className="relative mx-auto w-full max-w-site px-5 sm:px-8">{children}</div>
    </section>);
}

export function Heading({ id, eyebrow, title, lead, center = false, dark = false }:
  { id: string; eyebrow: string; title: ReactNode; lead?: ReactNode; center?: boolean; dark?: boolean }) {
  return (
    <div className={`reveal max-w-3xl ${center ? "mx-auto text-center" : ""}`}>
      <p className={`font-mono text-[11px] font-semibold uppercase tracking-[.22em] ${dark ? "text-qx-sky" : "text-qx-blue"}`}>{eyebrow}</p>
      <h2 id={id} className={`mt-3 text-balance text-3xl font-semibold tracking-[-0.03em] sm:text-[2.6rem] sm:leading-[1.08] ${dark ? "text-white" : "text-qx-ink"}`}>{title}</h2>
      {lead && <p className={`mt-4 text-pretty text-base leading-relaxed sm:text-lg ${dark ? "text-slate-300" : "text-qx-body"}`}>{lead}</p>}
    </div>);
}

const CHIP: Record<string, string> = {
  Implemented: "border-emerald-200 bg-emerald-50 text-emerald-800",
  Prototype: "border-amber-200 bg-amber-50 text-amber-900",
  "In validation": "border-blue-200 bg-blue-50 text-blue-800",
  "Opt-in": "border-slate-200 bg-slate-50 text-slate-700",
  Planned: "border-slate-200 bg-slate-50 text-slate-700",
  "Not certified": "border-rose-200 bg-rose-50 text-rose-800",
};
export function StatusChip({ children, kind }: { children: ReactNode; kind: CapStatus | "Planned" | "Not certified" }) {
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 font-mono text-[10.5px] font-semibold uppercase tracking-[.1em] ${CHIP[kind]}`}>{children}</span>;
}

export const CARD = "qx-card rounded-2xl border border-qx-line bg-white shadow-qx-card";

export function IconTile({ icon: Icon, tone = "blue" }: { icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>; tone?: "blue" | "slate" }) {
  return (
    <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border ${tone === "blue" ? "border-qx-blue/15 bg-gradient-to-br from-qx-ice to-white text-qx-blue" : "border-qx-line bg-qx-mist text-qx-body"}`}>
      <Icon className="h-5 w-5" aria-hidden />
    </span>);
}
