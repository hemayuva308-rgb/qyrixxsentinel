import { useId } from "react";

// QYRIX SENTINEL mark: geometric shield; an open "Q" ring around the core node; the execution path
// leaves the core through a checkpoint (cyan gate) set into the ring's opening. Source of truth for
// public/brand/*.svg and app/icon.svg (same geometry).
export const SHIELD = "M32 4 54 11.5V30c0 14.6-9.4 24.8-22 30-12.6-5.2-22-15.4-22-30V11.5L32 4z";
export const RING = "M33.9 39.8A11 11 0 1 1 42.8 30.9";
export const TAIL = "M32 29 46.5 43.5";
export const GATE = "M37.7 38.9 41.9 34.7";

export function BrandMark({ size = 32, mono = false, className = "", title = "QYRIX SENTINEL" }:
  { size?: number; mono?: boolean; className?: string; title?: string | null }) {
  const id = useId().replace(/:/g, "");
  const a11y = title ? { role: "img", "aria-label": title } : { "aria-hidden": true };
  if (mono) return (
    <svg viewBox="0 0 64 64" width={size} height={size} className={className} {...a11y}>
      <defs><mask id={`m${id}`}><path d={SHIELD} fill="#fff" />
        <path d={RING} fill="none" stroke="#000" strokeWidth="4.6" /><path d={TAIL} stroke="#000" strokeWidth="4" strokeLinecap="round" />
        <path d={GATE} stroke="#000" strokeWidth="5.4" /><circle cx="32" cy="29" r="3.6" fill="#000" /></mask></defs>
      <rect width="64" height="64" fill="currentColor" mask={`url(#m${id})`} />
    </svg>);
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} className={className} {...a11y}>
      <defs><linearGradient id={`g${id}`} x1="10" y1="4" x2="54" y2="60" gradientUnits="userSpaceOnUse">
        <stop offset="0" stopColor="#0A1A3F" /><stop offset=".62" stopColor="#1F5BFF" /><stop offset="1" stopColor="#06B6D4" /></linearGradient></defs>
      <path d={SHIELD} fill={`url(#g${id})`} />
      <path d={RING} fill="none" stroke="#fff" strokeWidth="4.6" />
      <path d={TAIL} stroke="#fff" strokeWidth="4" strokeLinecap="round" />
      <path d={GATE} stroke="#67E8F9" strokeWidth="5.4" />
      <circle cx="32" cy="29" r="3.6" fill="#67E8F9" />
    </svg>);
}

export function Wordmark({ tone = "light", className = "" }: { tone?: "light" | "dark"; className?: string }) {
  return (
    <span className={`whitespace-nowrap font-sans text-[15px] tracking-[.18em] ${className}`}>
      <b className={`font-extrabold ${tone === "light" ? "text-site-ink" : "text-ink"}`}>QYRIX</b>{" "}
      <span className={`font-medium ${tone === "light" ? "text-site-blue" : "text-neon"}`}>SENTINEL</span>
    </span>);
}
