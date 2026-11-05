"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Menu, X } from "lucide-react";
import { BrandMark, Wordmark } from "@/components/brand/BrandMark";
import { DEMO_HREF, NAV_LINKS } from "@/lib/home-content";

/** Site-wide navigation. Hash links go to the homepage sections ("/#..."); Security and Documentation are real pages. */
export const NAV = NAV_LINKS;

export default function SiteHeader() {
  const path = usePathname();
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const toggle = useRef<HTMLButtonElement>(null);
  useEffect(() => { setOpen(false); }, [path]);
  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 8); on();
    window.addEventListener("scroll", on, { passive: true }); return () => window.removeEventListener("scroll", on);
  }, []);
  useEffect(() => {
    if (!open) return;
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); toggle.current?.focus(); } };
    window.addEventListener("keydown", k); return () => window.removeEventListener("keydown", k);
  }, [open]);
  const active = (h: string) => !h.includes("#") && (path === h || path.startsWith(h + "/"));
  return (
    <header className={`sticky top-0 z-50 transition-[background,box-shadow,border-color,backdrop-filter] duration-300 ${scrolled || open ? "border-b border-qx-line/90 bg-white/80 shadow-[0_1px_0_rgba(16,24,40,.02)] backdrop-blur-xl" : "border-b border-transparent bg-white/0"}`}>
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-3 focus:z-50 focus:rounded-md focus:bg-qx-ink focus:px-3 focus:py-2 focus:text-white">Skip to content</a>
      <div className="mx-auto flex h-16 max-w-site items-center gap-6 px-5 sm:px-8">
        <Link href="/" className="flex items-center gap-2.5" aria-label="Qyrix Sentinel home">
          <BrandMark size={30} title={null} /><Wordmark />
        </Link>
        <nav aria-label="Primary" className="ml-2 hidden items-center gap-0.5 lg:flex xl:ml-4">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} aria-current={active(n.href) ? "page" : undefined}
              className={`relative whitespace-nowrap rounded-full px-2.5 py-1.5 text-[13.5px] xl:px-3 font-medium transition-colors duration-200 ${active(n.href) ? "text-qx-ink" : "text-qx-body hover:text-qx-ink"}`}>
              {n.label}
              <span aria-hidden className={`absolute inset-x-3 -bottom-0.5 h-px origin-left bg-qx-blue transition-transform duration-300 ${active(n.href) ? "scale-x-100" : "scale-x-0"}`} />
            </Link>))}
        </nav>
        <div className="ml-auto hidden items-center gap-2 sm:flex">
          <Link href="/login" className="rounded-full px-3 py-2 text-[13.5px] font-semibold text-qx-ink transition hover:text-qx-blue lg:px-2 xl:px-3">Login</Link>
          <Link href={DEMO_HREF} className="shrink-0 whitespace-nowrap rounded-full bg-qx-blue px-4 py-2 text-[13.5px] font-semibold text-white shadow-[0_8px_20px_-10px_rgba(37,99,235,.8)] transition duration-300 hover:bg-[#1d4fd0] active:scale-[.98]">Request a Demo</Link>
        </div>
        <button ref={toggle} type="button" className="ml-auto flex h-11 w-11 items-center justify-center rounded-lg text-qx-ink sm:ml-2 lg:hidden" aria-expanded={open} aria-controls="mobile-nav"
          aria-label={open ? "Close menu" : "Open menu"} onClick={() => setOpen((o) => !o)}>
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>
      <div id="mobile-nav" hidden={!open} className="border-t border-qx-line bg-white lg:hidden">
        <nav aria-label="Mobile" className="mx-auto flex max-w-site flex-col px-5 py-3 sm:px-8">
          {NAV.map((n, i) => (
            <Link key={n.href} href={n.href} aria-current={active(n.href) ? "page" : undefined} style={{ ["--d" as string]: `${i * 30}ms` }} onClick={() => setOpen(false)}
              className="rise flex min-h-12 items-center rounded-lg px-2 text-base font-medium text-qx-ink hover:bg-qx-mist">{n.label}</Link>))}
          <div className="mt-2 grid grid-cols-2 gap-2 border-t border-qx-line pt-3">
            <Link href="/login" onClick={() => setOpen(false)} className="flex min-h-11 items-center justify-center rounded-full border border-qx-line text-sm font-semibold">Login</Link>
            <Link href={DEMO_HREF} onClick={() => setOpen(false)} className="flex min-h-11 items-center justify-center rounded-full bg-qx-blue text-sm font-semibold text-white">Request a Demo</Link>
          </div>
        </nav>
      </div>
    </header>);
}
