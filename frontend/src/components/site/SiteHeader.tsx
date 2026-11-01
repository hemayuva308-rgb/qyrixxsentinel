"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Menu, X } from "lucide-react";
import { BrandMark, Wordmark } from "@/components/brand/BrandMark";

export const NAV = [
  { href: "/features", label: "Features" }, { href: "/how-it-works", label: "How it works" },
  { href: "/security", label: "Security" }, { href: "/forensic-lab", label: "Forensic Lab" },
  { href: "/pricing", label: "Pricing" }, { href: "/docs", label: "Docs" },
];

export default function SiteHeader() {
  const path = usePathname();
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => { setOpen(false); }, [path]);
  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 8); on();
    window.addEventListener("scroll", on, { passive: true }); return () => window.removeEventListener("scroll", on);
  }, []);
  useEffect(() => {
    if (!open) return;
    const k = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", k); return () => window.removeEventListener("keydown", k);
  }, [open]);
  const active = (h: string) => path === h || path.startsWith(h + "/");
  return (
    <header className={`sticky top-0 z-50 transition-[background,box-shadow,border-color] duration-300 ${scrolled || open ? "border-b border-site-line/80 bg-white/80 shadow-[0_1px_0_rgba(11,22,48,.02)] backdrop-blur-xl" : "border-b border-transparent bg-white/0"}`}>
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-3 focus:z-50 focus:rounded-md focus:bg-site-ink focus:px-3 focus:py-2 focus:text-white">Skip to content</a>
      <div className="mx-auto flex h-16 max-w-site items-center gap-6 px-5 sm:px-8">
        <Link href="/" className="flex items-center gap-2.5" aria-label="QYRIX SENTINEL home">
          <BrandMark size={30} title={null} /><Wordmark />
        </Link>
        <nav aria-label="Primary" className="ml-4 hidden items-center gap-1 lg:flex">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} aria-current={active(n.href) ? "page" : undefined}
              className={`relative rounded-full px-3 py-1.5 text-[13.5px] font-medium transition-colors duration-200 ${active(n.href) ? "text-site-ink" : "text-site-mute hover:text-site-ink"}`}>
              {n.label}
              <span aria-hidden className={`absolute inset-x-3 -bottom-0.5 h-px origin-left bg-site-blue transition-transform duration-300 ${active(n.href) ? "scale-x-100" : "scale-x-0"}`} />
            </Link>))}
        </nav>
        <div className="ml-auto hidden items-center gap-2 sm:flex">
          <Link href="/login" className="rounded-full px-4 py-2 text-[13.5px] font-semibold text-site-ink transition hover:text-site-blue">Login</Link>
          <Link href="/contact?topic=get-started" className="rounded-full bg-site-ink px-4 py-2 text-[13.5px] font-semibold text-white transition duration-300 hover:bg-site-blue hover:shadow-[0_10px_24px_-10px_rgba(31,91,255,.7)]">Get Started</Link>
        </div>
        <button type="button" className="ml-auto rounded-lg p-2 text-site-ink sm:ml-2 lg:hidden" aria-expanded={open} aria-controls="mobile-nav"
          aria-label={open ? "Close menu" : "Open menu"} onClick={() => setOpen((o) => !o)}>
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>
      <div id="mobile-nav" hidden={!open} className="border-t border-site-line bg-white lg:hidden">
        <nav aria-label="Mobile" className="mx-auto flex max-w-site flex-col px-5 py-3 sm:px-8">
          {NAV.map((n, i) => (
            <Link key={n.href} href={n.href} aria-current={active(n.href) ? "page" : undefined} style={{ ["--d" as string]: `${i * 30}ms` }}
              className="rise rounded-lg px-2 py-3 text-base font-medium text-site-ink hover:bg-site-mist">{n.label}</Link>))}
          <div className="mt-2 grid grid-cols-2 gap-2 border-t border-site-line pt-3">
            <Link href="/login" className="rounded-full border border-site-line py-2.5 text-center text-sm font-semibold">Login</Link>
            <Link href="/contact?topic=get-started" className="rounded-full bg-site-ink py-2.5 text-center text-sm font-semibold text-white">Get Started</Link>
          </div>
        </nav>
      </div>
    </header>);
}
