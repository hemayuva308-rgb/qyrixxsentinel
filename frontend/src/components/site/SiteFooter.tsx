import Link from "next/link";
import { BrandMark, Wordmark } from "@/components/brand/BrandMark";

const COLS = [
  { h: "Product", l: [["/features", "Features"], ["/how-it-works", "How It Works"], ["/forensic-lab", "Forensic Lab"], ["/pricing", "Pricing"]] },
  { h: "Trust", l: [["/security", "Security"], ["/docs", "Documentation"], ["/privacy", "Privacy"], ["/terms", "Terms"]] },
  { h: "Company", l: [["/contact", "Contact"], ["/contact?topic=enterprise-demo", "Request a demo"], ["/login", "Operator login"]] },
];

export default function SiteFooter() {
  return (
    <footer className="border-t border-site-line bg-site-mist">
      <div className="mx-auto grid max-w-site gap-10 px-5 py-14 sm:px-8 md:grid-cols-[1.4fr_repeat(3,1fr)]">
        <div>
          <Link href="/" className="inline-flex items-center gap-2.5" aria-label="QYRIX SENTINEL home"><BrandMark size={28} title={null} /><Wordmark /></Link>
          <p className="mt-4 max-w-xs text-sm leading-relaxed text-site-mute">Detection is not prevention. We enforce from trust to execution.</p>
          <p className="mt-4 max-w-xs text-xs leading-relaxed text-site-mute/80">Controlled beta. Single-tenant MVP; see Security for current limits.</p>
        </div>
        {COLS.map((c) => (
          <nav key={c.h} aria-label={c.h}>
            <h3 className="text-xs font-semibold uppercase tracking-[.16em] text-site-ink">{c.h}</h3>
            <ul className="mt-4 space-y-2.5">{c.l.map(([href, label]) => (
              <li key={href}><Link href={href} className="text-sm text-site-mute transition hover:text-site-blue">{label}</Link></li>))}</ul>
          </nav>))}
      </div>
      <div className="border-t border-site-line">
        <div className="mx-auto flex max-w-site flex-wrap items-center justify-between gap-2 px-5 py-5 text-xs text-site-mute sm:px-8">
          <span>© {new Date().getFullYear()} QYRIX SENTINEL. Trust-to-Execution Guard.</span>
          <span className="font-mono">Pricing shown is proposed launch pricing.</span>
        </div>
      </div>
    </footer>);
}
