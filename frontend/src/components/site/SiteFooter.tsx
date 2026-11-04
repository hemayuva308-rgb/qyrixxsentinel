import Link from "next/link";
import { BrandMark, Wordmark } from "@/components/brand/BrandMark";
import { FOOTER_COLS } from "@/lib/home-content";

export default function SiteFooter() {
  return (
    <footer className="border-t border-qx-line bg-qx-mist">
      <div className="mx-auto grid max-w-site gap-10 px-5 py-14 sm:px-8 sm:grid-cols-2 lg:grid-cols-[1.5fr_repeat(3,1fr)]">
        <div className="sm:col-span-2 lg:col-span-1">
          <Link href="/" className="inline-flex items-center gap-2.5" aria-label="Qyrix Sentinel home"><BrandMark size={28} title={null} /><Wordmark /></Link>
          <p className="mt-4 max-w-xs text-sm font-medium leading-relaxed text-qx-ink">Trust Every Execution. Verify Every Action.</p>
          <p className="mt-3 max-w-xs text-xs leading-relaxed text-qx-body">A Trust-to-Execution Guard for AI agent and automation tool execution. Prototype-stage; not independently certified.</p>
        </div>
        {FOOTER_COLS.map((c) => (
          <nav key={c.h} aria-label={c.h}>
            <h2 className="text-xs font-semibold uppercase tracking-[.16em] text-qx-ink">{c.h}</h2>
            <ul className="mt-4 space-y-2.5">{c.l.map(([href, label]) => (
              <li key={label}><Link href={href} className="inline-flex min-h-6 items-center text-sm text-qx-body transition hover:text-qx-blue">{label}</Link></li>))}</ul>
          </nav>))}
      </div>
      <div className="border-t border-qx-line">
        <div className="mx-auto flex max-w-site flex-wrap items-center justify-between gap-2 px-5 py-5 text-xs text-qx-body sm:px-8">
          <span>© {new Date().getFullYear()} Qyrix Sentinel</span>
          <span>Prototype-stage product. See product status on the homepage.</span>
        </div>
      </div>
    </footer>);
}
