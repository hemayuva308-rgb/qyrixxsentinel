import SiteHeader from "@/components/site/SiteHeader";
import SiteFooter from "@/components/site/SiteFooter";
import { RevealRoot } from "@/components/site/motion";

// Public marketing website: light theme, separate from the dark authenticated product.
export default function SiteLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="theme-site flex min-h-screen flex-col">
      <SiteHeader />
      <main id="main" className="flex-1">{children}</main>
      <SiteFooter />
      <RevealRoot />
    </div>);
}
