import type { Metadata } from "next";
import Hero from "@/components/home/Hero";
import TrustProblemSection from "@/components/home/TrustProblemSection";
import PlatformOverview from "@/components/home/PlatformOverview";
import ArchitectureSection from "@/components/home/ArchitectureSection";
import HowItWorksSection from "@/components/home/HowItWorksSection";
import SecurityCapabilities from "@/components/home/SecurityCapabilities";
import IntegrationsSection from "@/components/home/IntegrationsSection";
import EvidenceSection from "@/components/home/EvidenceSection";
import UseCasesSection from "@/components/home/UseCasesSection";
import WhySection from "@/components/home/WhySection";
import ProductStatusSection from "@/components/home/ProductStatusSection";
import FAQSection from "@/components/home/FAQSection";
import FinalCTA from "@/components/home/FinalCTA";

const TITLE = "Qyrix Sentinel — Trust Every Execution. Verify Every Action.";
const DESCRIPTION = "Qyrix Sentinel helps secure AI agent and automation tool execution through deterministic authorization, scoped grants, controlled egress, and verifiable evidence.";

// No canonical URL and no og:image: the production domain and a real share image are not defined in this repository.
export const metadata: Metadata = {
  title: { absolute: TITLE },
  description: DESCRIPTION,
  openGraph: { type: "website", title: TITLE, description: DESCRIPTION, siteName: "Qyrix Sentinel" },
  twitter: { card: "summary", title: TITLE, description: DESCRIPTION },
};

// Navbar and footer come from the (site) layout. Sections follow the homepage specification, in order.
export default function Home() {
  return (
    <>
      <Hero />
      <TrustProblemSection />
      <PlatformOverview />
      <ArchitectureSection />
      <HowItWorksSection />
      <SecurityCapabilities />
      <IntegrationsSection />
      <EvidenceSection />
      <UseCasesSection />
      <WhySection />
      <ProductStatusSection />
      <FAQSection />
      <FinalCTA />
    </>);
}
