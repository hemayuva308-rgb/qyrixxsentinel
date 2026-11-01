import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "QYRIX SENTINEL - Secure Every AI Action. Before Execution.", template: "%s | QYRIX SENTINEL" },
  description: "Trust-aware execution security for AI agents: inspect instructions, track provenance, enforce deterministic ALLOW/BLOCK before any tool runs, and verify the evidence.",
  applicationName: "QYRIX SENTINEL",
};
export const viewport: Viewport = { themeColor: "#0A1A3F" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (<html lang="en"><body>{children}</body></html>);
}
