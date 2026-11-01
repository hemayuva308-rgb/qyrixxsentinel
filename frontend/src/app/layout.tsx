import type { Metadata } from "next";
import "./globals.css";
import { ToastProvider } from "@/components/ui";

export const metadata: Metadata = { title: "Qyrix Sentinel", description: "Trust-to-Execution Guard" };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (<html lang="en"><body><ToastProvider>{children}</ToastProvider></body></html>);
}
