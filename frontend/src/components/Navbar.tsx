"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LogOut, ShieldCheck } from "lucide-react";
import { api, S } from "@/lib/api";
import type { Status } from "@/lib/types";
import { Badge, usePoll } from "./ui";

export default function Navbar() {
  const path = usePathname(); const router = useRouter();
  const { data, error } = usePoll(() => api<Status>(`${S}/status`), 5000);
  const tab = (href: string, label: string) => (
    <Link href={href} className={`rounded-lg px-3 py-1.5 text-xs font-semibold tracking-wider transition ${path === href ? "bg-neon/15 text-neon shadow-glow" : "text-mute hover:text-ink"}`}>{label}</Link>);
  const out = async () => { await fetch("/api/session", { method: "DELETE" }); router.push("/login"); };
  const degraded = data && (data.gate !== "available" || data.proof !== "available");
  return (
    <nav className="sticky top-0 z-40 border-b border-white/10 bg-bg/85 backdrop-blur">
      <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-3 px-4 py-2.5">
        <div className="flex items-center gap-2 font-semibold tracking-[.2em]"><ShieldCheck className="h-5 w-5 text-neon" />QYRIX <span className="text-neon">SENTINEL</span></div>
        <div className="flex gap-1">{tab("/", "NORMAL DASHBOARD")}{tab("/forensic", "GLOBAL FORENSIC LAB")}</div>
        <div className="ml-auto flex items-center gap-2">
          {error ? <Badge t="crit">● BACKEND OFFLINE</Badge>
            : !data ? <Badge>● CONNECTING</Badge>
            : degraded ? <Badge t="warn">● DEGRADED</Badge> : <Badge t="ok">● SYSTEM ONLINE</Badge>}
          {data && <Badge t="neon">role: {data.role}</Badge>}
          <button onClick={out} aria-label="Sign out" className="rounded-lg p-2 text-mute hover:text-ink"><LogOut className="h-4 w-4" /></button>
        </div>
      </div>
    </nav>);
}
