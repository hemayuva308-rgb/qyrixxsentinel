"use client";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { KeyRound } from "lucide-react";
import { BrandMark } from "@/components/brand/BrandMark";
import { Btn, ErrorBox } from "@/components/ui";

export default function Login() {
  const router = useRouter();
  const [token, setToken] = useState(""); const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setErr(null);
    const r = await fetch("/api/session", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) }).catch(() => null);
    setBusy(false);
    if (!r) return setErr("Cannot reach the server");
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return setErr(j.detail ?? "Login failed");
    // Only internal product paths are honoured (no open redirect).
    const next = new URLSearchParams(window.location.search).get("next") ?? "";
    router.push(/^\/(dashboard|forensic)(\/[\w-]*)*$/.test(next) ? next : "/dashboard"); router.refresh();
  }
  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-4">
      <div className="mb-6 flex items-center gap-3 text-lg font-semibold tracking-[.2em]"><BrandMark size={34} title={null} />QYRIX <span className="text-neon">SENTINEL</span></div>
      <form onSubmit={submit} className="space-y-3 rounded-2xl border border-white/10 bg-card/80 p-5 shadow-glow">
        <p className="text-sm text-mute">Operator sign-in. Paste an operator token or a tenant API key (qsk_…). It is exchanged for an expiring server-side session; the key itself is never stored in the browser.</p>
        <div><label htmlFor="t">API key or operator token</label><input id="t" type="password" autoComplete="off" required minLength={24} value={token} onChange={(e) => setToken(e.target.value)} /></div>
        {err && <ErrorBox msg={err} />}
        <Btn type="submit" loading={busy}><KeyRound className="h-3.5 w-3.5" />SIGN IN</Btn>
      </form>
      <Link href="/" className="mt-4 text-center text-xs text-mute hover:text-ink">← Back to qyrix sentinel website</Link>
    </main>);
}
