"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { BrandMark } from "@/components/brand/BrandMark";
import { Btn, ErrorBox } from "@/components/ui";

// Invitation acceptance and password reset. The single-use token arrives in the URL FRAGMENT (#token=...), which
// browsers never send to servers, so it does not appear in access logs; it is removed from the address bar at once.
export function AccountTokenForm({ kind }: { kind: "invite" | "reset" }) {
  const [token, setToken] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const t = new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
    setToken(t);
    if (t) history.replaceState(null, "", window.location.pathname);
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(null); setMsg(null);
    if (token && pw !== pw2) return setErr("Passwords do not match");
    setBusy(true);
    const path = !token ? "/api/account/forgot" : kind === "invite" ? "/api/account/invite-accept" : "/api/account/reset";
    const body = !token ? { email } : kind === "invite" ? { token, name, password: pw } : { token, new_password: pw };
    const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).catch(() => null);
    setBusy(false);
    if (!r) return setErr("Cannot reach the server");
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return setErr(j.detail ?? "Request failed");
    setPw(""); setPw2("");
    setMsg(!token ? String(j.notice ?? "If the account exists, a reset link was sent.")
      : kind === "invite" ? "Invitation accepted. Sign in to set up two-factor authentication." : "Password changed. Sign in again (two-factor authentication is still required).");
  }

  const title = kind === "invite" ? "Accept invitation" : token ? "Choose a new password" : "Reset your password";
  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-4">
      <div className="mb-6 flex items-center gap-3 text-lg font-semibold tracking-[.2em]"><BrandMark size={34} title={null} />QYRIX <span className="text-neon">SENTINEL</span></div>
      <form onSubmit={submit} className="space-y-3 rounded-2xl border border-white/10 bg-card/80 p-5 shadow-glow">
        <h1 className="text-sm font-semibold">{title}</h1>
        {kind === "invite" && !token && <p className="text-sm text-mute">This invitation link is incomplete. Open the full link you received.</p>}
        {kind === "reset" && !token && (<>
          <p className="text-sm text-mute">Enter your account e-mail. If e-mail delivery is configured, a single-use link will be sent. Otherwise ask an organisation admin to issue a reset.</p>
          <div><label htmlFor="em">E-mail</label><input id="em" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></div>
        </>)}
        {token && (<>
          {kind === "invite" && <div><label htmlFor="nm">Your name</label><input id="nm" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} /></div>}
          <p className="text-xs text-mute">{kind === "invite" ? "Already have an account? Enter its current password to link it." : "At least 12 characters; avoid common or repeated phrases."}</p>
          <div><label htmlFor="pw">Password</label><input id="pw" type="password" autoComplete="new-password" required minLength={12} maxLength={256} value={pw} onChange={(e) => setPw(e.target.value)} /></div>
          <div><label htmlFor="pw2">Repeat password</label><input id="pw2" type="password" autoComplete="new-password" required value={pw2} onChange={(e) => setPw2(e.target.value)} /></div>
        </>)}
        {err && <ErrorBox msg={err} />}
        {msg && <p className="rounded-lg border border-neon/30 p-3 text-sm">{msg}</p>}
        {(token || kind === "reset") && !msg && <Btn type="submit" loading={busy}>CONTINUE</Btn>}
      </form>
      <Link href="/login" className="mt-4 text-center text-xs text-mute hover:text-ink">← Sign in</Link>
    </main>);
}
