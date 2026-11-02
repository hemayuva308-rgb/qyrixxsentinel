"use client";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { KeyRound, ShieldCheck, UserRound } from "lucide-react";
import { BrandMark } from "@/components/brand/BrandMark";
import { Btn, ErrorBox } from "@/components/ui";

type Stage = "password" | "mfa" | "enroll" | "codes";

async function post(path: string, body: Record<string, string>) {
  const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).catch(() => null);
  if (!r) return { ok: false, j: { detail: "Cannot reach the server" } as Record<string, unknown> };
  return { ok: r.ok, j: (await r.json().catch(() => ({}))) as Record<string, unknown> };
}

export default function Login() {
  const router = useRouter();
  const [mode, setMode] = useState<"account" | "key">("account");
  const [stage, setStage] = useState<Stage>("password");
  const [f, setF] = useState({ tenant: "", email: "", password: "", code: "", recovery: "", token: "" });
  const [enroll, setEnroll] = useState<{ secret: string; uri: string } | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF((x) => ({ ...x, [k]: e.target.value }));

  function go() {
    // Only internal product paths are honoured (no open redirect).
    const next = new URLSearchParams(window.location.search).get("next") ?? "";
    router.push(/^\/(dashboard|forensic)(\/[\w-]*)*$/.test(next) ? next : "/dashboard"); router.refresh();
  }

  async function step(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setErr(null);
    try {
      if (mode === "key") {
        const { ok, j } = await post("/api/session", { token: f.token });
        return ok ? go() : setErr(String(j.detail ?? "Sign-in failed"));
      }
      if (stage === "password") {
        const { ok, j } = await post("/api/account/login", { tenant: f.tenant.trim(), email: f.email.trim(), password: f.password });
        if (!ok) return setErr(String(j.detail ?? "Sign-in failed"));
        setF((x) => ({ ...x, password: "" }));
        if (j.status === "ok") return go();
        if (j.status === "mfa_required") return setStage("mfa");
        const s = await post("/api/account/enroll-start", {});
        if (!s.ok) return setErr(String(s.j.detail ?? "Enrolment failed"));
        setEnroll({ secret: String(s.j.secret), uri: String(s.j.otpauth_uri) });
        return setStage("enroll");
      }
      if (stage === "mfa") {
        const body: Record<string, string> = f.recovery ? { recovery_code: f.recovery.trim() } : { code: f.code.trim() };
        const { ok, j } = await post("/api/account/mfa", body);
        return ok ? go() : setErr(String(j.detail ?? "Invalid code"));
      }
      if (stage === "enroll") {
        const { ok, j } = await post("/api/account/enroll-confirm", { code: f.code.trim() });
        if (!ok) return setErr(String(j.detail ?? "Invalid code"));
        setEnroll(null); setCodes((j.recovery_codes as string[]) ?? []);
        return setStage("codes");
      }
      if (stage === "codes") return go();
    } finally { setBusy(false); }
  }

  const tab = (m: "account" | "key", label: string, Icon: typeof KeyRound) => (
    <button type="button" onClick={() => { setMode(m); setErr(null); setStage("password"); }}
      className={`flex flex-1 items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs ${mode === m ? "bg-white/10 text-ink" : "text-mute hover:text-ink"}`}>
      <Icon className="h-3.5 w-3.5" />{label}</button>);

  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-4">
      <div className="mb-6 flex items-center gap-3 text-lg font-semibold tracking-[.2em]"><BrandMark size={34} title={null} />QYRIX <span className="text-neon">SENTINEL</span></div>
      <form onSubmit={step} className="space-y-3 rounded-2xl border border-white/10 bg-card/80 p-5 shadow-glow">
        <div className="flex gap-1 rounded-xl border border-white/10 p-1">{tab("account", "Organisation account", UserRound)}{tab("key", "API key", KeyRound)}</div>
        {mode === "key" && (<>
          <p className="text-sm text-mute">Paste an operator token or a tenant API key (qsk_…). It is exchanged for an expiring server-side session; the key itself is never stored in the browser.</p>
          <div><label htmlFor="t">API key or operator token</label><input id="t" type="password" autoComplete="off" required minLength={24} value={f.token} onChange={set("token")} /></div>
        </>)}
        {mode === "account" && stage === "password" && (<>
          <p className="text-sm text-mute">Sign in with your organisation account. Two-factor authentication is required.</p>
          <div><label htmlFor="org">Organisation ID</label><input id="org" autoComplete="organization" required pattern="[a-z0-9][a-z0-9-]{2,39}" value={f.tenant} onChange={set("tenant")} /></div>
          <div><label htmlFor="em">E-mail</label><input id="em" type="email" autoComplete="username" required value={f.email} onChange={set("email")} /></div>
          <div><label htmlFor="pw">Password</label><input id="pw" type="password" autoComplete="current-password" required value={f.password} onChange={set("password")} /></div>
          <Link href="/reset" className="block text-right text-xs text-mute hover:text-ink">Forgot password?</Link>
        </>)}
        {mode === "account" && stage === "mfa" && (<>
          <p className="text-sm text-mute">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
          <div><label htmlFor="code">Authenticator code</label><input id="code" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" value={f.code} onChange={set("code")} disabled={!!f.recovery} /></div>
          <div><label htmlFor="rc">Recovery code (instead)</label><input id="rc" autoComplete="off" value={f.recovery} onChange={set("recovery")} /></div>
        </>)}
        {mode === "account" && stage === "enroll" && enroll && (<>
          <p className="text-sm text-mute"><ShieldCheck className="mr-1 inline h-4 w-4 text-neon" />Set up two-factor authentication: add this key to an authenticator app (or open the link on your phone), then enter the current code. It is shown only once.</p>
          <code className="block select-all break-all rounded-lg border border-white/10 bg-black/40 p-3 text-xs">{enroll.secret}</code>
          <a href={enroll.uri} className="block break-all text-xs text-neon">Open in authenticator app</a>
          <div><label htmlFor="ec">Current code</label><input id="ec" inputMode="numeric" autoComplete="one-time-code" required pattern="\d{6}" value={f.code} onChange={set("code")} /></div>
        </>)}
        {mode === "account" && stage === "codes" && (<>
          <p className="text-sm text-mute">Two-factor authentication is on. Save these recovery codes somewhere safe and offline. Each works once, and they will not be shown again.</p>
          <ul className="grid grid-cols-2 gap-1 rounded-lg border border-white/10 bg-black/40 p-3 font-mono text-xs">{codes.map((c) => <li key={c} className="select-all">{c}</li>)}</ul>
        </>)}
        {err && <ErrorBox msg={err} />}
        <Btn type="submit" loading={busy}>{stage === "codes" ? "I SAVED THEM, CONTINUE" : "CONTINUE"}</Btn>
      </form>
      <Link href="/" className="mt-4 text-center text-xs text-mute hover:text-ink">← Back to qyrix sentinel website</Link>
    </main>);
}
