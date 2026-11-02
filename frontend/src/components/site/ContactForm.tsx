"use client";
import { useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Check, Copy, Mail } from "lucide-react";

const TOPICS: Record<string, string> = {
  "get-started": "Get started / beta access", "enterprise-demo": "Enterprise demo", "pricing-free": "Free plan",
  "pricing-pro": "Pro plan", "pricing-onprem": "On-premise licence", "security": "Security question", "other": "Something else",
};
// Destination is deployment configuration (build-time, public). When it is not set, nothing is "sent":
// the form says so and offers to copy the request instead.
const TO = process.env.NEXT_PUBLIC_CONTACT_EMAIL ?? "";

export default function ContactForm() {
  const q = useSearchParams().get("topic") ?? "";
  const [f, setF] = useState({ topic: q in TOPICS ? q : "enterprise-demo", name: "", email: "", company: "", message: "" });
  const [copied, setCopied] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  const body = useMemo(() => `Topic: ${TOPICS[f.topic]}\nName: ${f.name}\nEmail: ${f.email}\nCompany: ${f.company}\n\n${f.message}`, [f]);

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(null);
    if (TO) { window.location.href = `mailto:${TO}?subject=${encodeURIComponent("QYRIX SENTINEL - " + TOPICS[f.topic])}&body=${encodeURIComponent(body)}`; return; }
    try { await navigator.clipboard.writeText(body); setCopied(true); setTimeout(() => setCopied(false), 4000); }
    catch { setErr("Clipboard is not available in this browser. Select the text manually."); }
  }
  return (
    <form onSubmit={submit} className="space-y-4" aria-describedby="contact-note">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2"><label htmlFor="topic" className="mb-1.5 block text-sm font-medium text-site-ink">Topic</label>
          <select id="topic" className="site-input" value={f.topic} onChange={set("topic")}>{Object.entries(TOPICS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></div>
        <div><label htmlFor="name" className="mb-1.5 block text-sm font-medium text-site-ink">Name</label><input id="name" required maxLength={120} className="site-input" value={f.name} onChange={set("name")} autoComplete="name" /></div>
        <div><label htmlFor="email" className="mb-1.5 block text-sm font-medium text-site-ink">Work email</label><input id="email" type="email" required maxLength={200} className="site-input" value={f.email} onChange={set("email")} autoComplete="email" /></div>
        <div className="sm:col-span-2"><label htmlFor="company" className="mb-1.5 block text-sm font-medium text-site-ink">Company</label><input id="company" maxLength={160} className="site-input" value={f.company} onChange={set("company")} autoComplete="organization" /></div>
        <div className="sm:col-span-2"><label htmlFor="msg" className="mb-1.5 block text-sm font-medium text-site-ink">What should your agents be allowed to do?</label>
          <textarea id="msg" rows={5} required maxLength={4000} className="site-input" value={f.message} onChange={set("message")} placeholder="Tools, destinations, approval needs, deployment model…" /></div>
      </div>
      <p className="text-xs text-site-mute">Please do not include credentials, API keys or confidential data.</p>
      <button type="submit" className="inline-flex items-center gap-2 rounded-full bg-site-ink px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-site-blue active:scale-[.98]">
        {TO ? <><Mail className="h-4 w-4" />Open in email app</> : copied ? <><Check className="h-4 w-4" />Copied to clipboard</> : <><Copy className="h-4 w-4" />Copy request</>}
      </button>
      <p id="contact-note" role="status" className="text-xs text-site-mute">
        {TO ? <>Your email app opens with this message addressed to {TO}. Nothing is sent until you send it.</>
          : <><b className="text-amber-700">Contact address NOT CONFIGURED</b> on this deployment (set NEXT_PUBLIC_CONTACT_EMAIL). The button copies your request so you can send it through your usual channel. This page stores nothing.</>}
      </p>
      {err && <p role="alert" className="text-sm text-rose-600">{err}</p>}
    </form>);
}
