"use client";
import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from "react";
import { AlertTriangle, Inbox, Loader2 } from "lucide-react";

export function Card({ title, right, children, className = "" }: { title: string; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-2xl border border-white/10 bg-card/80 backdrop-blur p-4 ${className}`}>
      <header className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-[11px] font-semibold tracking-[.18em] text-neon">{title}</h2>{right}
      </header>
      {children}
    </section>
  );
}
const tone = { ok: "bg-ok/15 text-ok border-ok/40", warn: "bg-warn/15 text-warn border-warn/40", crit: "bg-crit/15 text-crit border-crit/40",
  neon: "bg-neon/10 text-neon border-neon/40", mute: "bg-white/5 text-mute border-white/10" };
export function Badge({ t = "mute", children }: { t?: keyof typeof tone; children: ReactNode }) {
  return <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[11px] ${tone[t]}`}>{children}</span>;
}
export const verdictTone = (v: string) => (v === "ALLOW" ? "ok" : "crit") as keyof typeof tone;
export const labelTone = (l: string) => (l === "approved" ? "ok" : l === "untrusted" ? "crit" : "warn") as keyof typeof tone;

export function Btn({ children, onClick, disabled, loading, kind = "primary", type = "button", title }: { children: ReactNode; onClick?: () => void;
  disabled?: boolean; loading?: boolean; kind?: "primary" | "ghost" | "danger"; type?: "button" | "submit"; title?: string }) {
  const k = { primary: "bg-neon/15 border-neon/60 text-neon hover:bg-neon/25", ghost: "bg-white/5 border-white/15 text-ink hover:bg-white/10",
    danger: "bg-crit/15 border-crit/60 text-crit hover:bg-crit/25" }[kind];
  return (
    <button type={type} title={title} onClick={onClick} disabled={disabled || loading}
      className={`inline-flex items-center justify-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold tracking-wider transition disabled:cursor-not-allowed disabled:opacity-40 ${k}`}>
      {loading && <Loader2 className="h-3.5 w-3.5 animate-spin" />}{children}
    </button>
  );
}
export const Loading = ({ label = "Loading" }: { label?: string }) => (
  <div className="flex items-center gap-2 py-6 text-sm text-mute"><Loader2 className="h-4 w-4 animate-spin" />{label}...</div>);
export const Empty = ({ text }: { text: string }) => (
  <div className="flex flex-col items-center gap-2 py-8 text-sm text-mute"><Inbox className="h-5 w-5" />{text}</div>);
export const ErrorBox = ({ msg, retry }: { msg: string; retry?: () => void }) => (
  <div role="alert" className="flex items-start gap-2 rounded-lg border border-crit/40 bg-crit/10 p-3 text-sm text-crit">
    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /><div className="flex-1">{msg}</div>
    {retry && <button onClick={retry} className="underline">retry</button>}
  </div>);
export const Mono = ({ children }: { children: ReactNode }) => <span className="font-mono text-xs break-all">{children}</span>;

// ---- toasts (only real outcomes are reported) ----
type Toast = { id: number; kind: "ok" | "err"; text: string };
const Ctx = createContext<(kind: "ok" | "err", text: string) => void>(() => {});
export const useToast = () => useContext(Ctx);
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const n = useRef(0);
  const push = useCallback((kind: "ok" | "err", text: string) => {
    const id = ++n.current; setItems((x) => [...x, { id, kind, text }]);
    setTimeout(() => setItems((x) => x.filter((t) => t.id !== id)), kind === "ok" ? 3500 : 7000);
  }, []);
  return (
    <Ctx.Provider value={push}>{children}
      <div aria-live="polite" className="fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
        {items.map((t) => (
          <div key={t.id} className={`rounded-lg border p-3 text-sm shadow-glow ${t.kind === "ok" ? "border-ok/40 bg-ok/10 text-ok" : "border-crit/40 bg-crit/10 text-crit"}`}>{t.text}</div>))}
      </div>
    </Ctx.Provider>);
}

// ---- polling hook: no duplicate in-flight requests, pauses when tab hidden ----
export function usePoll<T>(fn: () => Promise<T>, ms: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const busy = useRef(false);
  const fnRef = useRef(fn); fnRef.current = fn;
  const reload = useCallback(async () => {
    if (busy.current) return; busy.current = true;
    try { setData(await fnRef.current()); setError(null); } catch (e) { setError((e as Error).message); } finally { busy.current = false; setLoading(false); }
  }, []);
  useEffect(() => {
    reload(); const id = setInterval(() => { if (!document.hidden) reload(); }, ms);
    return () => clearInterval(id);
  }, [reload, ms]);
  return { data, error, loading, reload };
}
