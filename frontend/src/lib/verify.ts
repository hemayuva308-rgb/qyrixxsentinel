// Browser-side, independent re-verification of v2 proof records (canonical JSON + SHA-256 hash chain).
// Mirrors backend/app/proof.py: json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True).
import type { Proof } from "./types";

function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") {
    // JSON.stringify escapes quotes/backslash/control chars like Python; then escape every non-printable-ASCII
    // UTF-16 code unit as \uXXXX (lowercase hex), which is what ensure_ascii=True produces.
    return JSON.stringify(v).replace(/[^\x20-\x7e]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const o = v as Record<string, unknown>;
  return "{" + Object.keys(o).sort().map((k) => canonical(k) + ":" + canonical(o[k])).join(",") + "}";
}

async function sha256(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface BrowserVerify { status: "PARTIAL_UNANCHORED" | "FAIL" | "EMPTY"; checked: number; brokenAt: number | null; head: string | null }

export async function verifyInBrowser(chain: Proof[]): Promise<BrowserVerify> {
  if (!chain.length) return { status: "EMPTY", checked: 0, brokenAt: null, head: null };
  let prev = "0".repeat(64);
  for (let i = 0; i < chain.length; i++) {
    const r = chain[i] as unknown as Record<string, unknown>;
    if (r.v !== 2 || r.n !== i + 1 || r.prev !== prev) return { status: "FAIL", checked: i, brokenAt: i + 1, head: null };
    const { hash, ...rest } = r;
    if ((await sha256(prev + canonical(rest))) !== hash) return { status: "FAIL", checked: i, brokenAt: i + 1, head: null };
    prev = hash as string;
  }
  return { status: "PARTIAL_UNANCHORED", checked: chain.length, brokenAt: null, head: prev };
}
