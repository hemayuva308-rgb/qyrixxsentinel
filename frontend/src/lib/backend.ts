import type { NextRequest } from "next/server";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";

export const BACKEND = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

/** Visitor IP for per-IP rate limits - derived ONLY from proxies the operator declared trusted.
 *  Next.js keeps a client-supplied X-Forwarded-For as-is (it only fills the header when absent), so the header is
 *  attacker-controlled unless a trusted reverse proxy overwrites/appends it. With QYRIX_TRUSTED_PROXY_HOPS=N the client
 *  is the N-th entry from the right (the address the outermost trusted proxy saw). With N=0 (no proxy) the address is
 *  unknowable here and "unknown" is reported: the backend then skips per-IP limits (per-account + global still apply). */
export function clientIp(req: NextRequest): string {
  const hops = Number.parseInt(process.env.QYRIX_TRUSTED_PROXY_HOPS ?? "0", 10);
  if (!Number.isFinite(hops) || hops <= 0) return "unknown";
  const parts = (req.headers.get("x-forwarded-for") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (parts.length < hops) return "unknown";
  const ip = parts[parts.length - hops];
  return isIP(ip) ? ip : "unknown";
}

let key: Buffer | null | undefined;
function sigKey(): Buffer | null {
  if (key !== undefined) return key;
  try {
    const k = readFileSync(process.env.QYRIX_CLIENT_SIG_KEY_FILE ?? "").toString().trim();
    key = k.length >= 32 && !k.includes("CHANGE_ME") ? Buffer.from(k) : null;
  } catch { key = null; }
  return key;
}

/** Signed client identity for the backend: "v1|<ip>|<ts>|<hmac>" (see backend app/auth.py client_key). Without the
 *  shared key nothing is sent and the backend uses the TCP peer (this container). */
export function clientHeader(req: NextRequest): Record<string, string> {
  const k = sigKey();
  if (!k) return {};
  const msg = `v1|${clientIp(req)}|${Math.floor(Date.now() / 1000)}`;
  return { "x-qyrix-client": `${msg}|${createHmac("sha256", k).update(msg).digest("hex")}` };
}

export function sameOrigin(req: NextRequest): boolean {
  const o = req.headers.get("origin");
  if (!o) return true;
  try { return new URL(o).host === req.headers.get("host"); } catch { return false; }
}
