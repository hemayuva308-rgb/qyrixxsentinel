import type { NextRequest } from "next/server";

export const BACKEND = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

/** Client identity forwarded to the backend for auth-failure throttling (the backend trusts it only when
 *  QYRIX_TRUST_CLIENT_HEADER=1). Behind a reverse proxy, that proxy MUST overwrite X-Forwarded-For;
 *  a spoofed value can only dodge the per-client limit, never the global auth-failure ceiling. */
export function clientId(req: NextRequest): string {
  return (req.headers.get("x-forwarded-for") ?? req.headers.get("x-real-ip") ?? "").split(",")[0].trim().slice(0, 64);
}

export function sameOrigin(req: NextRequest): boolean {
  const o = req.headers.get("origin");
  if (!o) return true;
  try { return new URL(o).host === req.headers.get("host"); } catch { return false; }
}
