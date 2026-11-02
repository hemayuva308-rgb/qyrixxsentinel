import { NextRequest, NextResponse } from "next/server";
import { BACKEND, clientId, sameOrigin } from "@/lib/backend";

const COOKIE = "qs_session";

// Login: the operator credential (env token or qsk_ API key) is exchanged at the backend for a server-side
// session (qss_...). Only the session token is kept, in an httpOnly cookie; the credential itself is never stored.
// Sessions expire (absolute + idle), and are revoked on logout, key revocation or operator-token rotation.
export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return NextResponse.json({ detail: "bad origin" }, { status: 403 });
  const { token } = (await req.json().catch(() => ({}))) as { token?: string };
  if (typeof token !== "string" || !token || token.length > 512) return NextResponse.json({ detail: "token required" }, { status: 400 });
  const client = clientId(req);
  const r = await fetch(`${BACKEND}/api/v1/auth/session`, {
    method: "POST", cache: "no-store", signal: AbortSignal.timeout(15000),
    headers: { "content-type": "application/json", ...(client ? { "x-qyrix-client": client } : {}) },
    body: JSON.stringify({ credential: token }),
  }).catch(() => null);
  if (!r) return NextResponse.json({ detail: "backend unreachable" }, { status: 502 });
  if (r.status === 429) return NextResponse.json({ detail: "too many attempts, try again later" }, { status: 429 });
  if (r.status === 403) return NextResponse.json({ detail: "this credential cannot open a console session" }, { status: 403 });
  if (!r.ok) return NextResponse.json({ detail: "invalid credential" }, { status: 401 });
  const s = (await r.json()) as { session_token: string; expires_at: string; tenant: string; role: string };
  const maxAge = Math.max(60, Math.floor((Date.parse(s.expires_at) - Date.now()) / 1000));
  const res = NextResponse.json({ ok: true, tenant: s.tenant, role: s.role, expires_at: s.expires_at });
  res.cookies.set(COOKIE, s.session_token, { httpOnly: true, sameSite: "strict", path: "/",
    secure: process.env.QYRIX_COOKIE_SECURE === "1", maxAge });
  res.cookies.delete("qs_token");                       // legacy cookie that held the raw credential
  return res;
}

// Logout revokes the session server-side, then clears the cookie.
export async function DELETE(req: NextRequest) {
  if (!sameOrigin(req)) return NextResponse.json({ detail: "bad origin" }, { status: 403 });
  const tok = req.cookies.get(COOKIE)?.value;
  if (tok) {
    await fetch(`${BACKEND}/api/v1/auth/session`, { method: "DELETE", cache: "no-store", signal: AbortSignal.timeout(10000),
      headers: { authorization: `Bearer ${tok}` } }).catch(() => null);
  }
  const res = NextResponse.json({ ok: true });
  res.cookies.delete(COOKIE);
  res.cookies.delete("qs_token");
  return res;
}
