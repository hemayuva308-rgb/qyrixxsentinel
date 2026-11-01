import { NextRequest, NextResponse } from "next/server";
const BACKEND = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

function sameOrigin(req: NextRequest): boolean {
  const o = req.headers.get("origin");
  return !o || new URL(o).host === req.headers.get("host");
}

// Login: the operator token is verified against the backend, then kept ONLY in an httpOnly cookie.
export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return NextResponse.json({ detail: "bad origin" }, { status: 403 });
  const { token } = (await req.json().catch(() => ({}))) as { token?: string };
  if (!token || token.length > 512) return NextResponse.json({ detail: "token required" }, { status: 400 });
  const r = await fetch(`${BACKEND}/api/v1/sentinel/status`, { headers: { authorization: `Bearer ${token}` }, cache: "no-store" }).catch(() => null);
  if (!r) return NextResponse.json({ detail: "backend unreachable" }, { status: 502 });
  if (!r.ok) return NextResponse.json({ detail: "invalid token" }, { status: 401 });
  const res = NextResponse.json({ ok: true });
  res.cookies.set("qs_token", token, { httpOnly: true, sameSite: "strict", path: "/",
    secure: process.env.QYRIX_COOKIE_SECURE === "1", maxAge: 60 * 60 * 8 });
  return res;
}

export async function DELETE(req: NextRequest) {
  if (!sameOrigin(req)) return NextResponse.json({ detail: "bad origin" }, { status: 403 });
  const res = NextResponse.json({ ok: true });
  res.cookies.delete("qs_token");
  return res;
}
