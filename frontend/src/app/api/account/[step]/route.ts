import { NextRequest, NextResponse } from "next/server";
import { BACKEND, clientHeader, sameOrigin } from "@/lib/backend";

// Human-account relay (v1.4). Each step forwards ONLY its allow-listed fields to the backend. The short-lived MFA /
// enrolment challenge is kept in an httpOnly cookie scoped to this route, never exposed to page JavaScript; the final
// session token is stored the same way as API-key sessions (httpOnly qs_session). Recovery codes and the TOTP secret
// are returned to the browser exactly once because the human must save them.
const STEPS: Record<string, { path: string; fields: string[]; challenge?: boolean }> = {
  login: { path: "/api/v1/auth/login", fields: ["tenant", "email", "password"] },
  mfa: { path: "/api/v1/auth/login/mfa", fields: ["code", "recovery_code"], challenge: true },
  "enroll-start": { path: "/api/v1/auth/mfa/enroll/start", fields: [], challenge: true },
  "enroll-confirm": { path: "/api/v1/auth/mfa/enroll/confirm", fields: ["code"], challenge: true },
  "invite-accept": { path: "/api/v1/auth/invitations/accept", fields: ["token", "name", "password"] },
  forgot: { path: "/api/v1/auth/password/forgot", fields: ["email"] },
  reset: { path: "/api/v1/auth/password/reset", fields: ["token", "new_password"] },
};
const CH = "qs_challenge";
const secure = process.env.QYRIX_COOKIE_SECURE === "1";

export async function POST(req: NextRequest, ctx: { params: Promise<{ step: string }> }) {
  const { step } = await ctx.params;
  const spec = STEPS[step];
  if (!spec) return NextResponse.json({ detail: "not found" }, { status: 404 });
  if (!sameOrigin(req)) return NextResponse.json({ detail: "bad origin" }, { status: 403 });
  const raw = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || Object.keys(raw).some((k) => !spec.fields.includes(k)))
    return NextResponse.json({ detail: "unexpected fields" }, { status: 422 });
  const body: Record<string, unknown> = {};
  for (const k of spec.fields) if (typeof raw[k] === "string" && (raw[k] as string).length <= 256) body[k] = raw[k];
  if (spec.challenge) {
    const c = req.cookies.get(CH)?.value;
    if (!c) return NextResponse.json({ detail: "sign-in expired, start again" }, { status: 401 });
    body.challenge = c;
  }
  const r = await fetch(`${BACKEND}${spec.path}`, {
    method: "POST", cache: "no-store", signal: AbortSignal.timeout(20000),
    headers: { "content-type": "application/json", ...clientHeader(req) },
    body: JSON.stringify(body),
  }).catch(() => null);
  if (!r) return NextResponse.json({ detail: "backend unreachable" }, { status: 502 });
  const j = (await r.json().catch(() => ({}))) as Record<string, unknown>;
  if (!r.ok) return NextResponse.json({ detail: typeof j.detail === "string" ? j.detail : "request failed" }, { status: r.status });

  const out: Record<string, unknown> = {};
  for (const k of ["status", "tenant", "role", "expires_at", "secret", "otpauth_uri", "recovery_codes", "notice", "accepted", "reset", "next"])
    if (k in j) out[k] = j[k];
  const res = NextResponse.json(out);
  if (typeof j.challenge === "string")
    res.cookies.set(CH, j.challenge, { httpOnly: true, sameSite: "strict", secure, path: "/api/account", maxAge: 300 });
  if (typeof j.session_token === "string") {
    const maxAge = Math.max(60, Math.floor((Date.parse(String(j.expires_at)) - Date.now()) / 1000));
    res.cookies.set("qs_session", j.session_token, { httpOnly: true, sameSite: "strict", secure, path: "/", maxAge });
    res.cookies.set(CH, "", { httpOnly: true, sameSite: "strict", secure, path: "/api/account", maxAge: 0 });
  }
  return res;
}
