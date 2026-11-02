import { NextRequest, NextResponse } from "next/server";
import { BACKEND, clientHeader } from "@/lib/backend";
const SCENARIOS = new Set(["safe", "direct", "transformed", "delayed"]);

// Public, unauthenticated demo relay. Only a fixed scenario id is forwarded - never a URL, command, file or payload.
// The backend runs it in a fresh isolated sandbox context and rate-limits per client.
export async function POST(req: NextRequest) {
  const o = req.headers.get("origin");
  if (o && new URL(o).host !== req.headers.get("host")) return NextResponse.json({ detail: "bad origin" }, { status: 403 });
  const body = (await req.json().catch(() => null)) as { scenario?: unknown } | null;
  const scenario = body?.scenario;
  // Strict contract: exactly {"scenario": <fixed id>}. Any other field (URL, command, payload...) is refused, not ignored.
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some((k) => k !== "scenario"))
    return NextResponse.json({ detail: "only a scenario id is accepted" }, { status: 422 });
  if (typeof scenario !== "string" || !SCENARIOS.has(scenario)) return NextResponse.json({ detail: "unknown scenario" }, { status: 422 });
  const r = await fetch(`${BACKEND}/api/v1/demo/run`, {
    method: "POST", cache: "no-store", signal: AbortSignal.timeout(15000),
    headers: { "content-type": "application/json", ...clientHeader(req) },
    body: JSON.stringify({ scenario }),
  }).catch(() => null);
  if (!r) return NextResponse.json({ detail: "demo backend unreachable" }, { status: 502 });
  return new NextResponse(await r.text(), { status: r.status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}
