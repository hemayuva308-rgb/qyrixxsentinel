import { NextRequest, NextResponse } from "next/server";
const BACKEND = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

// Same-origin proxy: browser never sees the API token and the API needs no CORS.
async function handle(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const rel = path.join("/");
  if (rel.includes("..") || !(rel === "health" || rel.startsWith("sentinel/") || rel === "tools/execute")) return NextResponse.json({ detail: "not found" }, { status: 404 });
  if (req.method !== "GET") {
    const o = req.headers.get("origin");
    if (req.headers.get("x-qs-csrf") !== "1" || (o && new URL(o).host !== req.headers.get("host")))
      return NextResponse.json({ detail: "csrf check failed" }, { status: 403 });
  }
  const token = req.cookies.get("qs_token")?.value;
  if (!token) return NextResponse.json({ detail: "not authenticated" }, { status: 401 });
  const r = await fetch(`${BACKEND}/api/v1/${rel}${req.nextUrl.search}`, {
    method: req.method,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: req.method === "GET" ? undefined : await req.text(),
    cache: "no-store", signal: AbortSignal.timeout(30000),
  }).catch(() => null);
  if (!r) return NextResponse.json({ detail: "backend unreachable" }, { status: 502 });
  return new NextResponse(await r.text(), { status: r.status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}
export { handle as GET, handle as POST };
