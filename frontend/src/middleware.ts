import { NextRequest, NextResponse } from "next/server";

// Only the authenticated product requires a session. The public website, /login and the
// public demo route stay reachable. The backend still authenticates every protected API call.
export function middleware(req: NextRequest) {
  if (!req.cookies.get("qs_session")) {
    const url = new URL("/login", req.url);
    url.searchParams.set("next", req.nextUrl.pathname);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}
export const config = { matcher: ["/dashboard/:path*", "/forensic/:path*", "/enforcement/:path*"] };
