import { NextRequest, NextResponse } from "next/server";
export function middleware(req: NextRequest) {
  if (!req.cookies.get("qs_token")) return NextResponse.redirect(new URL("/login", req.url));
  return NextResponse.next();
}
export const config = { matcher: ["/((?!login|api|_next|favicon.ico).*)"] };
