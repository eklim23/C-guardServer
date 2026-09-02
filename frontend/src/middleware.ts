import { NextResponse, type NextRequest } from "next/server";

const ALLOWED_PREFIXES = ["/cguard-admin", "/cguard-api", "/_next"];
const ALLOWED_PATHS = new Set(["/favicon.ico", "/robots.txt"]);

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (pathname === "/") {
    return NextResponse.redirect(new URL("/cguard-admin", request.url));
  }

  if (ALLOWED_PATHS.has(pathname) || ALLOWED_PREFIXES.some((prefix) => pathname.startsWith(prefix))) {
    return NextResponse.next();
  }

  return NextResponse.redirect(new URL("/cguard-admin", request.url));
}

export const config = {
  matcher: ["/((?!.*\\..*).*)", "/favicon.ico", "/robots.txt"],
};
