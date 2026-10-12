import { NextResponse } from "next/server";

const AUTH_COOKIE = "authToken";

/**
 * Base URL for the server-side session check. Prefers an internal address so the
 * hop does not leave the deployment; falls back to the public API URL.
 */
function apiBaseUrl() {
  return (
    process.env.API_INTERNAL_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    "http://localhost:5000"
  );
}

function redirectToLogin(request) {
  const response = NextResponse.redirect(new URL("/login", request.url));
  // Drop the rejected cookie so the user is not bounced in a loop.
  response.cookies.delete(AUTH_COOKIE);
  return response;
}

/**
 * Route guard for authenticated pages (Next 16 proxy convention).
 *
 * Validates the session rather than merely checking that a cookie exists.
 * The cookie is an encrypted JWT that only the backend can open, so
 * validation is delegated to `/auth/check-auth`.
 */
export async function proxy(request) {
  const token = request.cookies.get(AUTH_COOKIE);
  const { pathname } = request.nextUrl;
  const isLoginRoute = pathname.startsWith("/login");

  // 1. If visiting /login, redirect authenticated users to /home
  if (isLoginRoute) {
    if (!token?.value) {
      return NextResponse.next();
    }

    try {
      const res = await fetch(`${apiBaseUrl()}/auth/check-auth`, {
        method: "GET",
        headers: {
          cookie: `${AUTH_COOKIE}=${token.value}`,
          accept: "application/json",
        },
        cache: "no-store",
      });

      if (res.ok) {
        return NextResponse.redirect(new URL("/home", request.url));
      }
    } catch (err) {
      console.warn("[proxy] auth check failed on login route:", err.message);
    }

    return NextResponse.next();
  }

  // 2. Protected routes handling
  if (!token?.value) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  try {
    const res = await fetch(`${apiBaseUrl()}/auth/check-auth`, {
      method: "GET",
      headers: {
        cookie: `${AUTH_COOKIE}=${token.value}`,
        accept: "application/json",
      },
      cache: "no-store",
    });

    if (res.status === 401 || res.status === 403) {
      return redirectToLogin(request);
    }
  } catch (err) {
    console.warn("[proxy] session check unreachable; deferring to API auth:", err.message);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/login",
    "/dashboard/:path*",
    "/home/:path*",
    "/settings/:path*",
    "/scanops/:path*"
  ],
};
