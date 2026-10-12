"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import AutoLogoutClient from "@/hooks/AutoLogoutClient";
import IdleTimer from "@/components/IdleTimer";

// In-memory cache for auth verification across layout transitions
let globalAuthVerified = false;
let lastAuthCheckTime = 0;
const AUTH_CACHE_TTL_MS = 60 * 1000; // 1 minute cache

export default function ProtectedLayout({ children }) {
  const router = useRouter();
  const [loading, setLoading] = useState(!globalAuthVerified);
  const [isAuthed, setIsAuthed] = useState(globalAuthVerified);

  useEffect(() => {
    let isMounted = true;

    async function checkAuth() {
      // If recently verified in this session, skip blocking check
      if (globalAuthVerified && Date.now() - lastAuthCheckTime < AUTH_CACHE_TTL_MS) {
        if (isMounted) {
          setIsAuthed(true);
          setLoading(false);
        }
        return;
      }

      try {
        const res = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL}/auth/check-auth`,
          {
            method: "GET",
            credentials: "include",
            cache: "no-store",
          }
        );

        if (!isMounted) return;

        if (res.ok) {
          globalAuthVerified = true;
          lastAuthCheckTime = Date.now();
          setIsAuthed(true);
        } else {
          globalAuthVerified = false;
          setIsAuthed(false);
          router.replace("/login");
        }
      } catch (error) {
        console.error("Auth check failed:", error);

        if (!isMounted) return;

        globalAuthVerified = false;
        setIsAuthed(false);
        router.replace("/login");
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    checkAuth();

    return () => {
      isMounted = false;
    };
  }, [router]);

  if (loading && !isAuthed) {
    return (
      <div className="flex h-screen items-center justify-center bg-[var(--bg)] text-[var(--muted)]">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-primary)] border-t-transparent" />
          <p className="text-sm font-medium">Verifying session...</p>
        </div>
      </div>
    );
  }

  if (!isAuthed) {
    return null;
  }

  return (
    <>
      <AutoLogoutClient />
      {/* <IdleTimer /> */}
      {children}
    </>
  );
}