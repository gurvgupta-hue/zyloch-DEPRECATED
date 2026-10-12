"use client";

import { useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { toast } from "react-toastify";
import { logout as logoutApi } from "@/lib/api/user";

export const IDLE_TIMEOUT = 15 * 60 * 1000; // 15 minutes

const ACTIVITY_EVENTS = [
  "mousemove",
  "mousedown",
  "click",
  "scroll",
  "keydown",
  "touchstart",
  "touchmove",
];

const STORAGE_KEY = "zyloch-last-activity";
const LOGOUT_EVENT = "zyloch-logout";

export default function useAutoLogout({ onLogout } = {}) {
  const router = useRouter();

  const timerRef = useRef(null);
  const isLoggingOut = useRef(false);
  const debounceRef = useRef(null);
  const activeRequestsRef = useRef(0);
  const resetTimerRef = useRef(null);

  const clearTimer = () => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  };

  const clearAuthStorage = () => {
    localStorage.removeItem("authToken");
    sessionStorage.removeItem("authToken");
    localStorage.removeItem(STORAGE_KEY);
  };

  const handleLogout = useCallback(async () => {
    if (isLoggingOut.current) return;

    // Wait for any in-flight network requests to finish (max 10 s)
    if (activeRequestsRef.current > 0) {
      const MAX_WAIT = 10_000;
      const start = Date.now();
      await new Promise((resolve) => {
        const check = () => {
          if (activeRequestsRef.current === 0 || Date.now() - start >= MAX_WAIT) {
            resolve();
          } else {
            setTimeout(check, 200);
          }
        };
        check();
      });
    }

    if (isLoggingOut.current) return;

    isLoggingOut.current = true;
    clearTimer();

    // Notify other tabs
    localStorage.setItem(LOGOUT_EVENT, Date.now().toString());

    let redirectUrl = null;
    try {
      const result = await logoutApi(false);
      if (typeof result === "string") {
        redirectUrl = result;
      }
    } catch (error) {
      console.error("Logout error:", error);
    }

    clearAuthStorage();

    if (onLogout) {
      onLogout();
    }

    toast.error("Logged out due to inactivity");

    // logoutApi already navigated to the provider-aware login URL
    // (e.g. /login?orgId=... for Google/Microsoft). Only force /login
    // when no redirect was issued, so the org context is preserved.
    if (!redirectUrl) {
      router.replace("/login");
    }
  }, [router, onLogout]);

  const startTimer = useCallback(
    (delay = IDLE_TIMEOUT) => {
      if (isLoggingOut.current) return;

      clearTimer();

      timerRef.current = setTimeout(() => {
        handleLogout();
      }, delay);
    },
    [handleLogout]
  );

  const resetTimer = useCallback(() => {
    if (isLoggingOut.current) return;

    localStorage.setItem(STORAGE_KEY, Date.now().toString());
    startTimer();
  }, [startTimer]);

  // Keep resetTimerRef in sync so the fetch interceptor always calls the latest version
  useEffect(() => {
    resetTimerRef.current = resetTimer;
  }, [resetTimer]);

  // Track in-flight fetch requests — reset timer on network activity, defer logout while any are active
  useEffect(() => {
    const originalFetch = window.fetch;
    window.fetch = async function (...args) {
      activeRequestsRef.current += 1;
      // Treat any outgoing network request as user activity
      if (resetTimerRef.current) {
        resetTimerRef.current();
      }
      try {
        return await originalFetch.apply(this, args);
      } finally {
        activeRequestsRef.current = Math.max(0, activeRequestsRef.current - 1);
      }
    };
    return () => {
      window.fetch = originalFetch;
    };
  }, []);

  // Track real user activity only
  useEffect(() => {
    const activityHandler = () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }

      debounceRef.current = setTimeout(() => {
        resetTimer();
      }, 300);
    };

    ACTIVITY_EVENTS.forEach((event) => {
      window.addEventListener(event, activityHandler, { passive: true });
    });

    return () => {
      ACTIVITY_EVENTS.forEach((event) => {
        window.removeEventListener(event, activityHandler);
      });

      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
        debounceRef.current = null;
      }
    };
  }, [resetTimer]);

  // Sync logout/activity between tabs
  useEffect(() => {
    const storageHandler = (e) => {
      if (isLoggingOut.current) return;

      if (e.key === STORAGE_KEY && e.newValue) {
        const lastActivity = Number(e.newValue);
        const inactiveTime = Date.now() - lastActivity;
        const remainingTime = IDLE_TIMEOUT - inactiveTime;

        if (remainingTime <= 0) {
          handleLogout();
        } else {
          startTimer(remainingTime);
        }
      }

      if (e.key === LOGOUT_EVENT && e.newValue) {
        handleLogout();
      }
    };

    window.addEventListener("storage", storageHandler);

    return () => {
      window.removeEventListener("storage", storageHandler);
    };
  }, [handleLogout, startTimer]);

  // Initialize timer
  useEffect(() => {
    const lastActivity = localStorage.getItem(STORAGE_KEY);

    if (!lastActivity) {
      resetTimer();
    } else {
      const inactiveTime = Date.now() - Number(lastActivity);
      const remainingTime = IDLE_TIMEOUT - inactiveTime;

      if (remainingTime <= 0) {
        handleLogout();
      } else {
        startTimer(remainingTime);
      }
    }

    return () => {
      clearTimer();
    };
  }, [resetTimer, handleLogout, startTimer]);
}