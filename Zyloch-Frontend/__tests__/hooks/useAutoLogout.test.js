import { renderHook, act } from "@testing-library/react";
import useAutoLogout, { IDLE_TIMEOUT } from "@/hooks/useAutoLogout";

// ─── Mocks ────────────────────────────────────────────────────────────────────

const mockReplace = jest.fn();
jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockReplace }),
}));

const mockToastError = jest.fn();
jest.mock("react-toastify", () => ({
  toast: { error: (...args) => mockToastError(...args) },
}));

const mockLogoutApi = jest.fn().mockResolvedValue(undefined);
jest.mock("@/lib/api/user", () => ({
  logout: (...args) => mockLogoutApi(...args),
}));

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fireActivityEvent(type = "mousemove") {
  window.dispatchEvent(new Event(type));
}

function fireStorageEvent(key, value) {
  const event = new Event("storage");
  event.key = key;
  event.newValue = value;
  window.dispatchEvent(event);
}

// ─── Setup / Teardown ─────────────────────────────────────────────────────────

beforeEach(() => {
  jest.useFakeTimers();
  localStorage.clear();
  sessionStorage.clear();
  mockReplace.mockClear();
  mockToastError.mockClear();
  mockLogoutApi.mockClear();
  mockLogoutApi.mockResolvedValue(undefined);
});

afterEach(() => {
  jest.useRealTimers();
  jest.clearAllTimers();
});

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("useAutoLogout", () => {
  describe("idle timer", () => {
    test("starts the idle timer on mount and logs out after IDLE_TIMEOUT", async () => {
      renderHook(() => useAutoLogout());

      expect(mockLogoutApi).not.toHaveBeenCalled();

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
      expect(mockToastError).toHaveBeenCalledWith("Logged out due to inactivity");
      expect(mockReplace).toHaveBeenCalledWith("/login");
    });

    test("does not override the provider-aware redirect from logoutApi", async () => {
      mockLogoutApi.mockResolvedValueOnce(
        "http://app.zyloch.test/login?orgId=org-123"
      );

      renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
      expect(mockReplace).not.toHaveBeenCalled();
    });

    test.each([
      "mousemove",
      "mousedown",
      "click",
      "scroll",
      "keydown",
      "touchstart",
      "touchmove",
    ])('resets the timer when "%s" event fires', async (eventType) => {
      renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT - 1000);
      });

      await act(async () => {
        fireActivityEvent(eventType);
        jest.advanceTimersByTime(300);
      });

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT - 1000);
      });

      expect(mockLogoutApi).not.toHaveBeenCalled();

      await act(async () => {
        jest.advanceTimersByTime(1100);
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
    });

    test("clears auth storage on logout", async () => {
      localStorage.setItem("authToken", "abc");
      sessionStorage.setItem("authToken", "abc");

      renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        await Promise.resolve();
      });

      expect(localStorage.getItem("authToken")).toBeNull();
      expect(sessionStorage.getItem("authToken")).toBeNull();
    });

    test("calls the onLogout callback when provided", async () => {
      const onLogout = jest.fn();
      renderHook(() => useAutoLogout({ onLogout }));

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        await Promise.resolve();
      });

      expect(onLogout).toHaveBeenCalledTimes(1);
    });

    test("handles logoutApi failure gracefully and still redirects", async () => {
      mockLogoutApi.mockRejectedValueOnce(new Error("network error"));
      const consoleErrorSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});

      renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        await Promise.resolve();
      });

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        "Logout error:",
        expect.objectContaining({ message: "network error" })
      );
      expect(mockReplace).toHaveBeenCalledWith("/login");
      expect(mockToastError).toHaveBeenCalledWith("Logged out due to inactivity");

      consoleErrorSpy.mockRestore();
    });

    test("writes zyloch-logout key to localStorage to notify other tabs", async () => {
      renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        await Promise.resolve();
      });

      expect(localStorage.getItem("zyloch-logout")).not.toBeNull();
    });

    test("does not log out after the hook unmounts", async () => {
      const { unmount } = renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT - 1000);
      });

      unmount();

      await act(async () => {
        jest.advanceTimersByTime(2000);
        await Promise.resolve();
      });

      expect(mockLogoutApi).not.toHaveBeenCalled();
    });

    test("ignores activity events after logout has already started", async () => {
      renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);

      await act(async () => {
        fireActivityEvent("mousemove");
        jest.advanceTimersByTime(300);
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
    });
  });

  describe("resuming from stored activity", () => {
    test("starts with remaining time when previous activity exists", async () => {
      const remainingTime = 5000;
      const lastActivity = Date.now() - (IDLE_TIMEOUT - remainingTime);
      localStorage.setItem("zyloch-last-activity", String(lastActivity));

      renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(remainingTime - 500);
      });
      expect(mockLogoutApi).not.toHaveBeenCalled();

      await act(async () => {
        jest.advanceTimersByTime(600);
        await Promise.resolve();
      });
      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
    });

    test("logs out immediately when stored activity is already past timeout", async () => {
      const lastActivity = Date.now() - (IDLE_TIMEOUT + 1000);
      localStorage.setItem("zyloch-last-activity", String(lastActivity));

      await act(async () => {
        renderHook(() => useAutoLogout());
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
    });
  });

  describe("cross-tab synchronization", () => {
    test("logs out when another tab fires the logout storage event", async () => {
      renderHook(() => useAutoLogout());

      await act(async () => {
        fireStorageEvent("zyloch-logout", String(Date.now()));
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
      expect(mockReplace).toHaveBeenCalledWith("/login");
    });

    test("resets timer based on activity from another tab", async () => {
      renderHook(() => useAutoLogout());

      const remainingTime = 3000;
      const lastActivity = Date.now() - (IDLE_TIMEOUT - remainingTime);

      await act(async () => {
        fireStorageEvent("zyloch-last-activity", String(lastActivity));
        jest.advanceTimersByTime(remainingTime - 500);
      });

      expect(mockLogoutApi).not.toHaveBeenCalled();

      await act(async () => {
        jest.advanceTimersByTime(600);
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
    });

    test("logs out when cross-tab storage event shows activity is already past timeout", async () => {
      renderHook(() => useAutoLogout());

      const expiredActivity = Date.now() - (IDLE_TIMEOUT + 5000);

      await act(async () => {
        fireStorageEvent("zyloch-last-activity", String(expiredActivity));
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
    });
  });

  describe("double-logout guard", () => {
    test("does not call logoutApi more than once if logout is triggered twice", async () => {
      renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        fireStorageEvent("zyloch-logout", String(Date.now()));
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
    });
  });

  describe("fetch interception", () => {
    let originalFetch;

    beforeEach(() => {
      originalFetch = window.fetch;
    });

    afterEach(() => {
      window.fetch = originalFetch;
    });

    test("wraps window.fetch and restores it on unmount", () => {
      const { unmount } = renderHook(() => useAutoLogout());

      expect(window.fetch).not.toBe(originalFetch);

      unmount();

      expect(window.fetch).toBe(originalFetch);
    });

    test("resets the idle timer when a network request is made", async () => {
      window.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      renderHook(() => useAutoLogout());

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT - 1000);
      });

      await act(async () => {
        await window.fetch("/api/test");
      });

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT - 1000);
      });
      expect(mockLogoutApi).not.toHaveBeenCalled();

      await act(async () => {
        jest.advanceTimersByTime(1100);
        await Promise.resolve();
      });
      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
    });

    test("defers logout until an in-flight fetch request completes", async () => {
      let resolveRequest;
      window.fetch = jest.fn().mockImplementation(
        () => new Promise((resolve) => { 
          resolveRequest = () => resolve({ ok: true, status: 200 });
        })
      );

      renderHook(() => useAutoLogout());

      const fetchPromise = window.fetch("/api/slow");

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        await Promise.resolve();
      });

      expect(mockLogoutApi).not.toHaveBeenCalled();

      await act(async () => {
        resolveRequest();
        await fetchPromise;
        jest.advanceTimersByTime(200);
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
      expect(mockReplace).toHaveBeenCalledWith("/login");
    });

    test("proceeds with logout after max 10 s wait if fetch never resolves", async () => {
      window.fetch = jest.fn().mockImplementation(
        () => new Promise(() => {})
      );

      renderHook(() => useAutoLogout());

      window.fetch("/api/hanging");

      await act(async () => {
        jest.advanceTimersByTime(IDLE_TIMEOUT + 100);
        await Promise.resolve();
      });

      expect(mockLogoutApi).not.toHaveBeenCalled();

      await act(async () => {
        jest.advanceTimersByTime(10000);
        await Promise.resolve();
      });

      expect(mockLogoutApi).toHaveBeenCalledTimes(1);
      expect(mockReplace).toHaveBeenCalledWith("/login");
    });
  });
});