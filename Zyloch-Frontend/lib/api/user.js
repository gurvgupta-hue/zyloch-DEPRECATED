import { toast } from 'react-toastify';
import { replaceLocation } from './navigation';

const API_URL = process.env.NEXT_PUBLIC_API_URL;

async function apiRequest(path, options = {}, showToast = true) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    if (showToast) {
      toast.error("Invalid API path");
    }
    return null;
  }

  try {
    const res = await fetch(`${API_URL}${path}`, {
      ...options,
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    if (!res.ok) {
      let errorMsg = `API error: ${res.status}`;
      try {
        const errData = await res.json();
        errorMsg = errData.message || errorMsg;
      } catch (_) {}
      if (showToast) {
        toast.error(errorMsg);
      }
      return null;
    }

    const data = await res.json();
    // Show success toast for non-GET requests
    if (showToast && options.method && options.method !== 'GET') {
      // toast.success('Operation successful!');
    }
    return data;
  } catch (error) {
    if (showToast && (!error.message || !error.message.includes('API error'))) {
      toast.error('Network error occurred');
    }
    return null;
  }
}

export async function getCurrentUser(showToast = true) {
  const data = await apiRequest("/auth/me", { method: "GET" }, showToast);
  return data ? data.user : null;
}

export async function getPreferences(showToast = true) {
  const data = await apiRequest("/auth/preferences", { method: "GET" }, showToast);
  return data ? data.preferences : null;
}

export async function updatePreferences(preferences, showToast = true) {
  const data = await apiRequest("/auth/preferences", {
    method: "PUT",
    body: JSON.stringify(preferences),
  }, showToast);
  return data ? data.preferences : null;
}

async function clearClientState() {
  try {
    sessionStorage.clear();
    ["authToken", "zyloch-last-activity"].forEach((key) =>
      localStorage.removeItem(key)
    );
    if (typeof caches !== "undefined" && caches?.keys) {
      const cacheKeys = await caches.keys();
      await Promise.all(cacheKeys.map((key) => caches.delete(key)));
    }
  } catch (error) {
    console.warn("Post-logout cache cleanup skipped:", error.message);
  }
}

export async function logout(showToast = true) {
  try {
    const data = await apiRequest("/auth/logout", { method: "POST" }, false);
    if (!data) {
      throw new Error("Logout request failed");
    }
    if (showToast) {
      toast.success('Logged out successfully');
    }
    await clearClientState();
    if (data.redirectUrl) {
      replaceLocation(data.redirectUrl);
      return data.redirectUrl;
    }
    return true;
  } catch (err) {
    if (showToast) {
      toast.error('Logout failed: ' + err.message);
    }
    console.error("Logout API failed:", err);
    throw err;
  }
}

export async function checkAuth(showToast = true) {
  const data = await apiRequest("/auth/check-auth", { method: "GET" }, showToast);
  return data;
}
