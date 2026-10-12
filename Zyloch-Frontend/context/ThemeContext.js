"use client";

import { createContext, useContext, useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import {
  getPreferences,
  updatePreferences,
  getCurrentUser,
} from "@/lib/api/user";

const ThemeContext = createContext({
  theme: "light",
  setTheme: () => { },
  toggleTheme: () => { },
  timeZone: "UTC",
  setTimeZone: () => { },
  user: null,
  refreshUser: () => { },
  themes: ["light", "dark"],
  timeZones: ["UTC", "IST", "EST", "PST", "CET", "JST", "AEST"],
  isLoading: true,
});

export const TIME_ZONE_OPTIONS = [
  { value: "UTC", label: "UTC", offset: 0 },
  { value: "IST", label: "India (IST)", offset: 5.5 },
  { value: "EST", label: "Eastern (EST)", offset: -5 },
  { value: "PST", label: "Pacific (PST)", offset: -8 },
  { value: "CET", label: "Central Europe (CET)", offset: 1 },
  { value: "JST", label: "Japan (JST)", offset: 9 },
  { value: "AEST", label: "Sydney (AEST)", offset: 10 },
];

const AVAILABLE_THEMES = ["light", "dark"];
const AVAILABLE_TIME_ZONES = TIME_ZONE_OPTIONS.map((zone) => zone.value);

export const ThemeProvider = ({ children }) => {
  const [theme, setThemeState] = useState("light");
  const [timeZone, setTimeZoneState] = useState("UTC");
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const pathname = usePathname();

  useEffect(() => {
    const loadInitialData = async () => {
      try {
        setIsLoading(true);

        // Apply theme from localStorage if available
        const localTheme = localStorage.getItem("theme");
        if (localTheme && AVAILABLE_THEMES.includes(localTheme)) {
          applyTheme(localTheme, false);
        } else {
          const systemTheme =
            window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
              ? "dark"
              : "light";
          applyTheme(systemTheme, false);
        }

        const localTimeZone = localStorage.getItem("timeZone");
        if (localTimeZone && AVAILABLE_TIME_ZONES.includes(localTimeZone)) {
          setTimeZoneState(localTimeZone);
        }

        // Skip user API calls on public auth & legal routes
        const isPublicAuthPage =
          pathname?.startsWith("/login") ||
          pathname?.startsWith("/signup") ||
          pathname?.startsWith("/auth/login") ||
          pathname?.startsWith("/auth/signup") ||
          pathname?.startsWith("/cookies") ||
          pathname?.startsWith("/privacy") ||
          pathname?.startsWith("/terms");

        if (!isPublicAuthPage) {
          const prefs = await getPreferences(false);

          if (prefs?.theme && AVAILABLE_THEMES.includes(prefs.theme)) {
            applyTheme(prefs.theme, false);
          }

          if (prefs?.timeZone && AVAILABLE_TIME_ZONES.includes(prefs.timeZone)) {
            applyTimeZone(prefs.timeZone, false);
          }

          const userData = await getCurrentUser(false);
          setUser(userData);
        }
      } catch (error) {
        console.error("Failed to load initial data:", error);
        applyTheme("light", false);

        const localTimeZone = localStorage.getItem("timeZone");
        if (localTimeZone && AVAILABLE_TIME_ZONES.includes(localTimeZone)) {
          setTimeZoneState(localTimeZone);
        }
      } finally {
        setIsLoading(false);
      }
    };

    loadInitialData();
  }, [pathname]);

  const applyTheme = (newTheme, persist = true) => {
    const safeTheme = AVAILABLE_THEMES.includes(newTheme)
      ? newTheme
      : "light";

    setThemeState(safeTheme);
    document.documentElement.setAttribute("data-theme", safeTheme);
    if (safeTheme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }

    if (persist) {
      localStorage.setItem("theme", safeTheme);
      updatePreferences({ theme: safeTheme }).catch(console.error);
    }
  };

  const toggleTheme = () => {
    const nextTheme = theme === "light" ? "dark" : "light";
    applyTheme(nextTheme);
  };

  const applyTimeZone = (newTimeZone, persist = true) => {
    const safeTimeZone = AVAILABLE_TIME_ZONES.includes(newTimeZone)
      ? newTimeZone
      : "UTC";

    setTimeZoneState(safeTimeZone);

    if (persist) {
      localStorage.setItem("timeZone", safeTimeZone);
      updatePreferences({ timeZone: safeTimeZone }).catch(console.error);
    }
  };

  const refreshUser = async () => {
    try {
      const userData = await getCurrentUser();
      setUser(userData);
      return userData;
    } catch (error) {
      console.error("Failed to refresh user:", error);
      return null;
    }
  };

  if (isLoading) {
    return <div style={{ visibility: "hidden" }}>{children}</div>;
  }

  return (
    <ThemeContext.Provider
      value={{
        theme,
        setTheme: applyTheme,
        toggleTheme,
        timeZone,
        setTimeZone: applyTimeZone,
        user,
        refreshUser,
        themes: AVAILABLE_THEMES,
        timeZones: AVAILABLE_TIME_ZONES,
        isLoading,
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
};
