"use client";

import React from "react";
import { Sun, Moon } from "lucide-react";
import { useTheme } from "@/context/ThemeContext";

export const ThemeToggle = () => {
  const { theme, setTheme } = useTheme();
  const isDark = theme === "dark";

  const toggleTheme = () => {
    const newTheme = isDark ? "light" : "dark";
    setTheme(newTheme);
  };

  return (
    <>
      {/* ✅ Show gradients ONLY in light theme */}
      {!isDark && (
        <>
          {/* Top Center Gradient */}
          <div
            className="fixed top-0 left-1/2 -translate-x-1/2 pointer-events-none z-[-3]"
            style={{
              width: "300px",
              height: "300px",
              borderRadius: "9999px",
              opacity: 0.6,
              background:
                "radial-gradient(circle at center, rgba(99, 102, 241, 0.15) 0%, rgba(168, 85, 247, 0.1) 70%, transparent 100%)",
              filter: "blur(40px)",
            }}
          />

          {/* Bottom Center Gradient */}
          <div
            className="fixed bottom-0 left-1/2 -translate-x-1/2 pointer-events-none z-[-3]"
            style={{
              width: "250px",
              height: "250px",
              borderRadius: "9999px",
              opacity: 0.5,
              background:
                "radial-gradient(circle at center, rgba(236, 72, 153, 0.15) 0%, rgba(99, 102, 241, 0.1) 70%, transparent 100%)",
              filter: "blur(50px)",
            }}
          />
        </>
      )}

      {/* Theme Toggle Button */}
      <button
        onClick={toggleTheme}
        className="
          relative 
          inline-flex 
          h-10 
          w-20 
          items-center 
          rounded-full 
          p-1 
          transition-colors 
          focus:outline-none 
          focus:ring-2 
          focus:ring-primary 
          focus:ring-offset-2 
          bg-surface
          focus-ring
          hover-lift
          active-scale
          shadow-1
        "
        aria-label={`Switch to ${isDark ? "light" : "dark"} theme`}
      >
        {/* Track background */}
        <div
          className="absolute inset-0 rounded-full transition-colors duration-300"
          style={{
            backgroundColor: isDark ? "#1F2937" : "var(--bg)",
          }}
        />

        {/* Static Icons */}
        <Sun
          className="absolute left-2.5 h-4 w-4 transition-colors duration-300"
          style={{
            color: isDark ? "var(--muted)" : "var(--color-primary)",
          }}
        />
        <Moon
          className="absolute right-2.5 h-4 w-4 transition-colors duration-300"
          style={{
            color: isDark ? "var(--color-primary)" : "var(--muted)",
          }}
        />

        {/* Thumb */}
        <div
          className={`
            absolute left-1 h-8 w-8 rounded-full 
            transition-all duration-300
            flex items-center justify-center
            ${isDark ? "translate-x-10" : "translate-x-0"}
            shadow-1
          `}
          style={{
            backgroundColor: "var(--surface)",
          }}
        >
          {isDark ? (
            <Moon className="h-4 w-4" style={{ color: "var(--color-primary)" }} />
          ) : (
            <Sun className="h-4 w-4" style={{ color: "var(--color-primary)" }} />
          )}
        </div>
      </button>
    </>
  );
};