"use client";

import React from "react";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useTheme } from "@/context/ThemeContext";

export const SettingsPageHeader = ({
  icon: Icon,
  title,
  subtitle,
  badge,
  children,
}) => {
  const { theme } = useTheme();
  const isLight = theme === "light";

  return (
    <section
      className="rounded-2xl p-4 sm:p-6"
      style={{
        background: isLight ? "rgba(255,255,255,0.88)" : "rgba(15,23,42,0.42)",
        border: "1px solid color-mix(in srgb, var(--border) 55%, transparent)",
        boxShadow: "var(--shadow-1)",
        backdropFilter: "blur(6px)",
      }}
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          {Icon && (
            <div
              className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl"
              style={{
                background: "rgba(var(--color-primary-rgb), 0.12)",
                border: "1px solid rgba(var(--color-primary-rgb), 0.24)",
              }}
            >
              <Icon size={20} style={{ color: "var(--color-primary)" }} />
            </div>
          )}

          <div className="min-w-0">
            <h1 className="text-2xl font-bold sm:text-3xl" style={{ color: "var(--text)" }}>
              {title}
            </h1>
            {subtitle && (
              <p className="mt-1 max-w-3xl text-sm sm:text-base" style={{ color: "var(--muted)" }}>
                {subtitle}
              </p>
            )}
          </div>
        </div>

        <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:flex-wrap sm:justify-end">
          {badge && (
            <span
              className="inline-flex min-h-10 items-center justify-center rounded-lg px-3 py-1.5 text-xs font-medium"
              style={{
                color: badge.color || "var(--color-primary)",
                background:
                  badge.background || "rgba(var(--color-primary-rgb), 0.12)",
                border:
                  badge.border ||
                  "1px solid rgba(var(--color-primary-rgb), 0.24)",
              }}
            >
              {badge.label}
            </span>
          )}

          <div
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg px-3 py-1.5"
            style={{
              background: isLight
                ? "rgba(var(--color-primary-rgb), 0.08)"
                : "rgba(255,255,255,0.06)",
              border:
                "1px solid color-mix(in srgb, var(--border) 55%, transparent)",
            }}
          >
            <span className="text-xs font-medium" style={{ color: "var(--muted)" }}>
              Theme
            </span>
            <ThemeToggle />
          </div>

          {children}
        </div>
      </div>
    </section>
  );
};
