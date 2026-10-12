"use client";

import React, { useState, useCallback } from "react";
import Link from "next/link";
import Image from "next/image";
import { User, Shield, Bell, LayoutDashboard, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { usePathname } from "next/navigation";
import { useTheme } from "@/context/ThemeContext";
import Logo from "@/public/zyloch_logo.webp";
import BlackLogo from "@/public/zyloch-black-logo.png";

const NAV = [
  { label: "Account", href: "/settings", Icon: User, exact: true },
  { label: "Policy Management", href: "/settings/policymanagement", Icon: Shield },
  // { label: "Notifications", href: "/settings/notification", Icon: Bell },
];

export default function Sidebar({ isOpen = false, showToggle = false, onToggle = null }) {
  const pathname = usePathname();
  const { theme } = useTheme();
  const [tip, setTip] = useState(null);
  const toggleBtnClass = 'inline-flex items-center justify-center p-1 text-[var(--text)] transition-all duration-200 hover:scale-110 hover:text-[var(--color-primary)] focus-visible:outline-none';
  const sidebarLogo = theme === 'light' ? BlackLogo : Logo;

  const isActive = (href, exact) =>
    exact ? pathname === href : pathname === href || pathname.startsWith(href + "/");

  const showTip = useCallback((e, label) => {
    const r = e.currentTarget.getBoundingClientRect();
    setTip({ label, x: r.right + 12, y: r.top + r.height / 2 });
  }, []);
  const hideTip = useCallback(() => setTip(null), []);

  /* ── Collapsed rail (desktop) ───────────────────────────────── */
  if (!isOpen) {
    return (
      <>
        <aside className="flex h-full w-full flex-col rounded-xl bg-transparent backdrop-blur-2xl">

          {/* Toggle */}
          <div className="flex h-14 w-full shrink-0 items-center justify-center">
            {showToggle && (
              <button
                type="button"
                onClick={onToggle}
                aria-label="Expand settings sidebar"
                className={toggleBtnClass}
              >
                <PanelLeftOpen className="h-5 w-5" strokeWidth={2.4} />
              </button>
            )}
          </div>

          <div className="mx-4 h-px bg-[var(--border)]" />

          {/* Nav */}
          <nav className="flex flex-1 flex-col items-center gap-0.5 py-4 px-3">
            {NAV.map(({ label, href, Icon, exact }) => {
              const active = isActive(href, exact);
              return (
                <div key={href} className="relative flex w-full items-center justify-center py-0.5">
                  {active && (
                    <span className="pointer-events-none absolute left-0 top-1/2 h-6 w-[3px] -translate-y-1/2 rounded-r-full bg-[var(--color-primary)]" />
                  )}
                  <Link
                    href={href}
                    aria-label={label}
                    onMouseEnter={(e) => showTip(e, label)}
                    onMouseLeave={hideTip}
                    className={`
                      group flex h-10 w-10 items-center justify-center rounded-xl
                      transition-all duration-200 ease-out
                      ${active
                        ? "bg-[rgba(var(--color-primary-rgb),0.15)] text-[var(--color-primary)] shadow-[0_0_14px_rgba(var(--color-primary-rgb),0.18)]"
                        : "text-[var(--text-secondary)] hover:bg-[rgba(var(--color-primary-rgb),0.12)] hover:text-[var(--text)]"
                      }
                    `}
                  >
                    <Icon className={`h-[18px] w-[18px] transition-transform duration-200 group-hover:scale-110 ${active ? 'text-[var(--color-primary)]' : 'text-[var(--text-secondary)]'}`} strokeWidth={1.8} />
                  </Link>
                </div>
              );
            })}
          </nav>

          {/* Dashboard link */}
          <div className="mx-4 h-px bg-[var(--border)]" />
          <div className="flex shrink-0 items-center justify-center py-3">
            <Link
              href="/dashboard"
              aria-label="Go to Dashboard"
              onMouseEnter={(e) => showTip(e, "Dashboard")}
              onMouseLeave={hideTip}
              className="group flex h-10 w-10 items-center justify-center rounded-xl text-[var(--text-secondary)] transition-all duration-200 ease-out hover:bg-[rgba(var(--color-primary-rgb),0.10)] hover:text-[var(--text)]"
            >
              <LayoutDashboard className="h-[18px] w-[18px] transition-transform duration-200 group-hover:scale-110" strokeWidth={1.8} />
            </Link>
          </div>
        </aside>

        {/* Tooltip — fixed so it's never clipped */}
        {tip && (
          <div
            className="pointer-events-none fixed z-[9999] whitespace-nowrap rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[12px] font-medium text-[var(--text)] shadow-[var(--shadow-2)]"
            style={{ left: tip.x, top: tip.y, transform: "translateY(-50%)" }}
          >
            {tip.label}
          </div>
        )}
      </>
    );
  }

  /* ── Expanded mobile drawer ─────────────────────────────────── */
  return (
    <aside className="flex h-full w-full flex-col overflow-hidden rounded-[20px] bg-transparent backdrop-blur-2xl">

      {/* Header */}
      <div className="flex h-14 shrink-0 items-center gap-3 border-b border-[var(--border)] px-4">
        <Image src={sidebarLogo} alt="Zyloch" className="w-[110px] h-auto shrink-0 object-contain" priority />
        {showToggle && (
          <button
            type="button"
            onClick={onToggle}
            aria-label="Collapse settings sidebar"
            className={`ml-auto ${toggleBtnClass}`}
          >
            <PanelLeftClose className="h-5 w-5" strokeWidth={2.4} />
          </button>
        )}
      </div>

      {/* Nav */}
      <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto px-2.5 py-3">
        <p className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--muted)]">
          Preferences
        </p>
        {NAV.map(({ label, href, Icon, exact }) => {
          const active = isActive(href, exact);
          return (
            <Link
              key={href}
              href={href}
              className={`
                group flex items-center gap-3 rounded-xl px-2.5 py-2.5
                transition-all duration-200 ease-out
                ${active
                  ? 'bg-[rgba(var(--color-primary-rgb),0.20)] text-[var(--text)] shadow-[inset_0_0_0_1px_rgba(var(--color-primary-rgb),0.35)]'
                  : 'text-[var(--text-secondary)] hover:bg-[rgba(var(--color-primary-rgb),0.10)] hover:text-[var(--text)]'
                }
              `}
            >
              <span className={`
                flex h-8 w-8 shrink-0 items-center justify-center rounded-lg
                transition-all duration-200
                ${active
                  ? 'h-9 w-9 rounded-xl bg-[var(--color-primary)] border border-[var(--color-primary-600)] text-[var(--text-on-primary)] shadow-[0_6px_14px_rgba(var(--color-primary-rgb),0.35)]'
                  : 'h-9 w-9 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text-secondary)] group-hover:border-[rgba(var(--color-primary-rgb),0.45)] group-hover:bg-[rgba(var(--color-primary-rgb),0.12)] group-hover:text-[var(--text)]'
                }
              `}>
                <Icon className="h-[15px] w-[15px]" strokeWidth={1.8} />
              </span>
              <span className={`text-[15px] leading-none text-[var(--text)] ${active ? 'font-semibold' : 'font-medium'}`}>
                {label}
              </span>
            </Link>
          );
        })}
      </nav>

      {/* Dashboard link */}
      <div className="shrink-0 border-t border-[var(--border)] px-2.5 py-3">
        <Link
          href="/dashboard"
          className="group flex items-center gap-3 rounded-xl px-2.5 py-2.5 text-[var(--text-secondary)] transition-all duration-200 ease-out hover:bg-[rgba(var(--color-primary-rgb),0.10)] hover:text-[var(--text)]"
        >
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text-secondary)] transition-all duration-200 group-hover:border-[rgba(var(--color-primary-rgb),0.45)] group-hover:bg-[rgba(var(--color-primary-rgb),0.12)] group-hover:text-[var(--text)]">
            <LayoutDashboard className="h-[15px] w-[15px]" strokeWidth={1.8} />
          </span>
          <span className="text-[15px] font-medium leading-none">Go to Dashboard</span>
        </Link>
      </div>
    </aside>
  );
}

