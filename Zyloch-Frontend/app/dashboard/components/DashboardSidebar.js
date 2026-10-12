'use client';

import React, { useState, useCallback } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { usePathname } from 'next/navigation';
import DashboardIcon from '@/public/assets/icons/dashboard.svg';
import ScanIcon from '@/public/assets/icons/survey.svg';
import SettingIcon from '@/public/assets/icons/setting.svg';
import { useTheme } from '@/context/ThemeContext';
import Logo from '@/public/zyloch_logo.webp';
import BlackLogo from '@/public/zyloch-black-logo.png';
import { useGithubStore } from '@/store/useGithubStore';

const NAV = [
  { label: 'Dashboard', href: '/dashboard', Icon: DashboardIcon },
  { label: 'ScanOps', href: '/scanops/overview', Icon: ScanIcon, requiresInstallation: true },
  { label: 'Settings', href: '/settings', Icon: SettingIcon },
];

const NavIcon = ({ Icon, lucide, className, strokeWidth }) => {
  if (lucide) {
    return <Icon className={className} strokeWidth={strokeWidth} />;
  }

  if (typeof Icon === 'function') {
    return <Icon className={className} style={{ fill: 'currentColor' }} />;
  }

  return <Image src={Icon} alt="" width={18} height={18} className={className} />;
};

export default function DashboardSidebar({ isOpen = false, showToggle = false, onToggle = null }) {
  const pathname = usePathname();
  const { theme } = useTheme();
  const selectedInstallation = useGithubStore((s) => s.selectedInstallation);
  const [tip, setTip] = useState(null);
  const toggleBtnClass = 'inline-flex items-center justify-center p-1 text-[var(--text)] transition-all duration-200 hover:scale-110 hover:text-[var(--color-primary)] focus-visible:outline-none';
  const sidebarLogo = theme === 'light' ? BlackLogo : Logo;

  const isActive = (href) => pathname === href || pathname.startsWith(href + '/');

  const showTip = useCallback((e, label) => {
    const r = e.currentTarget.getBoundingClientRect();
    setTip({ label, x: r.right + 12, y: r.top + r.height / 2 });
  }, []);
  const hideTip = useCallback(() => setTip(null), []);

  /* ── Collapsed rail (desktop) ───────────────────────────────── */
  if (!isOpen) {
    return (
      <>
        <aside className="flex h-full w-full flex-col rounded-xl bg-transparent">

          {/* Toggle */}
          <div className="flex h-14 w-full shrink-0 items-center justify-center">
            {showToggle && (
              <button
                type="button"
                onClick={onToggle}
                aria-label="Expand dashboard sidebar"
                className={toggleBtnClass}
              >
                <PanelLeftOpen className="h-5 w-5" strokeWidth={2.4} />
              </button>
            )}
          </div>

          {/* Divider */}
          <div className="mx-4 h-px bg-[var(--border)]" />

          {/* Nav */}
          <nav className="flex flex-1 flex-col items-center gap-0.5 py-4 px-3">
            {NAV.map(({ label, href, Icon, lucide, requiresInstallation }) => {
              const active = isActive(href);
              const disabled = requiresInstallation && !selectedInstallation;
              const tipLabel = disabled ? 'Select an installation first' : label;
              return (
                <div key={href} className="relative flex w-full items-center justify-center py-0.5">
                  {/* Active pill */}
                  {active && !disabled && (
                    <span className="pointer-events-none absolute left-0 top-1/2 h-6 w-[3px] -translate-y-1/2 rounded-r-full bg-[var(--color-primary)]" />
                  )}
                  {disabled ? (
                    <div
                      aria-label={tipLabel}
                      aria-disabled="true"
                      onMouseEnter={(e) => showTip(e, tipLabel)}
                      onMouseLeave={hideTip}
                      className="flex h-10 w-10 cursor-not-allowed items-center justify-center rounded-xl opacity-35"
                    >
                      <NavIcon
                        Icon={Icon}
                        lucide={lucide}
                        className="h-[18px] w-[18px] text-[var(--text-secondary)]"
                        strokeWidth={1.8}
                      />
                    </div>
                  ) : (
                    <Link
                      href={href}
                      aria-label={label}
                      onMouseEnter={(e) => showTip(e, label)}
                      onMouseLeave={hideTip}
                      className={`
                        group flex h-10 w-10 items-center justify-center rounded-xl
                        transition-all duration-200 ease-out
                        ${active
                          ? 'bg-[rgba(var(--color-primary-rgb),0.15)] text-[var(--color-primary)] shadow-[0_0_14px_rgba(var(--color-primary-rgb),0.18)]'
                          : 'text-[var(--text-secondary)] hover:bg-[rgba(var(--color-primary-rgb),0.12)] hover:text-[var(--text)]'
                        }
                      `}
                    >
                      <NavIcon
                        Icon={Icon}
                        lucide={lucide}
                        className={`h-[18px] w-[18px] transition-transform duration-200 group-hover:scale-110 ${active ? 'text-[var(--color-primary)]' : 'text-[var(--text-secondary)] group-hover:text-[var(--text)]'}`}
                        strokeWidth={1.8}
                      />
                    </Link>
                  )}
                </div>
              );
            })}
          </nav>
        </aside>

        {/* Tooltip — fixed so it's never clipped */}
        {tip && (
          <div
            className="pointer-events-none fixed z-[9999] whitespace-nowrap rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[12px] font-medium text-[var(--text)] shadow-[var(--shadow-2)]"
            style={{ left: tip.x, top: tip.y, transform: 'translateY(-50%)' }}
          >
            {tip.label}
          </div>
        )}
      </>
    );
  }

  /* ── Expanded mobile drawer ─────────────────────────────────── */
  return (
    <aside className="flex h-full w-full flex-col overflow-hidden rounded-[20px] bg-transparent">

      {/* Header */}
      <div className="flex h-14 shrink-0 items-center gap-3 border-b border-[var(--border)] px-4">
        <Image src={sidebarLogo} alt="Zyloch" className="w-[110px] h-auto shrink-0 object-contain" priority />
        {showToggle && (
          <button
            type="button"
            onClick={onToggle}
            aria-label="Collapse dashboard sidebar"
            className={`ml-auto ${toggleBtnClass}`}
          >
            <PanelLeftClose className="h-5 w-5" strokeWidth={2.4} />
          </button>
        )}
      </div>

      {/* Nav */}
      <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto px-2.5 py-3">
        <p className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--muted)]">
          Workspace
        </p>
        {NAV.map(({ label, href, Icon, lucide, requiresInstallation }) => {
          const active = isActive(href);
          const disabled = requiresInstallation && !selectedInstallation;
          if (disabled) {
            return (
              <div
                key={href}
                title="Select an installation first"
                className="flex cursor-not-allowed items-center gap-3 rounded-xl px-2.5 py-2.5 opacity-35"
              >
                <span className="h-9 w-9 shrink-0 rounded-xl bg-[var(--surface)] border border-[var(--border)] flex items-center justify-center text-[var(--text-secondary)]">
                  <NavIcon Icon={Icon} lucide={lucide} className="h-[15px] w-[15px]" strokeWidth={1.8} />
                </span>
                <span className="text-[15px] font-medium leading-none text-[var(--text)]">{label}</span>
              </div>
            );
          }
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
                <NavIcon Icon={Icon} lucide={lucide} className="h-[15px] w-[15px]" strokeWidth={1.8} />
              </span>
              <span className={`text-[15px] leading-none text-[var(--text)] ${active ? 'font-semibold' : 'font-medium'}`}>
                {label}
              </span>
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}