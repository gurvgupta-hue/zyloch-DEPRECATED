'use client';

import React, { useState, useCallback, useEffect } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { usePathname } from 'next/navigation';
import {
  ArrowLeft,
  PanelLeftClose,
  PanelLeftOpen
} from 'lucide-react';
import { useGithubStore } from '@/store/useGithubStore';
import { useTheme } from '@/context/ThemeContext';
import { useTenant } from '@/context/TenantContext';
import Logo from '@/public/zyloch_logo.webp';
import BlackLogo from '@/public/zyloch-black-logo.png';

const ALL_ITEMS = [
  { label: 'Overview', id: 'overview', path: '/scanops/overview' },
  { label: 'Workflow', id: 'workflow', path: '/scanops/workflow' },
  { label: 'Spec Scanner', id: 'spec-scanner', path: '/scanops/spec-scanner' },
  { label: 'Secret Scanner', id: 'secret-scanner', path: '/scanops/secret-scanner' },
  { label: 'SBOM', id: 'sbom', path: '/scanops/sbom' },
  { label: 'Infrastructure as Code', id: 'iac', path: '/scanops/iac' },
  { label: 'AI Security Scanner', id: 'skill-scanner', path: '/scanops/ai-security-scanner' },
];

const SIDEBAR_SCANNER_ICONS = {
  overview: '/assets/icons/scan/overviewscanicon/OVERVIEW.svg',
  workflow: '/assets/icons/scan/overviewscanicon/GITHUB%20WORKFLOW.svg',
  'spec-scanner': '/assets/icons/scan/overviewscanicon/API%20SCANNER.svg',
  'yaml-json': '/assets/icons/scan/overviewscanicon/CODEX.svg',
  'secret-scanner': '/assets/icons/scan/overviewscanicon/Artboard%2025.svg',
  yara: '/assets/icons/scan/overviewscanicon/CODE%20QUALITY.svg',
  sbom: '/assets/icons/scan/overviewscanicon/CVE.svg',
  iac: '/assets/icons/scan/overviewscanicon/INFRA%20CODE%20SCANNING.svg',
  'skill-scanner': '/assets/icons/scan/overviewscanicon/AISkill.svg',
};

function SidebarIcon({ id, className = '' }) {
  const iconPath = SIDEBAR_SCANNER_ICONS[id] || SIDEBAR_SCANNER_ICONS.overview;

  return (
    <span
      className={`inline-block shrink-0 ${className}`}
      role="img"
      aria-hidden="true"
      style={{
        backgroundColor: 'currentColor',
        WebkitMaskImage: `url("${iconPath}")`,
        maskImage: `url("${iconPath}")`,
        WebkitMaskRepeat: 'no-repeat',
        maskRepeat: 'no-repeat',
        WebkitMaskPosition: 'center',
        maskPosition: 'center',
        WebkitMaskSize: 'contain',
        maskSize: 'contain',
      }}
    />
  );
}

/**
 * Sidebar entry -> the licensed scanner key(s) it needs (MT-05.5).
 *
 * An entry is shown when the plan entitles ANY of its scanners; `iac` fans out
 * because one nav item covers several backend scanners. `overview` is omitted:
 * it reports on scans rather than running one, so it is never gated.
 */
const SIDEBAR_SCANNER_KEYS = {
  workflow: ['workflow'],
  'spec-scanner': ['spec-scanner'],
  'secret-scanner': ['secret_scanner'],
  sbom: ['sbom'],
  iac: [
    'docker',
    'kubernetes',
    'terraform_aws',
    'terraform_azure',
    'terraform_gcp',
    'bicep',
    'ansible',
    'cloudformation',
  ],
  // The 'AI Security Scanner' nav item. Unmapped ids are treated as ungated, so
  // without this a Free tenant saw the page and got
  // "Scanner not included in your plan" on trigger. It also fans out to
  // 'cis-agent': the page hosts a CIS Scanner tab alongside the skill-scanner
  // findings, so either license entitles the nav item.
  'skill-scanner': ['skill-scanner', 'cis-agent'],
};

export default function Sidebar({ isOpen = false, showToggle = false, onToggle = null }) {
  const pathname = usePathname();
  const { theme } = useTheme();
  const { hasScanner } = useTenant();
  const setSelectedRepo = useGithubStore((s) => s.setSelectedRepo);
  const toggleBtnClass = 'inline-flex items-center justify-center p-1 text-[var(--text)] transition-all duration-200 hover:scale-110 hover:text-[var(--color-primary)] focus-visible:outline-none';
  const sidebarLogo = theme === 'light' ? BlackLogo : Logo;

  const [tip, setTip] = useState(null);
  const [scanStates, setScanStates] = useState({
    overview: true,
    workflow: true,
    'spec-scanner': true,
    'secret-scanner': true,
    sbom: true,
    iac: true,
    'skill-scanner': true
  });

  useEffect(() => {
    fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/organization/scans`, { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.scanConfigurations) setScanStates(prev => ({ ...prev, ...data.scanConfigurations })); })
      .catch(() => { });
  }, []);

  const isActive = (path) => pathname === path || pathname.startsWith(path + '/');

  const showTip = useCallback((e, label) => {
    const r = e.currentTarget.getBoundingClientRect();
    setTip({ label, x: r.right + 12, y: r.top + r.height / 2 });
  }, []);
  const hideTip = useCallback(() => setTip(null), []);

  const handleBack = () => setSelectedRepo(null);

  // Two independent gates: what the plan licenses (MT-05.5) and what the tenant
  // has switched on. The licence check mirrors the backend scan-trigger gate, so
  // a visible scanner is always one that will actually run.
  const isLicensed = (id) => {
    const required = SIDEBAR_SCANNER_KEYS[id];
    if (!required) return true; // overview and anything not scanner-backed
    return required.some((key) => hasScanner(key));
  };

  const navItems = ALL_ITEMS
    .filter(i => isLicensed(i.id) && scanStates[i.id])
    .map(item => ({
      ...item,
      Icon: (props) => <SidebarIcon id={item.id} {...props} />
    }));

  /* -- Collapsed rail ----------------------------------------------- */
  if (!isOpen) {
    return (
      <>
        <aside className="flex h-full w-full flex-col rounded-xl bg-transparent backdrop-blur-2xl">

          {/* Toggle */}
          <div className="flex h-14 w-full shrink-0 items-center justify-center border-b border-[var(--border)]">
            {showToggle && (
              <button
                type="button"
                onClick={onToggle}
                aria-label="Expand sidebar"
                className={toggleBtnClass}
              >
                <PanelLeftOpen className="h-5 w-5" strokeWidth={2.4} />
              </button>
            )}
          </div>

          {/* Nav */}
          <nav className="flex flex-1 flex-col items-center gap-0.5 py-4 px-3">
            {navItems.map(({ label, id, path, Icon }) => {
              const active = isActive(path);
              return (
                <div key={id} className="relative flex w-full items-center justify-center py-0.5">
                  {active && (
                    <span className="pointer-events-none absolute left-0 top-1/2 h-6 w-[3px] -translate-y-1/2 rounded-r-full bg-[var(--color-primary)]" />
                  )}
                  <Link
                    href={path}
                    prefetch={true}
                    aria-label={label}
                    onMouseEnter={(e) => showTip(e, label)}
                    onMouseLeave={hideTip}
                    className={`group flex h-10 w-10 items-center justify-center rounded-xl transition-all duration-200 ease-out ${active
                      ? 'bg-[rgba(var(--color-primary-rgb),0.15)] text-[var(--color-primary)] shadow-[0_0_14px_rgba(var(--color-primary-rgb),0.18)]'
                      : 'text-[var(--text-secondary)] hover:bg-[rgba(var(--color-primary-rgb),0.12)] hover:text-[var(--text)]'
                      }`}
                  >
                    {Icon && (
                      <Icon className={`h-[18px] w-[18px] transition-transform duration-200 group-hover:scale-110 ${active ? 'text-[var(--color-primary)]' : 'text-[var(--text-secondary)]'}`} strokeWidth={1.9} />
                    )}
                  </Link>
                </div>
              );
            })}
          </nav>

          {/* Back to Dashboard */}
          <div className="mx-4 h-px bg-[var(--border)]" />
          <div className="flex shrink-0 items-center justify-center py-3">
            <Link
              href="/dashboard"
              prefetch={true}
              onClick={handleBack}
              aria-label="Back to Dashboard"
              onMouseEnter={(e) => showTip(e, 'Dashboard')}
              onMouseLeave={hideTip}
              className="group flex h-10 w-10 items-center justify-center rounded-xl text-[var(--muted)] transition-all duration-200 ease-out hover:bg-[var(--bg-hover)] hover:text-[var(--text)]"
            >
              <ArrowLeft className="h-[18px] w-[18px] transition-transform duration-200 group-hover:scale-110" strokeWidth={1.8} />
            </Link>
          </div>
        </aside>

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

  /* -- Expanded ----------------------------------------------------- */
  return (
    <aside className="flex h-full w-full flex-col overflow-hidden rounded-[20px] bg-transparent backdrop-blur-2xl">

      {/* Header */}
      <div className="flex h-14 shrink-0 items-center justify-between border-b border-[var(--border)] px-3.5">
        <Image src={sidebarLogo} alt="Zyloch" className="w-[110px] h-auto shrink-0 object-contain" priority />
        {showToggle && (
          <button
            type="button"
            onClick={onToggle}
            aria-label="Collapse sidebar"
            className={toggleBtnClass}
          >
            <PanelLeftClose className="h-5 w-5" strokeWidth={2.4} />
          </button>
        )}
      </div>

      {/* Nav */}
      <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto px-2.5 py-3">
        {navItems.map(({ label, id, path, Icon }) => {
          const active = isActive(path);
          return (
            <Link
              key={id}
              href={path}
              prefetch={true}
              className={`group flex w-full items-center gap-3 rounded-xl px-2.5 py-2.5 transition-all duration-200 ease-out ${active
                ? 'bg-[rgba(var(--color-primary-rgb),0.20)] text-[var(--text)] shadow-[inset_0_0_0_1px_rgba(var(--color-primary-rgb),0.35)]'
                : 'text-[var(--text-secondary)] hover:bg-[rgba(var(--color-primary-rgb),0.10)] hover:text-[var(--text)]'
                }`}
            >
              <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-all duration-200 ${active
                ? 'h-9 w-9 rounded-xl bg-[var(--color-primary)] border border-[var(--color-primary-600)] text-[var(--text-on-primary)] shadow-[0_6px_14px_rgba(var(--color-primary-rgb),0.35)]'
                : 'h-9 w-9 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text-secondary)] group-hover:border-[rgba(var(--color-primary-rgb),0.45)] group-hover:bg-[rgba(var(--color-primary-rgb),0.12)] group-hover:text-[var(--text)]'
                }`}>
                {Icon && <Icon className="h-[15px] w-[15px]" strokeWidth={1.9} />}
              </span>
              <span className={`text-[15px] leading-none text-[var(--text)] ${active ? 'font-semibold' : 'font-medium'}`}>
                {label}
              </span>
            </Link>
          );
        })}
      </nav>

      {/* Back to Dashboard */}
      <div className="shrink-0 border-t border-[var(--border)] px-2.5 py-3">
        <Link
          href="/dashboard"
          prefetch={true}
          onClick={handleBack}
          className="group flex w-full items-center gap-3 rounded-xl px-2.5 py-2.5 text-[var(--text-secondary)] transition-all duration-200 ease-out hover:bg-[rgba(var(--color-primary-rgb),0.10)] hover:text-[var(--text)]"
        >
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text-secondary)] transition-all duration-200 group-hover:border-[rgba(var(--color-primary-rgb),0.45)] group-hover:bg-[rgba(var(--color-primary-rgb),0.12)] group-hover:text-[var(--text)]">
            <ArrowLeft className="h-[15px] w-[15px]" strokeWidth={1.8} />
          </span>
          <span className="text-[15px] font-medium leading-none">Back to Dashboard</span>
        </Link>
      </div>
    </aside>
  );
}
