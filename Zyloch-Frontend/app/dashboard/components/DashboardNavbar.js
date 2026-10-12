"use client";

import React, { useEffect, memo, useCallback } from "react";
import { driver } from "driver.js";
import "driver.js/dist/driver.css";
import Link from "next/link";
import {
  ChevronDown,
  Building2,
  User,
  Crown,
  RefreshCw,
  Loader2,
  X,
  Menu,
  Plug,
} from "lucide-react";
import { useNavbar } from "@/hooks/useNavbar";
import { useGithubStore } from "@/store/useGithubStore";
import { ThemeToggle } from "@/components/ThemeToggle";

// Memoized icon component for better performance
const AccountIcon = memo(({ type, size = 14 }) => {
  switch (type) {
    case "organization":
      return <Building2 size={size} className="text-[var(--color-primary)]" />;
    case "enterprise":
      return <Crown size={size} className="text-[var(--color-secondary)]" />;
    case "user":
      return <User size={size} className="text-[var(--success)]" />;
    default:
      return <User size={size} className="text-[var(--success)]" />;
  }
});
AccountIcon.displayName = 'AccountIcon';

// Memoized SelectionPill component
const SelectionPill = memo(({ label, value, icon, onClear }) => (
  <div className="group flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyan-500/20 bg-cyan-500/10 hover:bg-[var(--surface)] transition-colors duration-150 ease-out">
    <div className="flex items-center gap-1.5 min-w-0">
      {icon}
      <span className="text-m font-bold text-cyan-500 whitespace-nowrap">{label}:</span>
      <span className="text-xs text-[var(--text)] truncate max-w-[120px] font-medium">
        {value}
      </span>
    </div>
    <div
      onClick={onClear}
      className="p-0.5 text-[var(--muted)] hover:text-[var(--color-primary)] rounded group-hover:opacity-100 transition-all duration-150 ease-out flex-shrink-0"
      title={`Change ${label}`}
      aria-label={`Change ${label}`}
    >
      <X size={12} />
    </div>
  </div>
));
SelectionPill.displayName = 'SelectionPill';

const ACCOUNT_TOUR_DONE_KEY = "zyloch-account-tour-done";

// Driver.js tour pointing at the GitHub Account picker. Returns a cleanup that
// cancels it if it has not started yet. `onFire` runs when the delay elapses;
// returning false from it skips the tour.
function scheduleAccountTour({ onFire } = {}) {
  const timeout = setTimeout(() => {
    if (onFire?.() === false) return;
    const el = document.getElementById("github-account-btn");
    if (!el) return;

    const tour = driver({
      animate: true,
      overlayOpacity: 0.35,
      steps: [
        {
          element: "#github-account-btn",
          popover: {
            title: "Select a GitHub Account",
            description:
              "Click here to choose a GitHub installation and unlock your repository analytics and insights.",
            side: "bottom",
            align: "start",
          },
        },
      ],
      onDestroyStarted: () => {
        localStorage.setItem(ACCOUNT_TOUR_DONE_KEY, "1");
        tour.destroy();
      },
    });

    tour.drive();
  }, 600);

  return () => clearTimeout(timeout);
}

const DashboardNavbar = ({ onToggleSidebar }) => {
  const {
    installations,
    selectedInstallation,
    loading,
    error,
    activeDropdown,
    dropdownRefs,
    setActiveDropdown,
    getAccountIcon,
    resetSelection,
    fetchInstallations,
    setSelectedInstallation,
    userRole,
  } = useNavbar();

  const connectingInstallation = useGithubStore((s) => s.connectingInstallation);
  const connectedInstallationId = useGithubStore((s) => s.connectedInstallationId);
  const acknowledgeConnectedInstallation = useGithubStore(
    (s) => s.acknowledgeConnectedInstallation
  );
  const isConnecting = Boolean(connectingInstallation && !connectingInstallation.timedOut);

  useEffect(() => {
    fetchInstallations();
  }, [fetchInstallations]);

  // One-time Driver.js tour for the GitHub Account dropdown. Held back while a
  // fresh install is still connecting — there is nothing to pick yet, and the
  // effect below shows it once there is.
  useEffect(() => {
    if (localStorage.getItem(ACCOUNT_TOUR_DONE_KEY)) return;
    // Checked when the tour fires: the dashboard starts the wait in its own
    // mount effect, which may run after this one.
    return scheduleAccountTour({
      onFire: () => !useGithubStore.getState().connectingInstallation,
    });
  }, []);

  // A just-installed account has arrived: always walk the user to the picker,
  // even if they dismissed the tour on an earlier visit.
  useEffect(() => {
    if (!connectedInstallationId) return;
    // Acknowledged only when the tour fires: clearing the flag re-runs this
    // effect, and its cleanup would otherwise cancel the pending tour.
    return scheduleAccountTour({ onFire: acknowledgeConnectedInstallation });
  }, [connectedInstallationId, acknowledgeConnectedInstallation]);

  // Memoize handlers
  const handleDropdownToggle = useCallback(() => {
    setActiveDropdown("installation");
  }, [setActiveDropdown]);

  const handleClearSelection = useCallback(() => {
    resetSelection("installation");
  }, [resetSelection]);

  const handleInstallationSelect = useCallback((install) => {
    setSelectedInstallation(install);
  }, [setSelectedInstallation]);

  const handleRefresh = useCallback((e) => {
    e.stopPropagation();
    fetchInstallations();
  }, [fetchInstallations]);

  const renderDropdown = () => {
    if (activeDropdown !== "installation") return null;

    return (
      <div
        className="absolute left-0 top-full mt-1 w-72 bg-[var(--surface)] rounded-lg shadow-xl border border-[var(--border)] z-50 max-h-80 overflow-y-auto will-change-transform backdrop-blur-sm bg-opacity-95 animate-fadeIn"
        ref={dropdownRefs.installation}
        style={{
          animation: 'fadeIn 0.2s ease-out',
          transformOrigin: 'top left'
        }}
      >
        <div className="py-1">
          {/* Header */}
          <div className="flex items-center justify-between px-3 py-2 border-b border-[var(--border)]">
            <span className="text-xs font-semibold text-[var(--muted)] tracking-wide">
              Select Installation
            </span>
            <button
              onClick={handleRefresh}
              className="p-1 hover:bg-[var(--elevated-surface)] rounded transition-all duration-150 active:scale-95"
              title="Refresh"
              aria-label="Refresh installations"
            >
              <RefreshCw size={12} className="text-[var(--muted)]" />
            </button>
          </div>

          {/* Installation Options */}
          {installations.length > 0 ? (
            <div className="max-h-60 overflow-y-auto">
              {installations.map((install) => (
                <button
                  key={install.installationId}
                  className="flex items-center w-full px-3 py-2.5 text-sm hover:bg-[var(--elevated-surface)] active:bg-[var(--border)] transition-colors duration-100 ease-out group/item"
                  onClick={() => handleInstallationSelect(install)}
                >
                  <AccountIcon type={getAccountIcon(install.account.type)} size={14} />
                  <span className="ml-2.5 text-[var(--text)] truncate flex-1 text-left group-hover/item:text-[var(--color-primary)] transition-colors">
                    {install.account.login}
                  </span>
                  <span className="text-xs text-[var(--muted)] capitalize px-1.5 py-0.5 rounded bg-[var(--elevated-surface)]">
                    {install.account.type}
                  </span>
                </button>
              ))}
            </div>
          ) : (
            <div className="p-4 text-center text-sm text-[var(--muted)]">
              {loading.installations || isConnecting ? (
                <div className="flex flex-col items-center justify-center gap-2">
                  <Loader2 size={16} className="animate-spin text-[var(--color-primary)]" />
                  <span>
                    {isConnecting
                      ? "Connecting to your GitHub account..."
                      : "Loading installations..."}
                  </span>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-1">
                  <Building2 size={20} className="text-[var(--muted)] mb-1" />
                  <span>No GitHub installations found</span>
                </div>
              )}
            </div>
          )}

          {/* Install GitHub Link - Only show for admins */}
          {userRole === 'admin' && (
            <div className="border-t border-[var(--border)] mt-1 pt-1">
              <Link
                href="/home"
                className="flex items-center justify-center gap-2 w-full px-3 py-2.5 text-sm font-medium text-[var(--color-primary)] hover:bg-[var(--elevated-surface)] active:bg-[var(--border)] transition-colors duration-150 rounded-b-lg group"
                prefetch={false}
              >
                <Plug size={16} className="text-[var(--color-primary)] group-hover:scale-110 transition-transform" />
                <span className="group-hover:translate-x-0.5 transition-transform">
                  Install GitHub
                </span>
              </Link>
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <nav className="flex items-center justify-between gap-3 px-3 py-3 relative">
      {/* Left side: Mobile menu and installation selector */}
      <div className="flex items-center gap-3">
        {/* Mobile Hamburger */}
        <button
          onClick={onToggleSidebar}
          className="sm:hidden p-2 rounded-lg hover:bg-[var(--elevated-surface)] active:bg-[var(--border)] transition-all duration-150 active:scale-95 text-[var(--text)]"
          aria-label="Toggle sidebar"
        >
          <Menu size={20} />
        </button>

        {/* Installation Dropdown */}
        {selectedInstallation ? (
          <SelectionPill
            label="GitHub Account"
            value={selectedInstallation.account.login}
            icon={<AccountIcon type={getAccountIcon(selectedInstallation.account.type)} />}
            onClear={handleClearSelection}
          />
        ) : (
          <div className="relative">
            <button
              id="github-account-btn"
              className="flex items-center gap-2 px-3 py-1.5 text-sm text-[var(--text)] bg-[var(--elevated-surface)] hover:bg-[var(--surface)] active:bg-[var(--border)] rounded-lg border border-[var(--border)] transition-all duration-150 min-w-[140px] active:scale-[0.98] group"
              onClick={handleDropdownToggle}
              aria-expanded={activeDropdown === "installation"}
              aria-haspopup="true"
            >
              {loading.installations || isConnecting ? (
                <Loader2 size={14} className="animate-spin text-[var(--muted)]" />
              ) : (
                <Building2 size={14} className="text-[var(--muted)] group-hover:text-[var(--color-primary)] transition-colors" />
              )}
              <span className="font-medium">GitHub Account</span>
              <ChevronDown
                size={12}
                className={`text-[var(--muted)] ml-auto transition-transform duration-200 ${activeDropdown === "installation" ? "rotate-180" : ""}`}
              />
            </button>
            {renderDropdown()}
          </div>
        )}
      </div>

      {/* Right side: Error state and Theme Toggle */}
      <div className="flex items-center gap-3 ml-auto">
        {/* Error State */}
        {error && (
          <div className="px-3 py-1.5 text-xs text-[var(--danger)] bg-[var(--danger)]/10 rounded-lg border border-[var(--danger)]/20 animate-fadeIn max-w-[200px] truncate">
            {error}
          </div>
        )}

        {/* Theme Toggle */}
        <div className="flex items-center">
          <ThemeToggle />
        </div>
      </div>
    </nav>
  );
};

export default memo(DashboardNavbar);