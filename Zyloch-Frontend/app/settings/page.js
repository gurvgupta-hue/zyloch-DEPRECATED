"use client";

import React, { useState, useEffect } from "react";
import {
  User,
  ChevronDown,
  Building2,
  ShieldCheck,
  ExternalLink,
  LogOut,
} from "lucide-react";
import { ProfileCard } from "./components/ProfileCard";
import { OrganizationDetailsCard } from "./components/OrganizationDetailsCard";
import { OAuthConfigCard } from "./components/OAuthConfigCard";
import { LicenseCard } from "./components/LicenseCard";
import { MembersCard } from "./components/MembersCard";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useTheme } from "@/context/ThemeContext";
import { useTenant } from "@/context/TenantContext";
import { logout } from "@/lib/api/user";
import { toast } from "react-toastify";

const SettingsPage = () => {
  const { user, refreshUser, theme } = useTheme();
  const { isAdmin: tenantIsAdmin, organizations, switchOrg, clearTenant } = useTenant();
  const isLight = theme === "light";
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isProfileCollapsed, setIsProfileCollapsed] = useState(false);
  const [isOrganizationCollapsed, setIsOrganizationCollapsed] = useState(false);

  useEffect(() => {
    fetchUserRole();
  }, []);

  useEffect(() => {
    if (tenantIsAdmin) setIsAdmin(true);
  }, [tenantIsAdmin]);
  const fetchUserRole = async () => {
    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization`,
        {
          credentials: "include",
        },
      );

      if (response.ok) {
        const data = await response.json();
        setIsAdmin(data.organization?.userRole === "admin");
      }
    } catch (error) {
      console.error("Error fetching user role:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      const toastId = toast.loading("Signing out...");
      await logout(false);
      clearTenant?.();
      toast.update(toastId, {
        render: "Signed out successfully",
        type: "success",
        isLoading: false,
        autoClose: 2000,
      });
    } catch (error) {
      toast.error("Failed to sign out: " + error.message);
    }
  };

  const borderSoft = "color-mix(in srgb, var(--border) 60%, transparent)";
  const sectionStyle = {
    background: isLight ? "rgba(255,255,255,0.92)" : "rgb(22 22 29 / 44%)",
    border: `1px solid ${borderSoft}`,
    boxShadow: "var(--shadow-1)",
    borderRadius: "16px",
  };
  const tileStyle = {
    background: "rgba(var(--color-primary-rgb), 0.1)",
    border: "1px solid rgba(var(--color-primary-rgb), 0.3)",
  };
  const collapseButtonStyle = {
    border: `1px solid ${borderSoft}`,
    background: isLight ? "rgba(var(--color-primary-rgb),0.08)" : "rgba(var(--surface-rgb),0.05)",
    color: "var(--muted)",
  };

  return (
    <div className="w-full pb-10" style={{ background: "transparent" }}>
      <div className="w-full px-3 sm:px-5 lg:px-7 pt-3">
        <header className="flex flex-wrap items-center justify-between gap-4 border-b pb-5" style={{ borderColor: "var(--border)" }}>
          <div className="flex items-center gap-4 min-w-0">
            <span className="h-14 w-14 rounded-xl flex items-center justify-center shrink-0" style={tileStyle}>
              <User size={24} style={{ color: "var(--color-primary)" }} />
            </span>
            <div className="min-w-0">
              <h1 className="text-2xl sm:text-3xl font-semibold leading-tight" style={{ color: "var(--text)" }}>
                Account Settings
              </h1>
              <p className="text-sm mt-1" style={{ color: "var(--muted)" }}>
                Manage your profile, organization, and integrations.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 ml-auto">
            {user?.login && (
              <a
                href={`https://github.com/${user.login}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-opacity hover:opacity-90 sm:text-sm"
                style={{
                  background: "var(--color-primary)",
                  color: "var(--text-on-primary)",
                }}
              >
                <ExternalLink size={14} />
                GitHub Profile
              </a>
            )}
            <ThemeToggle />
          </div>
        </header>

        <main className="flex flex-col gap-5 pt-5">
          <section className="rounded-2xl p-4 sm:p-6" style={sectionStyle}>
            <div className="flex flex-wrap items-start justify-between gap-3 mb-5">
              <div className="flex items-start gap-3 min-w-0">
                <span className="h-9 w-9 rounded-lg flex items-center justify-center shrink-0" style={tileStyle}>
                  <User size={16} style={{ color: "var(--color-primary)" }} />
                </span>
                <div>
                  <h2 className="text-base sm:text-lg font-semibold" style={{ color: "var(--text)" }}>
                    Profile Settings
                  </h2>
                  <p className="text-xs sm:text-sm" style={{ color: "var(--muted)" }}>
                    Update personal details, timezone and profile preferences.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsProfileCollapsed((prev) => !prev)}
                className="inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition-opacity hover:opacity-85"
                style={collapseButtonStyle}
              >
                {isProfileCollapsed ? "Expand" : "Collapse"}
                <ChevronDown size={14} className={`transition-transform ${isProfileCollapsed ? "" : "rotate-180"}`} />
              </button>
            </div>
            {!isProfileCollapsed && <ProfileCard />}
          </section>

          <section className="rounded-2xl p-4 sm:p-6" style={sectionStyle}>
            <div className="flex flex-wrap items-start justify-between gap-3 mb-5">
              <div className="flex items-start gap-3 min-w-0">
                <span className="h-9 w-9 rounded-lg flex items-center justify-center shrink-0" style={tileStyle}>
                  <Building2 size={16} style={{ color: "var(--color-primary)" }} />
                </span>
                <div>
                  <h2 className="text-base sm:text-lg font-semibold" style={{ color: "var(--text)" }}>
                    Organization Management
                  </h2>
                  <p className="text-xs sm:text-sm" style={{ color: "var(--muted)" }}>
                    View organization details, identity, and member context.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsOrganizationCollapsed((prev) => !prev)}
                className="inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition-opacity hover:opacity-85"
                style={collapseButtonStyle}
              >
                {isOrganizationCollapsed ? "Expand" : "Collapse"}
                <ChevronDown size={14} className={`transition-transform ${isOrganizationCollapsed ? "" : "rotate-180"}`} />
              </button>
            </div>
            {!isOrganizationCollapsed && <OrganizationDetailsCard isAdmin={isAdmin} />}
          </section>

          <section className="rounded-2xl p-4 sm:p-6" style={sectionStyle}>
            <LicenseCard />
          </section>

          <section className="rounded-2xl p-4 sm:p-6" style={sectionStyle}>
            <MembersCard isAdmin={isAdmin} />
          </section>

          {organizations?.length > 1 && (
            <section className="rounded-2xl p-4 sm:p-5" style={sectionStyle}>
              <h2 className="text-base font-semibold mb-3" style={{ color: "var(--text)" }}>
                Switch organization
              </h2>
              <p className="text-xs mb-3" style={{ color: "var(--muted)" }}>
                Switching re-issues your session cookie (no silent cross-org data).
              </p>
              <div className="flex flex-wrap gap-2">
                {organizations.map((org) => (
                  <button
                    key={org.tenantId}
                    type="button"
                    disabled={org.current}
                    onClick={() => switchOrg(org.tenantId)}
                    className="rounded-lg px-3 py-2 text-sm"
                    style={{
                      border: "1px solid var(--border)",
                      opacity: org.current ? 0.6 : 1,
                    }}
                  >
                    {org.name || org.domain || org.tenantId}
                    {org.current ? " (current)" : ""}
                  </button>
                ))}
              </div>
            </section>
          )}

          {!loading && isAdmin && (
            <section className="rounded-2xl p-4 sm:p-6" style={sectionStyle}>
              <div className="flex items-start gap-3 mb-5">
                <span className="h-9 w-9 rounded-lg flex items-center justify-center shrink-0" style={tileStyle}>
                  <ShieldCheck size={16} style={{ color: "var(--color-primary)" }} />
                </span>
                <div>
                  <h2 className="text-base sm:text-lg font-semibold" style={{ color: "var(--text)" }}>
                    OAuth Configuration
                  </h2>
                  <p className="text-xs sm:text-sm" style={{ color: "var(--muted)" }}>
                    Connect identity providers for organization sign-in.
                  </p>
                </div>
              </div>
              <OAuthConfigCard />
            </section>
          )}

          <section className="rounded-2xl p-4 sm:p-5" style={sectionStyle}>
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <p className="text-sm" style={{ color: "var(--muted)" }}>
                Current role: {isAdmin ? "Organization Admin" : "Organization Member"}
              </p>
              <button
                onClick={handleLogout}
                className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-opacity hover:opacity-85"
                style={{
                  border: "1px solid rgba(var(--danger-rgb), 0.28)",
                  background: "rgba(var(--danger-rgb), 0.08)",
                  color: "var(--danger)",
                }}
              >
                <LogOut size={14} />
                Sign Out
              </button>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
};

export default SettingsPage;
