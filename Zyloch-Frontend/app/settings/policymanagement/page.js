"use client";

import React, { useState, useEffect } from "react";
import { ScanLine, Shield } from "lucide-react";
import { ScanOptionsCard } from "../components/ScanOptionsCard";
import ScanPoliciesCard from "../components/ScanPoliciesCard";
import { useTenant } from "@/context/TenantContext";
import { useGithubStore } from "@/store/useGithubStore";

const PolicyManagementPage = () => {
  const { can } = useTenant();
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);
  const [activeView, setActiveView] = useState("scan-options");
  const [orgName, setOrgName] = useState(null);

  // Use the GitHub installation account login as orgName so it matches the
  // key used by the GHAPP backend (repo.owner.login from webhook / scan request).
  // Falls back through: selectedInstallation → first installation → user login.
  const selectedInstallation = useGithubStore((s) => s.selectedInstallation);
  const installations = useGithubStore((s) => s.installations);
  const fetchInstallations = useGithubStore((s) => s.fetchInstallations);

  // Scan options and policies both write through `organization.settings.write`.
  const canEditPolicies = can("organization.settings.write") && isAdmin;

  useEffect(() => {
    fetchUserRole();
  }, []);

  // Fetch installations once so we have them for the orgName fallback.
  useEffect(() => {
    if (!installations || installations.length === 0) {
      fetchInstallations().catch(() => { });
    }
  }, [fetchInstallations, installations]);

  // Resolve orgName: prefer the currently-selected GitHub installation, then
  // the first linked installation, then fall back to the auth-derived login.
  useEffect(() => {
    const installationLogin =
      selectedInstallation?.account?.login ||
      (installations && installations.length > 0 ? installations[0]?.account?.login : null);
    if (installationLogin) {
      setOrgName(installationLogin);
    }
  }, [selectedInstallation, installations]);

  const fetchUserRole = async () => {
    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization`,
        { credentials: "include" }
      );

      if (response.ok) {
        const data = await response.json();
        setIsAdmin(data.organization?.userRole === "admin");
        // Set orgName from auth as an initial fallback only if no installation
        // login is available yet (the useEffect above will override this).
        setOrgName((prev) => {
          if (prev) return prev;
          return data.organization?.githubLogin || data.organization?.name || null;
        });
      }
    } catch (error) {
      console.error("Error fetching user role:", error);
    } finally {
      setLoading(false);
    }
  };


  const tabBaseClass =
    "relative box-border h-[46px] rounded-t-[10px] rounded-b-none p-0 text-base leading-6 font-medium transition-all duration-200";
  const activeTabClass =
    "bg-[rgba(var(--color-primary-rgb),0.2)] border-b-2 border-b-[var(--color-primary)] text-[var(--color-primary)]";
  const inactiveTabClass =
    "bg-transparent border-b-2 border-b-transparent text-[var(--text-secondary)] hover:bg-[rgba(var(--muted-rgb),0.08)] hover:text-[var(--text)]";
  const tabBaseStyle = {
    appearance: "none",
    borderTop: "none",
    borderLeft: "none",
    borderRight: "none",
  };

  return (
    <div className="w-full flex flex-col h-full">
      <div className="w-full bg-[var(--surface)] flex flex-col flex-1 h-[calc(100vh-48px)] shadow-[var(--shadow-1)] rounded-lg border border-[var(--border)] overflow-hidden">
        {/* Sticky Header */}
        <div className="flex flex-col items-start px-4 sm:px-6 pt-6 sm:pt-7 pb-0 gap-5 border-b border-[var(--border)] z-30 shrink-0 bg-[var(--surface)]">
          <div className="w-full flex flex-col lg:flex-row justify-between lg:items-center gap-4">
            <div className="flex flex-row items-center gap-[18px] min-w-0">
              <div className="box-border flex flex-row justify-center items-center py-[11px] px-[15px] w-[56px] h-[55px] rounded-lg bg-[rgba(var(--color-primary-rgb),0.1)] border border-[rgba(var(--color-primary-rgb),0.24)]">
                <ScanLine className="w-7 h-7 text-[var(--color-primary)]" />
              </div>

              <div className="flex flex-col items-start gap-[2px] min-w-0">
                <h1 className="text-[32px] leading-[39px] tracking-[-0.02em] font-semibold text-[var(--text)] truncate">
                  {activeView === "scan-options" ? "Scan Options" : "Policy Management"}
                </h1>
                <p className="text-xs leading-[15px] tracking-[0.05em] uppercase text-[var(--muted)]">
                  {activeView === "scan-options"
                    ? "ENABLE OR DISABLE SECURITY SCANS FOR YOUR ORGANIZATION"
                    : "MANAGE SCAN POLICIES FOR YOUR ORGANIZATION"}
                </p>
              </div>
            </div>

            <p className="box-border inline-flex justify-center items-center py-[7px] px-3 rounded-full border bg-[var(--badge-green-bg)] border-[var(--badge-green-border)] text-[var(--badge-green-text)] text-sm leading-5 whitespace-nowrap">
              {isAdmin ? "Admin Access" : "View Only"}
            </p>
          </div>

          <div className="w-full pb-0">
            <div className="flex items-center gap-2 p-0 h-[46px] w-full max-w-[276px]">
              <button
                type="button"
                onClick={() => setActiveView("scan-options")}
                className={`${tabBaseClass} cursor-pointer w-[155px] ${activeView === "scan-options" ? activeTabClass : inactiveTabClass}`}
                style={{
                  ...tabBaseStyle,
                  fontWeight: 500,
                  letterSpacing: "-0.3125px",
                  background:
                    activeView === "scan-options"
                      ? "rgba(var(--color-primary-rgb),0.2)"
                      : "transparent",
                  borderBottom:
                    activeView === "scan-options"
                      ? "2px solid var(--color-primary)"
                      : "2px solid transparent",
                  color: activeView === "scan-options" ? "var(--color-primary)" : "var(--text-secondary)",
                }}
              >
                <ScanLine
                  className={`absolute left-4 top-[14px] h-4 w-4 ${activeView === "scan-options" ? "text-[var(--color-primary)]" : "text-[var(--text-secondary)]"}`}
                />
                <span className="absolute left-[41px] top-[10px] text-base leading-6 tracking-[-0.3125px]">
                  Scan Options
                </span>
              </button>

              <button
                type="button"
                onClick={() => setActiveView("policies")}
                className={`${tabBaseClass} flex items-center justify-center gap-[10px] cursor-pointer w-[113px] ${activeView === "policies" ? activeTabClass : inactiveTabClass}`}
                style={{
                  ...tabBaseStyle,
                  fontWeight: 500,
                  letterSpacing: "-0.3125px",
                  background:
                    activeView === "policies"
                      ? "rgba(var(--color-primary-rgb),0.2)"
                      : "transparent",
                  borderBottom:
                    activeView === "policies"
                      ? "2px solid var(--color-primary)"
                      : "2px solid transparent",
                  color: activeView === "policies" ? "var(--color-primary)" : "var(--text-secondary)",
                }}
              >
                <Shield className={`h-4 w-4 ${activeView === "policies" ? "text-[var(--color-primary)]" : "text-[var(--text-secondary)]"}`} />
                Policies
              </button>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col min-h-0 overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center min-h-[400px]">
              <div className="text-center">
                <div
                  className="animate-spin rounded-full h-12 w-12 mx-auto mb-4"
                  style={{
                    border: "2px solid var(--border)",
                    borderTopColor: "var(--color-primary)",
                  }}
                />
                <p style={{ color: "var(--muted)" }}>
                  Loading configuration...
                </p>
              </div>
            </div>
          ) : activeView === "scan-options" ? (
            <ScanOptionsCard isAdmin={canEditPolicies} orgName={orgName} />
          ) : (
            <ScanPoliciesCard
              orgName={orgName}
              canEdit={canEditPolicies}
              activeView={activeView}
              onTabChange={setActiveView}
            />
          )}
        </div>
        {/* Sticky Footer (if present in child) handled in ScanOptionsCard/ScanPoliciesCard */}
      </div>
    </div>
  );
};

export default PolicyManagementPage;
