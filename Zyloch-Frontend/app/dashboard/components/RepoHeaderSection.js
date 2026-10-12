"use client";

import React from "react";
import RepoLoading from "./RepoLoading";
import { useTheme } from "@/context/ThemeContext";
import {
  Plus,
  RefreshCw,
  GitBranch,
  Code2,
  FolderGit2,
  Users
} from "lucide-react";

const RepoHeaderSection = ({
  summaryAnalysis = {},
  selectedInstallation = {},
  refreshSummary,
  totalRepositories = 0,
  totalBranches = 0,
  totalTeams = 0,
  totalTeamMembers = 0,
  teamsArray = [],
  languagesArray = [],
  loading = {},
  newSummaryAnalysis, // Add this prop
}) => {
  const { theme } = useTheme();
  const isLight = theme === "light";
  const status = summaryAnalysis?.status || "idle";
  const isOrganization = selectedInstallation?.account?.type === "Organization";

  // Safely parsed values
  const safeRepos = Number(totalRepositories) || 0;
  const safeBranches = Number(totalBranches) || 0;
  const safeLanguages = Array.isArray(languagesArray)
    ? languagesArray.length
    : 0;
  const safeTeams = Number(totalTeams) || 0;
  const safeTeamMembers = Number(totalTeamMembers) || 0;

  // KPI list - conditionally include teams for organizations
  const stats = [
    {
      label: "Repositories",
      value: safeRepos,
      icon: FolderGit2,
      color: "var(--color-primary)",
      bgColor: "rgba(var(--color-primary-rgb, 59, 130, 246), 0.25)",
    },
    {
      label: "Branches",
      value: safeBranches,
      icon: GitBranch,
      color: "var(--color-secondary)",
      bgColor: "rgba(var(--color-secondary-rgb, 16, 185, 129), 0.25)",
    },
    {
      label: "Languages",
      value: safeLanguages,
      icon: Code2,
      color: "var(--color-accent)",
      bgColor: "rgba(var(--color-accent-rgb, 245, 158, 11), 0.25)",
    },
  ];

  // Add teams stats only for organizations
  if (isOrganization) {
    stats.push({
      label: "Teams",
      value: safeTeams,
      icon: Users,
      color: "var(--color-info)",
      bgColor: "rgba(var(--color-info-rgb, 99, 102, 241), 0.25)",
    });
  }

  const isRefreshing = status === "in_progress";

  // Handle New Analysis button click
  const handleNewAnalysis = () => {
    if (!selectedInstallation?.installationId) {
      console.error("No installation selected");
      return;
    }

    // Reset summary and start fresh analysis
    if (newSummaryAnalysis) {
      newSummaryAnalysis(selectedInstallation.installationId);
    }
  };

  return (
    <div className="w-full flex flex-col gap-5">
      {/* HEADER */}
      <div
        className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 bg-[var(--surface)] px-4 py-4 rounded-[var(--radius-lg)]"
        style={{
          boxShadow: "var(--shadow-1)",
          border: "1px solid var(--border)",
        }}
      >
        <div className="space-y-2">
          <h1 className="font-bold text-[23px] text-[var(--text)]">
            Repository Analysis
          </h1>
          <p className="text-[var(--muted)] text-[13px] p-0">
            {selectedInstallation?.account?.login || "Organization"}{" "}
            repositories
          </p>
        </div>

        {/* ACTION BUTTONS */}
        <div className="flex w-full sm:w-auto flex-wrap sm:flex-nowrap items-center gap-3">
          {/* New Analysis Button */}
          <button
            onClick={handleNewAnalysis}
            disabled={isRefreshing || !selectedInstallation}
            className="new-analysis-btn group flex-1 sm:flex-none justify-center sm:justify-start items-center gap-3 px-4 sm:px-5 py-2.5 rounded-[var(--radius-lg)] font-medium text-[var(--font-size-sm)] border transition-all duration-200 hover:shadow-[var(--shadow-soft)] active:scale-[0.98] disabled:opacity-60 disabled:cursor-not-allowed"
            style={
              isLight
                ? {
                  background:
                    "color-mix(in srgb, var(--success) 12%, transparent)",
                  color: "var(--success)",
                  borderColor:
                    "color-mix(in srgb, var(--success) 28%, transparent)",
                }
                : undefined
            }
          >
            <Plus className="w-4 h-4" />
          </button>

          {/* Refresh Button (for incremental updates) */}
          <button
            onClick={refreshSummary}
            disabled={isRefreshing}
            className="refresh-btn group flex-1 sm:flex-none justify-center sm:justify-start items-center gap-3 px-4 sm:px-5 py-2.5 rounded-[var(--radius-lg)] font-medium text-[var(--font-size-sm)] border transition-all duration-200 disabled:opacity-60 disabled:cursor-not-allowed hover:shadow-[var(--shadow-soft)] active:scale-[0.98]"
            style={
              isLight
                ? {
                  background:
                    "color-mix(in srgb, var(--info) 12%, transparent)",
                  color: "var(--info)",
                  borderColor:
                    "color-mix(in srgb, var(--info) 28%, transparent)",
                }
                : undefined
            }
          >
            <RefreshCw
              className={`w-4 h-4 transition-transform ${isRefreshing ? "animate-spin" : "group-hover:rotate-180"
                }`}
            />
          </button>
        </div>
      </div>

      {/* KPI CARDS */}
      {loading?.repositories ? (
        <RepoLoading message="Loading repositories..." variant="inline" />
      ) : (
        <div className={`grid grid-cols-1 ${isOrganization ? 'md:grid-cols-2 lg:grid-cols-4' : 'md:grid-cols-3'} gap-4`}>
          {stats.map(({ label, value, icon: Icon, color, bgColor }, i) => (
            <div
              key={i}
              className="group p-5 w-full rounded-[var(--radius-lg)] transition-all duration-200"
              style={{
                background: "var(--surface)",
                boxShadow: "var(--shadow-1)",
                border: "1px solid var(--border)",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.boxShadow = "var(--shadow-2)")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.boxShadow = "var(--shadow-1)")
              }
            >
              <div className="flex items-center gap-4">
                {/* Icon wrapper */}
                <div
                  className="p-3 rounded-[var(--radius-md)] transition-transform duration-300 group-hover:scale-110"
                  style={{
                    backgroundColor: bgColor,
                  }}
                >
                  <Icon className="w-5 h-5" style={{ color }} />
                </div>

                {/* Content */}
                <div className="space-y-1">
                  <p className="text-[var(--muted)] text-[var(--font-size-sm)]">
                    {label}
                  </p>
                  <p
                    className="font-semibold text-[var(--font-size-2xl)]"
                    style={{ color }}
                  >
                    {value.toLocaleString()}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default RepoHeaderSection;
