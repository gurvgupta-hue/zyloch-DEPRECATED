"use client";

import React from "react";
import { useRouter } from "next/navigation";
import {
  Globe,
  Lock,
  GitBranch,
  Star,
  GitCommit,
  Archive,
  Clock,
  ArrowRight,
} from "lucide-react";

export default function RepoPerformanceSection({ summary = {} }) {
  const router = useRouter();

  const totals = summary?.totals || summary || {};
  const {
    totalCommits = 0,
    totalForks = 0,
    totalStars = 0,
    totalPrivate = 0,
    totalPublic = 0,
    totalInternal = 0,
    totalArchivedRepos = 0,
    totalStaleBranches = 0,
  } = totals;

  const stats = [
    {
      label: "Public Repos",
      value: totalPublic,
      icon: Globe,
      color: "text-primary",
      bg: "bg-primary/20",
      type: "public",
    },
    {
      label: "Private Repos",
      value: totalPrivate,
      icon: Lock,
      color: "text-secondary",
      bg: "bg-secondary/20",
      type: "private",
    },
    ...(totalInternal > 0 ? [{
      label: "Internal Repos",
      value: totalInternal,
      icon: Lock,
      color: "text-info",
      bg: "bg-info/20",
      type: "internal",
    }] : []),
    {
      label: "Total Forks",
      value: totalForks,
      icon: GitBranch,
      color: "text-warning",
      bg: "bg-warning/20",
      type: "forks",
    },
    {
      label: "Total Stars",
      value: totalStars,
      icon: Star,
      color: "text-accent",
      bg: "bg-accent/20",
      type: "stars",
    },
    {
      label: "Total Commits",
      value: totalCommits,
      icon: GitCommit,
      color: "text-success",
      bg: "bg-success/20",
      type: "commits",
    },
    {
      label: "Archived Repos",
      value: totalArchivedRepos,
      icon: Archive,
      color: "text-muted",
      bg: "bg-muted/20",
      type: "archived",
    },
    {
      label: "Stale Branches",
      value: totalStaleBranches,
      icon: Clock,
      color: "text-warning",
      bg: "bg-warning/20",
      type: "stale-branches",
    },
  ];

  return (
    <div className="rounded-xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-6 gap-2">
        <div>
          <h2 className="font-semibold text-lg text-text">
            Repository Metadata
          </h2>
          <p className="text-xs text-muted">Overview of repository metrics</p>
        </div>

      </div>

      {/* Horizontal Scroll Container */}
      <div className="relative overflow-hidden">
        <div
          className="
            scrollbar-hide-lg flex flex-nowrap gap-4
            overflow-x-auto overflow-y-hidden
            pb-6 -mb-6
          "
          style={{ scrollbarWidth: "auto" }}
        >
          {stats.map(({ label, value, icon: Icon, color, bg, type }, idx) => (
            <div
              key={idx}
              onClick={() =>
                router.push(`/dashboard/repo-details?type=${type}`)
              }
              className="
                group relative cursor-pointer overflow-hidden
                flex-shrink-0
                rounded-lg p-4 min-w-[150px] sm:min-w-[180px]
                transition-all duration-300
                hover:-translate-y-[3px]
              "
              style={{
                background: "var(--surface)",
                borderRadius: "var(--radius-lg)",
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
              {/* Hover overlay */}
              <div
                className="
                  absolute inset-0 z-20
                  flex items-center justify-center
                  bg-surface/80 backdrop-blur-sm
                  opacity-0 group-hover:opacity-100
                  transition-all duration-300
                  text-sm font-medium text-text
                "
              >
                Explore <ArrowRight className="w-4 h-4 ml-1" />
              </div>

              {/* Card Content */}
              <div className="relative z-10 space-y-3">
                <p className="text-xs text-muted">{label}</p>

                <div className="flex items-center gap-2">
                  <div className={`p-2 rounded-md w-fit ${bg}`}>
                    <Icon className={`h-5 w-5 ${color}`} />
                  </div>

                  <p className={`font-semibold text-xl ${color}`}>
                    {value.toLocaleString()}
                  </p>
                </div>
              </div>

              {/* Radial Glow */}
              <div
                className="
                  absolute -bottom-6 -right-6
                  w-14 h-14 rounded-full
                  opacity-20 blur-xl
                  transition-transform duration-300
                  group-hover:scale-125
                "
              />
            </div>
          ))}

          <div className="flex-shrink-0 w-4" />
        </div>

        {/* Scroll fades */}
        <div className="absolute left-0 top-0 bottom-6 w-8 pointer-events-none bg-gradient-to-r from-surface to-transparent" />
        <div className="absolute right-0 top-0 bottom-6 w-8 pointer-events-none bg-gradient-to-l from-surface to-transparent" />
      </div>
    </div>
  );
}
