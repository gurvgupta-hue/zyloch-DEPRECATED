"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { useRepoData } from "@/hooks/useRepoData";
import { useEffect, useState, useRef, useCallback } from "react";
import Link from "next/link";
import { useInteractiveTable } from "@/app/scanops/components/scan/shared/useInteractiveTable";

// Icons
import {
  Globe,
  Lock,
  GitFork,
  Star,
  GitCommit,
  Code2,
  GitBranch,
  ChevronRight,
  Archive,
  Timer,
  ExternalLink,
} from "lucide-react";

const FILTER_TYPES = [
  { id: "public", label: "Public", icon: Globe },
  { id: "private", label: "Private", icon: Lock },
  { id: "forks", label: "Forks", icon: GitFork },
  { id: "stars", label: "Stars", icon: Star },
  { id: "commits", label: "Commits", icon: GitCommit },
  { id: "archived", label: "Archived", icon: Archive },
  { id: "stale-branches", label: "Stale", icon: Timer },
];

export default function RepoDetailsPage() {
  const { repositoriesArray } = useRepoData();
  const searchParams = useSearchParams();
  const router = useRouter();
  const type = searchParams.get("type") || "public";

  const [filteredRepos, setFilteredRepos] = useState([]);
  const [stats, setStats] = useState({});
  const [filterCounts, setFilterCounts] = useState({});

  const calculateFilterCounts = useCallback(() => {
    if (!repositoriesArray?.length) return {};

    const counts = {};

    FILTER_TYPES.forEach((filter) => {
      let count = 0;

      switch (filter.id) {
        case "public":
          count = repositoriesArray.filter((r) => !r.isPrivate).length;
          break;
        case "private":
          count = repositoriesArray.filter((r) => r.isPrivate).length;
          break;
        case "forks":
          count = repositoriesArray.filter((r) => r.forks > 0).length;
          break;
        case "stars":
          count = repositoriesArray.filter((r) => r.stars > 0).length;
          break;
        case "commits":
          count = repositoriesArray.filter((r) => r.commits > 0).length;
          break;
        case "archived":
          count = repositoriesArray.filter((r) => r.isArchived).length;
          break;
        case "stale-branches":
          count = repositoriesArray.filter((r) => r.hasStaleBranches).length;
          break;
      }

      counts[filter.id] = count;
    });

    return counts;
  }, [repositoriesArray]);

  const filterRepositories = useCallback(() => {
    if (!repositoriesArray?.length) return { repos: [], stats: {} };

    let repos = [...repositoriesArray];

    switch (type) {
      case "public":
        repos = repos.filter((r) => !r.isPrivate);
        break;
      case "private":
        repos = repos.filter((r) => r.isPrivate);
        break;
      case "forks":
        repos = repos.filter((r) => r.forks > 0);
        break;
      case "stars":
        repos = repos.filter((r) => r.stars > 0);
        break;
      case "commits":
        repos = repos.filter((r) => r.commits > 0);
        break;
      case "archived":
        repos = repos.filter((r) => r.isArchived);
        break;
      case "stale-branches":
        repos = repos.filter((r) => r.hasStaleBranches);
        break;
    }

    return {
      repos,
      stats: {
        totalStars: repos.reduce((s, r) => s + (r.stars || 0), 0),
        totalForks: repos.reduce((s, r) => s + (r.forks || 0), 0),
        totalCommits: repos.reduce((s, r) => s + (r.commits || 0), 0),
        totalBranches: repos.reduce((s, r) => s + (r.branches || 0), 0),
      },
    };
  }, [repositoriesArray, type]);

  useEffect(() => {
    const result = filterRepositories();
    setFilteredRepos(result.repos);
    setStats(result.stats);

    const counts = calculateFilterCounts();
    setFilterCounts(counts);
  }, [filterRepositories, calculateFilterCounts]);

  const handleTypeChange = (newType) => {
    router.push(`/dashboard/repo-details?type=${newType}`);
  };

  return (
    <div className="min-h-screen bg p-3 sm:p-6">
      <section className="flex w-full flex-col items-stretch gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-4 py-4 shadow-[var(--shadow-soft)]">
        <div className="flex flex-col items-stretch gap-5 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-4 py-5 sm:px-6 sm:py-6">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2 text-sm text-muted">
              <Link href="/dashboard" className="transition-colors hover:text-primary">
                Dashboard
              </Link>
              <ChevronRight className="h-4 w-4" />
              <span className="font-medium text">Repository Analytics</span>
            </div>

            <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between sm:gap-4">
              <div>
                <h1 className="text-2xl font-semibold tracking-tight text sm:text-3xl">
                  Repository Insights
                </h1>
                <p className="mt-1 max-w-xl text-sm text-muted sm:text-base">
                  Deep dive into stars, forks, commits, and repository activity.
                </p>
              </div>
              <span className="text-sm text-muted">{filteredRepos.length} repositories</span>
            </div>
          </div>

          <nav aria-label="Repository filters" className="-mx-1 flex gap-2 overflow-x-auto border-b border-[var(--border)] px-1 pb-1">
            {FILTER_TYPES.map((ft) => {
              const Icon = ft.icon;
              const active = ft.id === type;
              const count = filterCounts[ft.id] || 0;

              return (
                <button
                  key={ft.id}
                  type="button"
                  onClick={() => handleTypeChange(ft.id)}
                  className={`relative flex shrink-0 items-center gap-2 px-3 py-2 text-sm font-medium transition-colors ${active ? "text-primary" : "text-muted hover:text"}`}
                  aria-current={active ? "page" : undefined}
                >
                  <Icon className="h-4 w-4" />
                  {ft.label}
                  <span className="text-xs text-muted">{count}</span>
                  {active && <span className="absolute -bottom-[5px] left-0 right-0 h-0.5 rounded-full bg-primary" />}
                </button>
              );
            })}
          </nav>

          <div className="grid grid-cols-1 divide-y divide-[var(--border)] border-y border-[var(--border)] sm:grid-cols-2 sm:divide-x sm:divide-y-0 lg:grid-cols-4">
            <StatCard label="Total Stars" value={stats.totalStars} icon={Star} />
            <StatCard label="Total Forks" value={stats.totalForks} icon={GitFork} />
            <StatCard label="Total Commits" value={stats.totalCommits} icon={GitCommit} />
            <StatCard label="Total Branches" value={stats.totalBranches} icon={GitBranch} />
          </div>

          {filteredRepos.length ? <TableView repos={filteredRepos} /> : <NoData handleTypeChange={handleTypeChange} />}
        </div>
      </section>
    </div>
  );
}

/* TABLE VIEW */
function TableView({ repos }) {
  const tableRef = useRef(null);

  useInteractiveTable({
    containerRef: tableRef,
    storageKey: "dashboard-repo-details-table",
    minWidth: 92,
    deps: [repos.length],
  });

  const handleRepoClick = (url) => {
    window.open(url, "_blank", "noopener,noreferrer");
  };

  return (
    <div className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)]">
      <div className="overflow-x-auto" ref={tableRef}>
        <table className="w-full min-w-[820px]">
          <thead className="sticky top-0 z-10 bg-[var(--elevated-surface)]/90 backdrop-blur">
            <tr className="border-b border-[var(--border)]">
              <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-[0.08em] text-muted">
                Repository
              </th>
              <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-[0.08em] text-muted">
                Stars
              </th>
              <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-[0.08em] text-muted">
                Forks
              </th>
              <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-[0.08em] text-muted">
                Commits
              </th>
              <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-[0.08em] text-muted">
                Branches
              </th>
              <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-[0.08em] text-muted">
                Last Active
              </th>
              <th className="px-5 py-3 text-center text-xs font-semibold uppercase tracking-[0.08em] text-muted">
                Action
              </th>
            </tr>
          </thead>

          <tbody>
            {repos.map((repo, i) => (
              <tr
                key={i}
                className="group border-b border-[var(--border)] transition-colors last:border-b-0 hover:bg-[var(--primary)]/5"
              >
                <td className="px-5 py-3">
                  <button
                    onClick={() => handleRepoClick(repo.url)}
                    className="flex min-w-0 items-center gap-3 text-left"
                  >
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                      <GitBranch className="h-4 w-4 text-primary" />
                    </div>
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium text">
                        {repo.name}
                      </div>
                      {repo.description && (
                        <div className="max-w-xs truncate text-xs text-muted">
                          {repo.description}
                        </div>
                      )}
                    </div>
                  </button>
                </td>

                <td className="px-4 py-3 text-right font-mono text-sm text-muted">{repo.stars}</td>
                <td className="px-4 py-3 text-right font-mono text-sm text-muted">{repo.forks}</td>
                <td className="px-4 py-3 text-right font-mono text-sm text">{repo.commits}</td>
                <td className="px-4 py-3 text-right font-mono text-sm text-muted">{repo.branches}</td>

                <td className="px-4 py-3 text-right text-sm text-muted">
                  {repo.lastActive
                    ? new Date(repo.lastActive).toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                      year: "numeric",
                    })
                    : "Never"}
                </td>

                <td className="px-5 py-3 text-center">
                  <button
                    onClick={() => handleRepoClick(repo.url)}
                    aria-label={`Open ${repo.name}`}
                    className="inline-flex rounded-lg p-2 text-muted transition-colors hover:bg-primary/10 hover:text-primary"
                  >
                    <ExternalLink className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* STAT CARD */
function StatCard({ label, value, icon: Icon }) {
  return (
    <div className="flex min-h-[108px] flex-col justify-between px-4 py-4 sm:px-6">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm text-muted">{label}</div>
        <div className="rounded-lg bg-primary/10 p-2 text-primary">
          <Icon className="h-4 w-4" />
        </div>
      </div>
      <div className="text-2xl font-semibold text">
        {value?.toLocaleString() || 0}
      </div>
    </div>
  );
}

/* NO DATA */
function NoData({ handleTypeChange }) {
  return (
    <div className="glass text-center p-12 rounded-2xl">
      <div className="w-20 h-20 mx-auto mb-6 rounded-full bg-primary/10 flex items-center justify-center">
        <Code2 className="w-10 h-10 text-primary" />
      </div>
      <h3 className="text-xl font-semibold">Nothing here yet</h3>
      <p className="text-muted mt-2 max-w-md mx-auto">
        This filter doesn’t match any repositories. Try switching views or
        explore your public repos.
      </p>
      <button
        onClick={() => handleTypeChange("public")}
        className="mt-6 px-6 py-3 rounded-xl bg-primary text-white font-medium
          transition-all hover:scale-[1.02] active:scale-[0.98]"
      >
        View All Repositories
      </button>
    </div>
  );
}
