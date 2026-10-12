"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Archive,
  Check,
  GitFork,
  Loader2,
  Lock,
  RefreshCw,
  Search,
  Sparkles,
  X,
} from "lucide-react";
import { useGithubStore } from "@/store/useGithubStore";

/**
 * The gate an installation with more repositories than its plan covers must pass.
 *
 * "All repositories" on an org with 21,000 repos against a 2,000-repo plan is not
 * something we can resolve by guessing: which 2,000 matter is a decision only the
 * customer can make. So the dashboard is held here until they make it.
 *
 * The list is paged, searched and sorted server-side — 21,000 rows is not
 * something a browser should hold, and GitHub's API can neither search nor sort
 * an installation's repository list. The server reads it live from GitHub and
 * holds it in memory only; nothing but the repositories chosen here is stored.
 *
 * The middle of the three onboarding screens (connect → choose → sync): the same
 * centred column, and a table rather than a card because the decision needs the
 * repository's size and last activity side by side.
 */

const PAGE_SIZES = [25, 50, 100];
const SEED_PAGE_SIZE = 100;

const SORTS = [
  { value: "active", label: "Last active" },
  { value: "name", label: "Name" },
  { value: "size", label: "Size" },
];

const FILTERS = [
  { value: "all", label: "All" },
  { value: "unselected", label: "Not selected" },
  { value: "selected", label: "Previously selected" },
];

const PANEL = { background: "var(--surface)", border: "1px solid var(--border)" };

function relativeTime(value) {
  if (!value) return "—";
  const diff = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(diff)) return "—";
  const days = Math.floor(diff / 86_400_000);
  if (days < 1) return "today";
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.floor(months / 12)}y ago`;
}

function formatSize(kb) {
  const value = Number(kb) || 0;
  if (value < 1024) return `${value} KB`;
  return `${(value / 1024).toFixed(1)} MB`;
}

/** Toolbar control: same frame for the selects and the plain buttons. */
function ToolbarButton({ active = false, className = "", style, ...props }) {
  return (
    <button
      type="button"
      className={`inline-flex items-center gap-2 text-sm px-3 py-2 rounded-[var(--radius-md)] transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
      style={{
        background: active ? "var(--color-primary)" : "var(--surface)",
        border: `1px solid ${active ? "var(--color-primary)" : "var(--border)"}`,
        color: active ? "var(--text-on-primary)" : "var(--text-secondary)",
        ...style,
      }}
      {...props}
    />
  );
}

export default function RepoSelectionGate({ selection, installationId, onDone }) {
  const {
    fetchSelectableRepos,
    commitRepoSelection,
    autoSelectRepoSelection,
    refreshRepoCatalog,
    fetchRepoSelection,
  } = useGithubStore();

  const limit = selection?.limit ?? 0;
  const repoCount = selection?.repoCount ?? 0;
  const catalogStatus = selection?.catalog?.status || "idle";
  const catalogReady = catalogStatus === "ready";

  const [selected, setSelected] = useState(() => new Set());
  const [seeded, setSeeded] = useState(false);
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(PAGE_SIZES[0]);
  const [totalPages, setTotalPages] = useState(1);
  const [query, setQuery] = useState("");
  const [searchFocused, setSearchFocused] = useState(false);
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [sort, setSort] = useState("active");
  const [filter, setFilter] = useState("all");
  const [listLoading, setListLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const overBy = Math.max(repoCount - limit, 0);
  const remaining = limit - selected.size;
  const overLimit = remaining < 0;
  const mounted = useRef(true);

  useEffect(() => () => { mounted.current = false; }, []);

  // --- Search debounce: 21,000 rows is a server query, not a keystroke handler.
  useEffect(() => {
    const id = setTimeout(() => setDebouncedQuery(query.trim()), 300);
    return () => clearTimeout(id);
  }, [query]);

  // --- While the list is still being read, poll the gate state.
  useEffect(() => {
    if (catalogReady || catalogStatus === "failed") return undefined;
    const id = setInterval(() => fetchRepoSelection(installationId), 3000);
    return () => clearInterval(id);
  }, [catalogReady, catalogStatus, fetchRepoSelection, installationId]);

  // --- Seed from a selection that already exists, so an edit starts where the
  //     last one left off rather than from an empty list.
  useEffect(() => {
    if (seeded || !catalogReady) return;
    if (!selection?.selectedCount) {
      setSeeded(true);
      return;
    }

    let cancelled = false;
    (async () => {
      const names = new Set();
      let current = 1;
      let pages = 1;
      try {
        do {
          const data = await fetchSelectableRepos(installationId, {
            filter: "selected",
            perPage: SEED_PAGE_SIZE,
            page: current,
            sort: "name",
          });
          data.repositories.forEach((repo) => names.add(repo.fullName));
          pages = data.totalPages || 1;
          current += 1;
        } while (current <= pages && !cancelled);
      } catch {
        // A failed seed is not fatal: the admin can still build a fresh selection.
      }
      if (!cancelled && mounted.current) {
        setSelected(names);
        setSeeded(true);
      }
    })();

    return () => { cancelled = true; };
  }, [seeded, catalogReady, selection?.selectedCount, fetchSelectableRepos, installationId]);

  // --- The visible page.
  const loadPage = useCallback(async () => {
    if (!catalogReady) return;
    setListLoading(true);
    try {
      const data = await fetchSelectableRepos(installationId, {
        q: debouncedQuery,
        page,
        perPage,
        sort,
        filter,
      });
      if (!mounted.current) return;
      setRows(data.repositories || []);
      setTotal(data.total || 0);
      setTotalPages(data.totalPages || 1);
    } catch (err) {
      if (mounted.current) setError(err.message);
    } finally {
      if (mounted.current) setListLoading(false);
    }
  }, [catalogReady, fetchSelectableRepos, installationId, debouncedQuery, page, perPage, sort, filter]);

  useEffect(() => { loadPage(); }, [loadPage]);
  useEffect(() => { setPage(1); }, [debouncedQuery, sort, filter, perPage]);

  const toggle = (fullName) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(fullName)) next.delete(fullName);
      else next.add(fullName);
      return next;
    });
  };

  const selectPage = () => {
    setSelected((prev) => {
      const next = new Set(prev);
      rows.forEach((repo) => next.add(repo.fullName));
      return next;
    });
  };

  const clearPage = () => {
    setSelected((prev) => {
      const next = new Set(prev);
      rows.forEach((repo) => next.delete(repo.fullName));
      return next;
    });
  };

  const handleSave = async () => {
    setBusy(true);
    setError(null);
    try {
      await commitRepoSelection(installationId, [...selected]);
      onDone?.();
    } catch (err) {
      setError(err.message);
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  const handleAuto = async () => {
    setBusy(true);
    setError(null);
    try {
      await autoSelectRepoSelection(installationId);
      onDone?.();
    } catch (err) {
      setError(err.message);
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  const handleRefreshList = async () => {
    setBusy(true);
    setError(null);
    try {
      await refreshRepoCatalog(installationId);
      setSeeded(false);
    } catch (err) {
      setError(err.message);
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  const pageSelected = rows.length > 0 && rows.every((repo) => selected.has(repo.fullName));
  const counterColor = overLimit ? "var(--danger)" : remaining === 0 ? "var(--success)" : "var(--text)";
  const canSave = !busy && !overLimit && selected.size > 0 && catalogReady;

  const read = selection?.catalog?.syncedCount || 0;
  const readTotal = selection?.catalog?.totalCount || 0;
  const readPct = readTotal ? Math.min(Math.round((read / readTotal) * 100), 100) : 0;

  return (
    <div className="w-full min-h-screen px-[var(--space-4)] py-[var(--space-6)] md:px-[var(--space-8)]">
      <div className="mx-auto w-full max-w-5xl">
        {/* Why you are here */}
        <div
          className="rounded-[var(--radius-lg)] p-5 flex items-start gap-3"
          style={{
            background: "rgba(var(--color-accent-rgb), 0.08)",
            border: "1px solid rgba(var(--color-accent-rgb), 0.35)",
          }}
        >
          <AlertTriangle className="w-5 h-5 mt-0.5 shrink-0" style={{ color: "var(--warning)" }} />
          <div>
            <h1 className="text-lg md:text-xl font-semibold" style={{ color: "var(--text)" }}>
              Choose the repositories to monitor
            </h1>
            <p className="text-sm mt-1 leading-relaxed" style={{ color: "var(--text-secondary)" }}>
              <span className="font-medium">{selection?.accountLogin}</span> gives Zyloch access to{" "}
              <span className="font-medium">{repoCount.toLocaleString()}</span> repositories, and your{" "}
              <span className="font-medium">{selection?.planId || "current"}</span> plan covers{" "}
              <span className="font-medium">{limit.toLocaleString()}</span>
              {overBy > 0 && <> — {overBy.toLocaleString()} over.</>} Pick the ones that matter and we
              will start populating your dashboard. You can change this later in settings, or upgrade
              your plan to raise the limit.
            </p>
          </div>
        </div>

        {/* Reading the list from GitHub */}
        {!catalogReady && catalogStatus !== "failed" && (
          <div
            className="mt-6 rounded-[var(--radius-xl)] px-8 py-10 text-center animate-fade-up"
            style={{ ...PANEL, boxShadow: "var(--shadow-1)" }}
          >
            <div className="flex justify-center">
              <Loader2 className="w-8 h-8 animate-spin" style={{ color: "var(--color-primary)" }} />
            </div>
            <p className="text-base font-semibold mt-5" style={{ color: "var(--text)" }}>
              Discovering repositories
            </p>
            <p className="text-sm mt-1" style={{ color: "var(--muted)" }}>
              Listing the repositories in this installation…
            </p>

            <div className="mx-auto mt-6 w-full max-w-md">
              <div
                className="h-1.5 w-full rounded-full overflow-hidden"
                style={{ background: "var(--elevated-surface)" }}
              >
                {readTotal ? (
                  <div
                    className="h-full rounded-full transition-[width] duration-700 ease-out"
                    style={{ width: `${Math.max(readPct, 2)}%`, background: "var(--color-primary)" }}
                  />
                ) : (
                  <div
                    className="h-full w-2/5 rounded-full animate-bar-sweep"
                    style={{
                      background:
                        "linear-gradient(90deg, transparent, var(--color-primary), transparent)",
                    }}
                  />
                )}
              </div>
              {readTotal > 0 && (
                <div className="flex items-center justify-between mt-2 text-xs" style={{ color: "var(--muted)" }}>
                  <span>{read.toLocaleString()}</span>
                  <span>{readTotal.toLocaleString()}</span>
                </div>
              )}
            </div>

            <p className="text-xs mt-4" style={{ color: "var(--muted)" }}>
              A few minutes for a very large organisation.
            </p>
          </div>
        )}

        {catalogStatus === "failed" && (
          <div
            className="mt-6 rounded-[var(--radius-lg)] p-5"
            style={{
              background: "rgba(var(--danger-rgb), 0.08)",
              border: "1px solid rgba(var(--danger-rgb), 0.35)",
            }}
          >
            <p className="text-sm" style={{ color: "var(--text)" }}>
              We could not read the repository list: {selection?.catalog?.error || "unknown error"}
            </p>
            <button
              onClick={handleRefreshList}
              className="mt-3 inline-flex items-center gap-2 text-sm px-3 py-1.5 rounded-[var(--radius-md)]"
              style={{ background: "var(--color-primary)", color: "var(--text-on-primary)" }}
            >
              <RefreshCw className="w-4 h-4" /> Try again
            </button>
          </div>
        )}

        {catalogReady && (
          <>
            {/* Toolbar */}
            <div className="mt-6 flex flex-col gap-3">
              <div className="flex flex-col md:flex-row md:items-center gap-3">
                <div
                  className="flex items-center gap-2 flex-1 rounded-[var(--radius-md)] px-3 py-2 transition-shadow"
                  style={{
                    background: "var(--surface)",
                    border: `1px solid ${searchFocused ? "var(--color-primary)" : "var(--border)"}`,
                    boxShadow: searchFocused ? "0 0 0 3px rgba(var(--color-primary-rgb), 0.15)" : "none",
                  }}
                >
                  <Search className="w-4 h-4 shrink-0" style={{ color: "var(--muted)" }} />
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onFocus={() => setSearchFocused(true)}
                    onBlur={() => setSearchFocused(false)}
                    placeholder="Search repositories…"
                    aria-label="Search repositories"
                    className="w-full bg-transparent outline-none text-sm"
                    style={{ color: "var(--text)" }}
                  />
                  {query && (
                    <button onClick={() => setQuery("")} aria-label="Clear search">
                      <X className="w-4 h-4" style={{ color: "var(--muted)" }} />
                    </button>
                  )}
                </div>

                <select
                  value={sort}
                  onChange={(e) => setSort(e.target.value)}
                  aria-label="Sort repositories"
                  className="text-sm rounded-[var(--radius-md)] px-3 py-2"
                  style={{ ...PANEL, color: "var(--text)" }}
                >
                  {SORTS.map((option) => (
                    <option key={option.value} value={option.value}>
                      Sort: {option.label}
                    </option>
                  ))}
                </select>

                <select
                  value={perPage}
                  onChange={(e) => setPerPage(Number(e.target.value))}
                  aria-label="Rows per page"
                  className="text-sm rounded-[var(--radius-md)] px-3 py-2"
                  style={{ ...PANEL, color: "var(--text)" }}
                >
                  {PAGE_SIZES.map((size) => (
                    <option key={size} value={size}>
                      Rows: {size}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex rounded-[var(--radius-md)] overflow-hidden" style={{ border: "1px solid var(--border)" }}>
                  {FILTERS.map((option) => (
                    <button
                      key={option.value}
                      onClick={() => setFilter(option.value)}
                      className="text-sm px-3 py-2 transition-colors"
                      style={{
                        background: filter === option.value ? "var(--color-primary)" : "var(--surface)",
                        color: filter === option.value ? "var(--text-on-primary)" : "var(--text-secondary)",
                      }}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <ToolbarButton onClick={handleAuto} disabled={busy}>
                    <Sparkles className="w-4 h-4" style={{ color: "var(--color-primary)" }} />
                    Auto-select most active {limit.toLocaleString()}
                  </ToolbarButton>
                  <ToolbarButton onClick={selectPage} active={pageSelected} disabled={rows.length === 0}>
                    Select page
                  </ToolbarButton>
                  <ToolbarButton onClick={clearPage} disabled={rows.length === 0}>
                    Clear page
                  </ToolbarButton>
                  <ToolbarButton
                    onClick={handleRefreshList}
                    disabled={busy}
                    title="Re-read the repository list from GitHub"
                    aria-label="Refresh the repository list"
                    className="px-2.5"
                  >
                    <RefreshCw className="w-4 h-4" />
                  </ToolbarButton>
                </div>
              </div>
            </div>

            {/* Table */}
            <div className="mt-4 rounded-[var(--radius-lg)] overflow-hidden" style={PANEL}>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm">
                  <thead>
                    <tr style={{ background: "var(--elevated-surface)" }}>
                      <th className="w-12 px-4 py-3" scope="col">
                        <span className="sr-only">Selected</span>
                      </th>
                      {["Repository", "Visibility", "Size", "Last updated"].map((label, index) => (
                        <th
                          key={label}
                          scope="col"
                          className={`px-4 py-3 text-[11px] uppercase tracking-wide font-medium ${
                            index === 0 ? "text-left" : "text-right md:text-left"
                          }`}
                          style={{ color: "var(--muted)" }}
                        >
                          {label}
                        </th>
                      ))}
                    </tr>
                  </thead>

                  <tbody>
                    {listLoading && (
                      <tr>
                        <td colSpan={5} className="px-4 py-6">
                          <span className="flex items-center gap-2 text-sm" style={{ color: "var(--muted)" }}>
                            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
                          </span>
                        </td>
                      </tr>
                    )}

                    {!listLoading && rows.length === 0 && (
                      <tr>
                        <td colSpan={5} className="px-4 py-10 text-center text-sm" style={{ color: "var(--muted)" }}>
                          No repositories match this filter.
                        </td>
                      </tr>
                    )}

                    {!listLoading &&
                      rows.map((repo) => {
                        const isSelected = selected.has(repo.fullName);
                        return (
                          <tr
                            key={repo.fullName}
                            onClick={() => toggle(repo.fullName)}
                            className="cursor-pointer transition-colors h-[52px]"
                            style={{
                              background: isSelected
                                ? "rgba(var(--color-primary-rgb), 0.07)"
                                : "transparent",
                              borderTop: "1px solid var(--border-light)",
                            }}
                          >
                            <td className="px-4">
                              <span
                                className="flex w-4 h-4 rounded-[var(--radius-xs)] items-center justify-center"
                                style={{
                                  background: isSelected ? "var(--color-primary)" : "var(--surface)",
                                  border: `1px solid ${isSelected ? "var(--color-primary)" : "var(--border-hover)"}`,
                                }}
                              >
                                {isSelected && <Check className="w-3 h-3" style={{ color: "var(--text-on-primary)" }} />}
                              </span>
                              <input
                                type="checkbox"
                                className="sr-only"
                                checked={isSelected}
                                onChange={() => toggle(repo.fullName)}
                                onClick={(e) => e.stopPropagation()}
                                aria-label={`Monitor ${repo.fullName}`}
                              />
                            </td>

                            <td className="px-4 max-w-[320px]">
                              <span
                                className="block truncate font-medium"
                                style={{ color: isSelected ? "var(--color-primary-600)" : "var(--text)" }}
                                title={repo.fullName}
                              >
                                {repo.name || repo.fullName}
                              </span>
                              <span className="block truncate text-xs" style={{ color: "var(--muted)" }}>
                                {repo.owner}
                              </span>
                            </td>

                            <td className="px-4">
                              <span className="flex flex-wrap items-center gap-1.5 text-xs" style={{ color: "var(--muted)" }}>
                                {repo.isPrivate ? (
                                  <span className="inline-flex items-center gap-1">
                                    <Lock className="w-3 h-3" /> Private
                                  </span>
                                ) : (
                                  <span>Public</span>
                                )}
                                {repo.isFork && (
                                  <span className="inline-flex items-center gap-1">
                                    · <GitFork className="w-3 h-3" /> Fork
                                  </span>
                                )}
                                {repo.isArchived && (
                                  <span className="inline-flex items-center gap-1">
                                    · <Archive className="w-3 h-3" /> Archived
                                  </span>
                                )}
                              </span>
                            </td>

                            <td className="px-4 whitespace-nowrap" style={{ color: "var(--text-secondary)" }}>
                              {formatSize(repo.sizeKb)}
                            </td>

                            <td className="px-4 whitespace-nowrap" style={{ color: "var(--text-secondary)" }}>
                              {relativeTime(repo.updatedAt)}
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>

              {/* Paging */}
              <div
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm"
                style={{ borderTop: "1px solid var(--border)", color: "var(--muted)" }}
              >
                <span>
                  {total.toLocaleString()} repositories{debouncedQuery ? ` matching “${debouncedQuery}”` : ""}
                </span>
                <span className="flex items-center gap-2">
                  <ToolbarButton
                    onClick={() => setPage((p) => Math.max(p - 1, 1))}
                    disabled={page <= 1}
                    className="py-1.5"
                  >
                    Previous
                  </ToolbarButton>
                  <span>
                    Page {page} of {totalPages}
                  </span>
                  <ToolbarButton
                    onClick={() => setPage((p) => Math.min(p + 1, totalPages))}
                    disabled={page >= totalPages}
                    className="py-1.5"
                  >
                    Next
                  </ToolbarButton>
                </span>
              </div>
            </div>
          </>
        )}

        {error && (
          <p className="mt-4 text-sm" style={{ color: "var(--danger)" }}>
            {error}
          </p>
        )}

        {/* Commit bar: the count and the way out stay in view while paging.
            Sticky inside the column rather than fixed to the viewport, so it
            never sits over the sidebar. */}
        <div
          className="sticky bottom-0 mt-4 -mx-[var(--space-4)] px-[var(--space-4)] py-3 md:-mx-[var(--space-8)] md:px-[var(--space-8)] flex flex-wrap items-center justify-between gap-3"
          style={{ background: "var(--surface)", borderTop: "1px solid var(--border)" }}
        >
          <p className="text-sm" style={{ color: counterColor }}>
            <span className="font-semibold">{selected.size.toLocaleString()}</span> of{" "}
            <span className="font-semibold">{limit.toLocaleString()}</span> repositories selected
            {overLimit && <> — remove {Math.abs(remaining).toLocaleString()} to continue</>}
          </p>

          <button
            onClick={handleSave}
            disabled={!canSave}
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-[var(--radius-md)] text-sm font-medium transition-colors"
            style={{
              background: canSave ? "var(--color-primary)" : "var(--elevated-surface)",
              border: `1px solid ${canSave ? "var(--color-primary)" : "var(--border)"}`,
              color: canSave ? "var(--text-on-primary)" : "var(--text-disabled)",
              cursor: canSave ? "pointer" : "not-allowed",
            }}
            onMouseEnter={(e) => {
              if (canSave) e.currentTarget.style.background = "var(--color-primary-600)";
            }}
            onMouseLeave={(e) => {
              if (canSave) e.currentTarget.style.background = "var(--color-primary)";
            }}
          >
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
            Save and start sync
          </button>
        </div>
      </div>
    </div>
  );
}
