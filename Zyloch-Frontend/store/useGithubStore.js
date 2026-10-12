"use client";

import { create } from "zustand";
import {
  getInstallations,
  checkInstallationLinked,
  getRepositories,
  getRepositoriesFromDB,
  getBranches,
  startInstallationSummary,
  refreshInstallationData,
  pollInstallationSummary,
  getBranchesFromDB,
  retryFailedJob,
  getRepoSelection,
  listSelectableRepos,
  saveRepoSelection,
  autoSelectRepos,
  syncRepoCatalog,
} from "@/lib/api/github";

// status: idle | checking | pending | in_progress | completed | failed | blocked
// "checking" means the server has not yet said whether a job is running.
const EMPTY_SUMMARY_ANALYSIS = {
  installationId: null,
  jobId: null,
  status: "idle",
  progress: 0,
  data: null,
  error: null,
  // Volume + timing, so the sync screen can say "1,240 of 21,430 repositories,
  // about 6 hours left" instead of spinning silently for a working day.
  startedAt: null,
  repoTarget: 0,
  repoProcessed: 0,
};

const inFlightSummaryStarts = new Map();

const RUNNING_STATUSES = ["pending", "in_progress"];
const isRunning = (status) => RUNNING_STATUSES.includes(status);

// Bumped by every pollSummaryAnalysis call. Only the newest loop may write:
// two loops on one job used to interleave, and a slow response from the older
// one landed after a newer one and pulled the bar backwards.
let summaryPollRun = 0;

// Bumped by every waitForInstallation call (and by cancelWaitForInstallation),
// so a check loop from an earlier mount stops touching the store.
let connectRun = 0;

export const useGithubStore = create((set, get) => ({

  // ------------------------------------------------------------------
  // Global State
  // ------------------------------------------------------------------
  installations: [],
  repositories: [],
  branches: [],

  selectedInstallation: null,
  selectedRepo: null,
  selectedBranch: null,

  // Post-install hand-off. `connectingInstallation` ({ installationId, timedOut })
  // is set while the dashboard waits for the installation GitHub redirected back
  // with; `connectedInstallationId` is set once it arrives, until the navbar has
  // shown the "select your account" tour for it.
  connectingInstallation: null,
  connectedInstallationId: null,

  // User role information
  userRole: null, // 'admin' or 'member'

  loading: {
    installations: false,
    repos: false,
    branches: false,
  },

  error: null,

  // ------------------------------------------------------------------
  // Error Handling
  // ------------------------------------------------------------------
  setError: (error) => set({ error }),
  clearError: () => set({ error: null }),

  // ------------------------------------------------------------------
  // Installation Selection (Null-safe + Cascading Fetch)
  // ------------------------------------------------------------------
  setSelectedInstallation: (installation) => {
    const prevInstall = get().selectedInstallation;

    // Null safety: Clear all state if user resets installation
    if (!installation) {
      set({
        selectedInstallation: null,
        selectedRepo: null,
        selectedBranch: null,
        repositories: [],
        branches: [],
      });
      return;
    }

    set({
      selectedInstallation: installation,
      selectedRepo: null,
      selectedBranch: null,
      repositories: [],
      branches: [],
    });

    // Only fetch if installation actually changed
    if (!prevInstall || prevInstall.installationId !== installation.installationId) {
      get().fetchRepositories(installation.installationId);
    }
  },

  // ------------------------------------------------------------------
  // Repository Selection (Null-safe + Cascading Fetch)
  // ------------------------------------------------------------------
  setSelectedRepo: (repo) => {
    const prevRepo = get().selectedRepo;

    // Null safety: Clear branch state when resetting repo
    if (!repo) {
      set({
        selectedRepo: null,
        selectedBranch: null,
        branches: [],
      });
      return;
    }

    set({
      selectedRepo: repo,
      selectedBranch: null,
      branches: [],
    });

    // Don't fetch branches if repo is archived
    if (!prevRepo || prevRepo.id !== repo.id) {
      if (!repo.archived) {
        const [owner, name] = repo.full_name.split("/");
        get().fetchBranches(owner, name);
      }
    }
  },

  // ------------------------------------------------------------------
  // Branch Selection (Null-safe)
  // ------------------------------------------------------------------
  setSelectedBranch: (branch) => {
    // If null, clear selection
    if (!branch) {
      set({ selectedBranch: null });
      return;
    }
    set({ selectedBranch: branch });
  },

  // ------------------------------------------------------------------
  // Fetch Installations
  // ------------------------------------------------------------------
  fetchInstallations: async () => {
    set((s) => ({
      error: null,
      loading: { ...s.loading, installations: true },
    }));

    try {
      const data = await getInstallations();
      // Handle new response format: { installations: [...], userRole: 'admin' | 'member' }
      if (data && typeof data === 'object' && data.installations) {
        set({ 
          installations: data.installations,
          userRole: data.userRole 
        });
      } else {
        // Fallback for legacy format (array directly)
        set({ installations: data || [] });
      }
    } catch (err) {
      set({ error: err.message });
    } finally {
      set((s) => ({
        loading: { ...s.loading, installations: false },
      }));
    }
  },

  // ------------------------------------------------------------------
  // Post-install hand-off
  // ------------------------------------------------------------------
  /**
   * Wait for the installation GitHub just redirected back with to be recorded.
   *
   * GitHub returns the browser to `?installation_id=…&setup_action=install` as
   * soon as the install is confirmed, but the installation only exists for us
   * once the `installation.created` webhook has been processed, which can take a
   * while. Until then there is nothing to select. This drives the "Connecting…"
   * screen: a small status check every few seconds, while that screen is open,
   * stopping at a deadline rather than spinning forever.
   *
   * Resolves true once the installation is linked (the list is reloaded and
   * `connectedInstallationId` set), false on timeout or cancellation.
   */
  waitForInstallation: async (
    installationId,
    { intervalMs = 5000, timeoutMs = 5 * 60 * 1000 } = {}
  ) => {
    const id = String(installationId || "");
    if (!id) return false;

    const run = ++connectRun;
    const deadline = Date.now() + timeoutMs;
    set({ connectingInstallation: { installationId: id, timedOut: false } });

    while (connectRun === run) {
      let linked = false;
      try {
        linked = await checkInstallationLinked(id);
      } catch {
        // A failed check is treated as "not yet"; the next one may succeed.
      }
      if (connectRun !== run) return false;

      if (linked) {
        await get().fetchInstallations();
        if (connectRun !== run) return false;
        set({ connectingInstallation: null, connectedInstallationId: id });
        return true;
      }

      if (Date.now() + intervalMs > deadline) {
        set({ connectingInstallation: { installationId: id, timedOut: true } });
        return false;
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    return false;
  },

  cancelWaitForInstallation: () => {
    connectRun += 1;
    set({ connectingInstallation: null });
  },

  // The navbar has pointed the user at the new installation.
  acknowledgeConnectedInstallation: () => set({ connectedInstallationId: null }),

  // ------------------------------------------------------------------
  // Fetch Repositories (Safe, Controlled)
  // ------------------------------------------------------------------
  fetchRepositories: async (installationId) => {
    if (!installationId || get().loading.repos) return;

    set((s) => ({
      error: null,
      loading: { ...s.loading, repos: true },
      repositories: [],
      branches: [],
      selectedRepo: null,
      selectedBranch: null,
    }));

    try {
      // Try to fetch from MongoDB first
      try {
        const dbData = await getRepositoriesFromDB(installationId);

        // If we have data from MongoDB, transform it to match the expected format
        if (dbData && dbData.repositories && dbData.repositories.length > 0) {
          const formattedRepos = dbData.repositories.map(repo => ({
            id: repo._id,
            full_name: `${repo.owner}/${repo.repositoryName}`,
            private: repo.isPrivate,
            archived: repo.isArchived || false,
            owner: repo.owner,
            name: repo.repositoryName,
            url: repo.repositoryUrl,
            stars: repo.stars,
            forks: repo.forks,
            branches: repo.branches || [],
            totalCommits: repo.totalCommits,
            lastActive: repo.lastActive
          }));

          set({
            repositories: formattedRepos,
            branches: [],
            selectedRepo: null,
            selectedBranch: null,
          });
          return;
        }
      } catch (dbErr) {
        console.warn('Failed to fetch from MongoDB, falling back to GitHub API:', dbErr.message);
      }

      // Fallback to GitHub API if MongoDB data not available
      const data = await getRepositories(installationId);
      set({
        repositories: data,
        branches: [],
        selectedRepo: null,
        selectedBranch: null,
      });
    } catch (err) {
      set({ error: err.message });
    } finally {
      set((s) => ({
        loading: { ...s.loading, repos: false },
      }));
    }
  },

  // ------------------------------------------------------------------
  // Fetch Branches (Safe, Controlled)
  // ------------------------------------------------------------------
  fetchBranches: async (owner, repo) => {
    const installationId = get().selectedInstallation?.installationId;
    if (!installationId || !repo || get().loading.branches) return;

    set((s) => ({
      error: null,
      loading: { ...s.loading, branches: true },
      selectedBranch: null,
    }));

    try {

      // Try to fetch from MongoDB first using the dedicated branches endpoint
      try {
        const dbData = await getBranchesFromDB(
          installationId,
          repo
        );

        // If we have branches data from MongoDB
        if (dbData && dbData.branches && dbData.branches.length > 0) {
          const formattedBranches = dbData.branches.map(branch => ({
            name: branch.name,
            protected: false, // MongoDB doesn't store this, can be enhanced
            isDefault: branch.isDefault,
            lastCommit: branch.target?.committedDate,
            oid: branch.target?.oid
          }));

          set({ branches: formattedBranches, selectedBranch: null });
          return;
        }
      } catch (dbErr) {
        console.warn('Failed to fetch branches from MongoDB, falling back to GitHub API:', dbErr.message);
      }

      // Fallback to GitHub API
      const data = await getBranches(
        installationId,
        owner,
        repo
      );
      set({ branches: data, selectedBranch: null });
    } catch (err) {
      set({ error: err.message });
    } finally {
      set((s) => ({
        loading: { ...s.loading, branches: false },
      }));
    }
  },

  // ------------------------------------------------------------------
  // Summary Analysis (Polling)
  // ------------------------------------------------------------------
  summaryAnalysis: { ...EMPTY_SUMMARY_ANALYSIS },

  startSummaryAnalysis: async (installationId) => {
    if (!installationId) return;

    // The dashboard and the navbar both ask for the summary when an installation
    // is picked, and React re-runs effects on remount. Share one request per
    // installation instead of racing several against each other.
    if (inFlightSummaryStarts.has(installationId)) {
      return inFlightSummaryStarts.get(installationId);
    }

    const request = (async () => {
      const current = get().summaryAnalysis;
      const sameInstallation = current.installationId === installationId;
      const hasSummary =
        sameInstallation && current.status === "completed" && Boolean(current.data);
      // Coming back to a dashboard whose sync is still running keeps the bar
      // where it was, rather than dropping to a spinner and restarting from 0.
      const showingRun = sameInstallation && Boolean(current.jobId) && isRunning(current.status);

      // Until the server says a job is actually running this is only a check, not
      // a sync: "checking" renders a plain spinner. Setting "pending" here is what
      // flashed the full sync screen on every reload. A summary already on screen
      // for this installation stays up while it is revalidated in the background.
      if (!hasSummary && !showingRun) {
        set({
          summaryAnalysis: {
            ...EMPTY_SUMMARY_ANALYSIS,
            installationId,
            status: "checking",
            repoTarget: get().selectedInstallation?.selection?.selectedCount ||
              get().selectedInstallation?.repoCount ||
              0,
          },
        });
      }

      try {
        const response = await startInstallationSummary(installationId);

        // The user switched installations while this was in flight.
        if (get().selectedInstallation?.installationId !== installationId) return;

        // A finished summary comes back with the response — show it straight away
        // rather than bouncing through a poll.
        if (response?.status === "from_cache" && response.summary) {
          set({
            summaryAnalysis: {
              ...EMPTY_SUMMARY_ANALYSIS,
              installationId,
              jobId: response.jobId,
              status: "completed",
              progress: 100,
              data: response.summary,
            },
          });
          return;
        }

        const jobId = response?.jobId || null;
        const resumingShownRun =
          showingRun && String(get().summaryAnalysis.jobId) === String(jobId);

        // The server joins an existing run rather than starting a second one; a
        // run already on screen keeps its progress and only polling resumes.
        if (!resumingShownRun) {
          set((state) => ({
            summaryAnalysis: {
              ...EMPTY_SUMMARY_ANALYSIS,
              installationId,
              jobId,
              status: "pending",
              startedAt: new Date().toISOString(),
              repoTarget: state.summaryAnalysis.repoTarget,
            },
          }));
        }

        get().pollSummaryAnalysis(jobId);
      } catch (err) {
        if (get().selectedInstallation?.installationId !== installationId) return;

        // An installation with more repositories than the plan covers is not a
        // failed analysis — it is waiting on a decision. Park it in the gate state
        // so the dashboard shows the chooser.
        if (err.code === "REPO_SELECTION_REQUIRED") {
          set({
            summaryAnalysis: { ...get().summaryAnalysis, installationId, status: "blocked", error: null },
            repoSelection: {
              status: "required",
              state: err.selection || null,
              error: null,
            },
          });
          get().fetchRepoSelection(installationId);
          return;
        }

        set({
          summaryAnalysis: {
            ...get().summaryAnalysis,
            installationId,
            status: "failed",
            error: err.message,
          },
          error: err.message,
        });
      }
    })();

    inFlightSummaryStarts.set(installationId, request);
    try {
      return await request;
    } finally {
      inFlightSummaryStarts.delete(installationId);
    }
  },

  // ------------------------------------------------------------------
  // Poll Summary Analysis
  // ------------------------------------------------------------------
  pollSummaryAnalysis: async (jobId) => {
    if (!jobId) return;

    // A first sync of a large org legitimately runs for hours, so this loop must
    // not give up: the old version polled every 2s and declared failure after 300
    // attempts, which turned every sync longer than ten minutes into a fake
    // error. It keeps polling instead, backing the interval off as the job ages
    // so a 12-hour sync costs a request a minute rather than 21,600 of them.
    // Capped at 15s: at a minute between reads the bar sat still long enough to
    // look stuck, then jumped. The status read is a couple of indexed lookups.
    const pollIntervalFor = (elapsedMs) => {
      if (elapsedMs < 60_000) return 2000;
      if (elapsedMs < 10 * 60_000) return 5000;
      return 15_000;
    };
    const startedAtMs = Date.now();
    const MAX_CONSECUTIVE_POLL_ERRORS = 3;
    let consecutiveErrors = 0;

    // A newer poll loop (e.g. from switching installations) may have
    // started since this one was kicked off; if the jobId in state no
    // longer matches ours, this loop is stale and should stop updating.
    const run = ++summaryPollRun;
    const isStale = () => run !== summaryPollRun || get().summaryAnalysis.jobId !== jobId;

    const poll = async () => {
      if (isStale()) return;

      try {
        const data = await pollInstallationSummary(jobId);

        if (isStale()) return;
        consecutiveErrors = 0;

        const previous = get().summaryAnalysis;
        const reported = Number(data.progress) || 0;
        // Within one run the bar only moves forward. A new run is started from
        // 0 explicitly (refresh, retry, fresh start) before polling begins.
        const progress =
          isRunning(previous.status) && isRunning(data.status)
            ? Math.max(previous.progress || 0, reported)
            : reported;
        set({
          summaryAnalysis: {
            installationId: previous.installationId,
            jobId,
            status: data.status,
            progress,
            data: data.summary || null,
            error: data.error || null,
            startedAt: data.startedAt || previous.startedAt || null,
            repoTarget: data.repositories?.target || previous.repoTarget || 0,
            repoProcessed: data.repositories?.processed || 0,
          },
        });

        if (data.status === "pending" || data.status === "in_progress") {
          setTimeout(poll, pollIntervalFor(Date.now() - startedAtMs));
        } else if (
          data.status === "completed" &&
          isRunning(previous.status) &&
          previous.installationId &&
          !get().selectedRepo
        ) {
          // The first sync has now stored the monitored repositories; swap the
          // provisional list loaded before it for the stored one. Skipped once
          // a repository is picked, since reloading clears that pick.
          get().fetchRepositories(previous.installationId);
        }
      } catch (err) {
        if (isStale()) return;

        // One dropped status request is not a failed sync. Keep polling through
        // brief network blips and only surface the error when it persists.
        consecutiveErrors += 1;
        if (consecutiveErrors < MAX_CONSECUTIVE_POLL_ERRORS) {
          setTimeout(poll, pollIntervalFor(Date.now() - startedAtMs));
          return;
        }

        set({
          summaryAnalysis: {
            ...get().summaryAnalysis,
            status: "failed",
            error: err.message,
          },
          error: err.message,
        });
      }
    };

    poll();
  },

  // ------------------------------------------------------------------
  // Refresh Summary (Manual) - Uses Incremental Update
  // ------------------------------------------------------------------
  refreshSummary: async (forceRefresh = false) => {
    const installationId = get().selectedInstallation?.installationId;
    if (!installationId) {
      console.error('No installation selected for refresh');
      return;
    }

    set((state) => ({
      loading: { ...state.loading, summary: true },
      error: null,
    }));

    try {
      const refreshType = forceRefresh ? 'FORCE' : 'incremental';
      const response = await refreshInstallationData(installationId, forceRefresh);
      
      if (response?.jobId) {
        const isIncremental = response.isIncremental ?? true;

        // Joining a sync that is already running keeps its progress; only a run
        // this request started begins at 0.
        // (A finished summary on screen is at 100 — that is not this run's value.)
        set((state) => {
          const keep = response.alreadyRunning && isRunning(state.summaryAnalysis.status);
          return {
            summaryAnalysis: {
              ...state.summaryAnalysis,
              installationId,
              jobId: response.jobId,
              status: keep ? state.summaryAnalysis.status : "pending",
              progress: keep ? state.summaryAnalysis.progress || 0 : 0,
              error: null,
              isIncremental,
            },
            // The job status drives the screen from here on.
            loading: { ...state.loading, summary: false },
          };
        });

        // Start polling for the job status
        get().pollSummaryAnalysis(response.jobId);
      } else {
        set((state) => ({ loading: { ...state.loading, summary: false } }));
      }
    } catch (err) {
      if (err.code === "REPO_SELECTION_REQUIRED") {
        set((state) => ({
          summaryAnalysis: { ...state.summaryAnalysis, status: "blocked", error: null },
          repoSelection: { status: "required", state: err.selection || null, error: null },
          loading: { ...state.loading, summary: false },
        }));
        get().fetchRepoSelection(installationId);
        return;
      }

      console.error('? Failed to trigger incremental refresh:', err.message);
      set((state) => ({
        error: err.message,
        loading: { ...state.loading, summary: false },
      }));
    }
  },

  // --- Retry Failed Job ---
  retryFailedSummary: async () => {
    const { summaryAnalysis } = get();
    
    if (!summaryAnalysis?.jobId) {
      console.error('No job ID found to retry');
      return;
    }

    // A failed run is stored at 100%; the retried run starts again from 0.
    set((state) => ({
      summaryAnalysis: { ...state.summaryAnalysis, status: "pending", progress: 0, error: null },
      loading: { ...state.loading, summary: true }
    }));

    try {
      const response = await retryFailedJob(summaryAnalysis.jobId);
      
      if (response.success) {
        set((state) => ({ 
          summaryAnalysis: { 
            ...state.summaryAnalysis, 
            status: "in_progress",
            error: null 
          } 
        }));
        // Start polling for the retried job
        get().pollSummaryAnalysis(summaryAnalysis.jobId);
      } else {
        // The job is already completed or running. Status was optimistically set
        // to "pending" above, so read the real state back instead of leaving the
        // sync screen up with nothing polling behind it.
        get().pollSummaryAnalysis(summaryAnalysis.jobId);
      }
    } catch (err) {
      console.error('? Failed to retry job:', err.message);
      set((state) => ({
        summaryAnalysis: { 
          ...state.summaryAnalysis, 
          status: "failed", 
          error: err.message 
        },
        error: err.message,
      }));
    } finally {
      set((state) => ({ loading: { ...state.loading, summary: false } }));
    }
  },

  // --- Reset Summary ---
  resetSummaryAnalysis: () => {
    set({ summaryAnalysis: { ...EMPTY_SUMMARY_ANALYSIS } });
  },


  // ------------------------------------------------------------------
  // Repository selection gate
  //
  // An installation holding more repositories than the plan covers is held here
  // until an admin says which ones to monitor. The answer lives on the server,
  // so this state is re-derived on every load rather than remembered locally —
  // navigating away or signing out does not get past the gate.
  // ------------------------------------------------------------------
  repoSelection: {
    status: "idle", // idle | loading | required | ok | saving
    state: null,
    error: null,
  },

  fetchRepoSelection: async (installationId) => {
    const id = installationId || get().selectedInstallation?.installationId;
    if (!id) return null;

    set((state) => ({ repoSelection: { ...state.repoSelection, status: "loading", error: null } }));

    try {
      const state = await getRepoSelection(id);
      set({
        repoSelection: {
          status: state.selectionRequired ? "required" : "ok",
          state,
          error: null,
        },
      });
      return state;
    } catch (err) {
      set((current) => ({
        repoSelection: { ...current.repoSelection, status: "idle", error: err.message },
      }));
      return null;
    }
  },

  /** Page through the catalog. Kept out of store state: the chooser owns it. */
  fetchSelectableRepos: async (installationId, options) => {
    const id = installationId || get().selectedInstallation?.installationId;
    if (!id) return { repositories: [], total: 0, totalPages: 1 };
    return listSelectableRepos(id, options);
  },

  refreshRepoCatalog: async (installationId) => {
    const id = installationId || get().selectedInstallation?.installationId;
    if (!id) return null;
    const state = await syncRepoCatalog(id);
    set({ repoSelection: { status: state.selectionRequired ? "required" : "ok", state, error: null } });
    return state;
  },

  /**
   * Commit a selection. On success the gate clears and the summary job is
   * started, which is the point of the whole flow.
   */
  commitRepoSelection: async (installationId, repos) => {
    const id = installationId || get().selectedInstallation?.installationId;
    if (!id) return null;

    set((state) => ({ repoSelection: { ...state.repoSelection, status: "saving", error: null } }));

    try {
      const state = await saveRepoSelection(id, repos);
      set({ repoSelection: { status: "ok", state, error: null } });
      // The list loaded before the choice was empty (nothing is offered until
      // repositories are chosen); load the chosen ones now.
      get().fetchRepositories(id);
      await get().startSummaryAnalysis(id);
      return state;
    } catch (err) {
      set((current) => ({
        repoSelection: { ...current.repoSelection, status: "required", error: err.message },
      }));
      throw err;
    }
  },

  autoSelectRepoSelection: async (installationId) => {
    const id = installationId || get().selectedInstallation?.installationId;
    if (!id) return null;

    set((state) => ({ repoSelection: { ...state.repoSelection, status: "saving", error: null } }));

    try {
      const state = await autoSelectRepos(id);
      set({ repoSelection: { status: "ok", state, error: null } });
      get().fetchRepositories(id);
      await get().startSummaryAnalysis(id);
      return state;
    } catch (err) {
      set((current) => ({
        repoSelection: { ...current.repoSelection, status: "required", error: err.message },
      }));
      throw err;
    }
  },

  // ------------------------------------------------------------------
  // Initialization
  // ------------------------------------------------------------------
  initGithubState: async () => {
    await get().fetchInstallations();
  },
}));
