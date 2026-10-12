"use client";
import React, { useCallback, useEffect, useMemo } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import RepoHeaderSection from "./RepoHeaderSection";
import RepoChartsSection from "./RepoChartsSection";
import RepoPerformanceSection from "./RepoPerformanceSection";
import RepoLoading from "./RepoLoading";
import RepoSelectionGate from "./RepoSelectionGate";
import NoInstallationSelected from "./NoInstallationSelected";
import InstallationConnecting from "./InstallationConnecting";
import { AlertCircle, Play, Box } from "lucide-react";
import { useRepoData } from "@/hooks/useRepoData";

const Repo = () => {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const isDevMode = searchParams.get("dev") === "true";

  const {
    summaryAnalysis,
    selectedInstallation,
    loading,
    startSummaryAnalysis,
    refreshSummary,
    retryFailedSummary,
    totalRepositories,
    totalBranches,
    totalTeams,
    totalTeamMembers,
    teamsArray,
    repositoriesArray,
    processedLanguages,
    allLanguages,
    summary,
    repoSelection,
    fetchRepoSelection,
    connectingInstallation,
    waitForInstallation,
    cancelWaitForInstallation,
  } = useRepoData();

  const newSummaryAnalysis = useMemo(
    () => () => refreshSummary(true),
    [refreshSummary]
  );

  const handleRefreshSummary = useMemo(
    () => () => refreshSummary(isDevMode),
    [refreshSummary, isDevMode]
  );

  const installationId = selectedInstallation?.installationId;

  // Back from the GitHub App install screen: hold a "Connecting…" screen until
  // the installation is recorded, then the navbar points at the account picker.
  const redirectInstallationId = searchParams.get("installation_id");

  // Once connected, drop the redirect params so a reload doesn't replay the
  // connecting screen and the tour.
  const clearInstallRedirect = useCallback(
    (connected) => {
      if (!connected) return;
      const params = new URLSearchParams(searchParams.toString());
      params.delete("installation_id");
      params.delete("setup_action");
      const query = params.toString();
      router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
    },
    [searchParams, router, pathname]
  );

  useEffect(() => {
    if (!redirectInstallationId) return undefined;
    waitForInstallation(redirectInstallationId).then(clearInstallRedirect);
    return () => cancelWaitForInstallation();
    // clearInstallRedirect is left out on purpose: it changes with the URL,
    // and a URL change must not restart the wait.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [redirectInstallationId, waitForInstallation, cancelWaitForInstallation]);

  // Keyed on the id, not the object: the installation list is refetched and
  // replaced with new objects, which must not restart the summary check.
  useEffect(() => {
    if (installationId) {
      startSummaryAnalysis(installationId);
    }
  }, [installationId, startSummaryAnalysis]);

  // The gate is re-derived from the server on every mount, so closing the tab or
  // signing out never gets past it.
  useEffect(() => {
    if (installationId) {
      fetchRepoSelection(installationId);
    }
  }, [installationId, fetchRepoSelection]);

  // ✅ No installation selected
  if (!selectedInstallation) {
    if (connectingInstallation) {
      return (
        <InstallationConnecting
          timedOut={connectingInstallation.timedOut}
          onRetry={() =>
            waitForInstallation(connectingInstallation.installationId).then(clearInstallRedirect)
          }
        />
      );
    }
    return <NoInstallationSelected />;
  }

  // 🚧 More repositories than the plan covers: nothing is populated until the
  // customer says which ones to monitor.
  const selectionState =
    repoSelection?.state ||
    (selectedInstallation.selection?.selectionRequired ? selectedInstallation.selection : null);

  if (
    repoSelection?.status === "required" ||
    selectionState?.selectionRequired ||
    summaryAnalysis.status === "blocked"
  ) {
    return (
      <RepoSelectionGate
        selection={selectionState}
        installationId={installationId}
        onDone={() => fetchRepoSelection(installationId)}
      />
    );
  }

  // 🌀 Not known yet whether a sync is running: plain round loader only. The
  // sync screen is reserved for a job the server has confirmed, and the
  // dashboard for a finished summary, so neither flashes on reload/navigation.
  const summaryIsForAnotherInstallation =
    summaryAnalysis.installationId != null &&
    String(summaryAnalysis.installationId) !== String(installationId);

  if (
    summaryIsForAnotherInstallation ||
    !summaryAnalysis.status ||
    ["idle", "checking"].includes(summaryAnalysis.status)
  ) {
    return <RepoLoading variant="spinner" message="Loading GitHub summary..." />;
  }

  // ❳ Sync job running
  if (["in_progress", "pending"].includes(summaryAnalysis.status)) {
    return (
      <RepoLoading
        message="We are reading every repository you selected — branches, commits and languages."
        status={summaryAnalysis.status}
        progress={summaryAnalysis.progress}
        repoTarget={summaryAnalysis.repoTarget}
        repoProcessed={summaryAnalysis.repoProcessed}
        startedAt={summaryAnalysis.startedAt}
        accountLogin={selectedInstallation.account?.login}
      />
    );
  }

  // ❌ Failed state
  if (["failed", "error"].includes(summaryAnalysis.status)) {
    return (
      <div
        className="
          w-full 
          mx-auto 
          space-y-[var(--space-6)] 
          p-[var(--space-4)]
          md:p-[var(--space-6)]
          lg:p-[var(--space-8)]
          text-center 
          bg-[var(--bg)]
        "
      >
        <div className="
          flex 
          flex-col 
          items-center 
          justify-center 
          min-h-64
          py-[var(--space-8)]
        ">
          <AlertCircle
            className="
              w-10 h-10
              md:w-12 md:h-12
              mb-[var(--space-4)]
            "
            style={{ color: "var(--danger)" }}
          />

          <h3
            className="
              text-[var(--font-size-lg)]
              md:text-[var(--font-size-xl)]
              font-medium 
              mb-[var(--space-2)]
              px-[var(--space-4)]
            "
            style={{ color: "var(--text)" }}
          >
            Analysis Failed
          </h3>

          <p
            className="
              text-[var(--font-size-sm)]
              md:text-[var(--font-size-base)]
              max-w-md 
              mb-[var(--space-4)]
              px-[var(--space-4)]
              md:px-0
            "
            style={{ color: "var(--muted)" }}
          >
            {summaryAnalysis.error ||
              "Unable to analyze repositories. Please try again."}
          </p>

          {/* Retry Button */}
          <button
            onClick={retryFailedSummary}
            disabled={loading.summary}
            className="
              flex 
              items-center 
              gap-[var(--space-2)]
              px-[var(--space-4)] 
              py-[var(--space-2)]
              md:px-[var(--space-5)] 
              md:py-[var(--space-3)]
              rounded-[var(--radius-md)]
              font-medium 
              mx-auto
              disabled:opacity-50 
              disabled:cursor-not-allowed
              transition-all 
              duration-[var(--transition-normal)]
              min-h-11
            "
            style={{
              backgroundColor: "var(--color-primary)",
              color: "var(--surface)",
            }}
            onMouseEnter={(e) =>
            (e.currentTarget.style.backgroundColor =
              "var(--color-primary-600)")
            }
            onMouseLeave={(e) =>
              (e.currentTarget.style.backgroundColor = "var(--color-primary)")
            }
          >
            <Play className="w-4 h-4 md:w-5 md:h-5" />
            <span className="text-[var(--font-size-sm)] md:text-[var(--font-size-base)]">
              {loading.summary ? "Retrying..." : "Retry Analysis"}
            </span>
          </button>
        </div>
      </div>
    );
  }

  if (!summaryAnalysis.data) {
    return <RepoLoading variant="spinner" message="Loading GitHub summary..." />;
  }

  // ============================
  // ✅ MAIN CONTENT
  // ============================
  return (
    <div className="w-full flex flex-col gap-5">
      {/* Header - ADD startSummaryAnalysis prop here */}
      <RepoHeaderSection
        summaryAnalysis={summaryAnalysis}
        selectedInstallation={selectedInstallation}
        refreshSummary={handleRefreshSummary}
        totalRepositories={totalRepositories}
        totalBranches={totalBranches}
        totalTeams={totalTeams}
        totalTeamMembers={totalTeamMembers}
        teamsArray={teamsArray}
        languagesArray={allLanguages}
        loading={loading}
        newSummaryAnalysis={newSummaryAnalysis} // Add this line
        isDevMode={isDevMode}
      />

      {/* Charts Card */}
      <div
        className="
          rounded-[var(--radius-md)]
          md:rounded-[var(--radius-lg)]
          overflow-hidden
        "
      >
        <RepoChartsSection
          processedLanguages={processedLanguages}
          repositories={repositoriesArray}
        />
      </div>

      {/* Performance Card */}
      <div
        className="
          border 
          border-[var(--border)]
          bg-[var(--surface)]
          rounded-[var(--radius-md)]
          md:rounded-[var(--radius-lg)]
          p-[var(--space-3)]
          sm:p-[var(--space-4)]
          md:p-[var(--space-6)]
          shadow-[var(--shadow-soft)]
        "
      >
        <RepoPerformanceSection summary={summary} />
      </div>
    </div>
  );
};

export default Repo;