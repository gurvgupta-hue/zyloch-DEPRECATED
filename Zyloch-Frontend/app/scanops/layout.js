'use client';

import React, { useState, useEffect, Suspense } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import ProtectedLayout from "@/components/ProtectedLayout";
import TimeZoneDisplay from "@/components/ui/TimeZoneDisplay";
import RepoNavbar from "./components/Navbar";
import Sidebar from "./components/Sidebar";
import ScanHeader, { BULK_OVERVIEW_DISABLED_HINT } from "./components/scan/Header";

import { useScanStore } from "@/store/useScanStore";
import { useNavbar } from "@/hooks/useNavbar";

import Loading from "@/components/Loader";
import { Play, RefreshCw, AlertCircle, FolderOpen, Info, Calendar, FileSearch, ShieldCheck } from "lucide-react";
import { toast } from "react-toastify";

function CustomButton({ label, icon, onClick, variant = "primary", disabled = false, loading = false, title }) {
  const baseStyle = `
    inline-flex items-center justify-center gap-2
    px-[var(--space-4)] py-[var(--space-2)]
    rounded-[var(--radius-md)]
    text-[var(--font-size-sm)] font-[var(--weight-medium)]
    transition-all duration-200 active:scale-95
    disabled:opacity-50 disabled:cursor-not-allowed
    border
  `;

  const variants = {
    primary: `
      bg-[var(--color-primary-600)]
      hover:bg-[var(--color-primary-600)]
      text-[var(--color-primary)]
      border-[var(--color-primary)]
    `,
    secondary: `
      bg-[var(--color-primary-600)]
      hover:bg-[var(--border)]
      text-[var(--color-primary)]
      border-[var(--border)]
    `,
    danger: `
      bg-[var(--color-primary-600)]
      hover:opacity-90
      text-[var(--color-primary)]
      border-[var(--danger)]
    `,
    accent: `
      bg-[var(--color-primary-600)]
      hover:opacity-90
      text-[var(--color-primary)]
      border-[var(--color-accent)]
    `
  };

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || loading}
      title={title}
      className={`${baseStyle} ${variants[variant]}`}
    >
      {loading ? <RefreshCw size={16} className="animate-spin" /> : icon}
      <span>{label}</span>
    </button>
  );
}

function EmptyState({ icon, title, description, action }) {
  return (
    <div className="flex h-full items-center justify-center p-8">
      <div className="flex w-full max-w-xl flex-col items-center gap-4 p-6 text-center">
        <div className="flex h-16 w-16 items-center justify-center">
          {icon}
        </div>
        <div className="space-y-1.5">
          <h3 className="text-[15px] font-semibold text-[var(--text)]">{title}</h3>
          <p className="text-[13px] leading-relaxed text-[var(--muted)] whitespace-pre-line break-words">{description}</p>
        </div>
        {action && <div className="pt-1">{action}</div>}
      </div>
    </div>
  );
}

function InfoState({ title, message, onAction, isPolling = false, actionDisabled = false, actionTitle }) {
  const { selectedBranch } = useNavbar();
  const msg = String(message || "").toLowerCase();

  const isUninitiated = !isPolling && (
    msg.includes("no scans found") ||
    msg.includes("no scan found") ||
    msg.includes("scan not initiated") ||
    !message ||
    message === "Start a new scan to find issues."
  );

  const displayTitle = isPolling
    ? "Scan in Progress"
    : (title || (isUninitiated ? "Scan Not Initiated" : "Scan Not Initiated"));

  const displayMessage = isPolling
    ? "Please wait while the scan completes."
    : (isUninitiated
      ? "Start a new scan to find issues."
      : (msg.includes("no scans found for organization")
        ? `No scans available for '${selectedBranch?.name}' branch.\nInitial scans run only on main/master branches.\nStart a manual scan to generate results.`
        : (message || "Start a new scan to find issues.")));

  return (
    <div className="flex h-full items-center justify-center p-8">
      <div className="flex w-full max-w-xl flex-col items-center gap-4 p-6 text-center">
        <div className="flex h-16 w-16 items-center justify-center">
          {isPolling
            ? <RefreshCw className="w-7 h-7 animate-spin" style={{ color: "rgba(var(--color-primary-rgb), 0.7)" }} />
            : <Info className="w-7 h-7 text-[var(--muted)]" />}
        </div>
        <div className="space-y-1.5">
          <h3 className="text-[15px] font-semibold text-[var(--text)]">
            {displayTitle}
          </h3>
          <p className="text-[13px] leading-relaxed text-[var(--muted)] whitespace-pre-line">
            {displayMessage}
          </p>
        </div>
        {!isPolling && (
          <CustomButton
            label="Start New Scan"
            icon={<Play size={15} />}
            onClick={actionDisabled ? undefined : onAction}
            disabled={actionDisabled}
            title={actionDisabled ? actionTitle : undefined}
          />
        )}
      </div>
    </div>
  );
}

const getScanTitleFromPath = (pathname) => {
  if (!pathname) return "OVERVIEW";
  const path = pathname
    .replace(/^\/scanops\/?/, "")
    .split("/")
    .filter(Boolean)[0] || "overview";

  const titleMap = {
    overview: "OVERVIEW",
    workflow: "GITHUB ACTIONS WORKFLOW",
    sbom: "SBOM",
    "secret-scanner": "SECRET SCANNER",
    "spec-scanner": "API DISCOVERY",
    docker: "DOCKER",
    kubernetes: "KUBERNETES",
    terraform: "TERRAFORM",
    "ai-vs-human": "AI VS HUMAN",
    iac: "INFRASTRUCTURE AS CODE",
    "skill-scanner": "AI SECURITY SCANNER",
    "ai-security-scanner": "AI SECURITY SCANNER",
  };

  return titleMap[path] || "OVERVIEW";
};

const TABBED_AI_ROUTES = ["ai-security-scanner", "skill-scanner"];

// `tab` only matters on the AI Security Scanner route, which hosts two separate
// backend scans (skill-scanner and cis-agent) as tabs on one page.
const getScanTypeFromPath = (pathname, tab) => {
  if (!pathname) return "all";
  const path = pathname
    .replace(/^\/scanops\/?/, "")
    .split("/")
    .filter(Boolean)[0] || "overview";

  const scanTypeMap = {
    overview: "all",
    workflow: "workflow",
    "spec-scanner": "spec-scanner",
    docker: "docker",
    kubernetes: "kubernetes",
    terraform: "terraform",
    "secret-scanner": "secret_scanner",
    sbom: "sbom",
    "ai-vs-human": "AiVsHuman",
    iac: "iac",
    "skill-scanner": "skill-scanner",
    "ai-security-scanner": "skill-scanner",
  };

  if (tab === "cis" && TABBED_AI_ROUTES.includes(path)) return "cis-agent";

  return scanTypeMap[path] || "all";
};

const isTabbedAiRoute = (pathname) =>
  TABBED_AI_ROUTES.includes(
    String(pathname || "").replace(/^\/scanops\/?/, "").split("/").filter(Boolean)[0]
  );

const isPrimaryBranch = (name) =>
  Boolean(name && ["main", "master"].includes(String(name).toLowerCase()));

export default function HomeLayout({ children }) {
  return (
    <Suspense fallback={null}>
      <HomeLayoutInner>{children}</HomeLayoutInner>
    </Suspense>
  );
}

function HomeLayoutInner({ children }) {
  const pathname = usePathname();
  const router = useRouter();
  const activeTab = useSearchParams().get("tab");

  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [desktopSidebarOpen, setDesktopSidebarOpen] = useState(true);
  const [currentScanTitle, setCurrentScanTitle] = useState("Overview");

  useEffect(() => {
    const saved = window.localStorage.getItem('zyloch:sidebar:scanops');
    if (saved === 'open' || saved === 'closed') setDesktopSidebarOpen(saved === 'open');
  }, []);

  useEffect(() => {
    window.localStorage.setItem('zyloch:sidebar:scanops', desktopSidebarOpen ? 'open' : 'closed');
  }, [desktopSidebarOpen]);

  const {
    latestScan,
    error,
    loading,
    startingScan,
    refreshingScan,
    pollingScan,
    initiateScan,
    fetchLatestScan,
    clearLatestScan,
    clearStatus,
  } = useScanStore();

  const { selectedInstallation, selectedRepo, selectedBranch } = useNavbar();

  const scanTypeForPath = getScanTypeFromPath(pathname, activeTab);
  const tabbedAiRoute = isTabbedAiRoute(pathname);
  const aiScanTabs = tabbedAiRoute
    ? [
        { id: "skill-scanner", label: "AI Security Scanner", icon: FileSearch },
        { id: "cis", label: "CIS Scanner", icon: ShieldCheck },
      ]
    : null;
  const isCveDetailsRoute = pathname?.startsWith("/scanops/cve/");
  const bulkOverviewScanBlocked =
    scanTypeForPath === "all" && !isPrimaryBranch(selectedBranch?.name);

  const canFetchScan = Boolean(selectedRepo?.full_name && selectedBranch?.name);
  const canStartScan = Boolean(selectedInstallation && canFetchScan);

  useEffect(() => {
    setCurrentScanTitle(getScanTitleFromPath(pathname));
  }, [pathname]);

  useEffect(() => {
    clearStatus();
    clearLatestScan();

    if (!canFetchScan) {
      setCurrentScanTitle(getScanTitleFromPath(pathname));
    }
  }, [selectedInstallation, selectedRepo, selectedBranch, clearStatus, clearLatestScan, canFetchScan]);

  useEffect(() => {
    if (!canFetchScan || isCveDetailsRoute || !selectedInstallation?.installationId) return;

    const [org, repo] = selectedRepo.full_name.split("/");
    const scanType = getScanTypeFromPath(pathname, activeTab);
    fetchLatestScan(
      selectedInstallation.installationId,
      org,
      repo,
      selectedBranch.name,
      scanType
    );

    return () => {
      clearLatestScan();
    };
  }, [
    isCveDetailsRoute,
    canFetchScan,
    selectedInstallation,
    selectedRepo,
    selectedBranch,
    pathname,
    activeTab,
    fetchLatestScan,
    clearLatestScan,
  ]);

  const handleStartNewScan = async () => {
    if (!canStartScan) return;

    if (bulkOverviewScanBlocked) {
      toast.info(BULK_OVERVIEW_DISABLED_HINT);
      return;
    }

    clearLatestScan();
    const [org, repo] = selectedRepo.full_name.split("/");
    const scanType = getScanTypeFromPath(pathname, activeTab);

    await initiateScan(
      selectedInstallation.installationId,
      org,
      repo,
      selectedBranch.name,
      scanType
    );
  };

  const handleRefresh = async () => {
    if (!canFetchScan) return;

    clearLatestScan();
    const [org, repo] = selectedRepo.full_name.split("/");
    const scanType = getScanTypeFromPath(pathname, activeTab);

    await fetchLatestScan(
      selectedInstallation.installationId,
      org,
      repo,
      selectedBranch.name,
      scanType,
      true
    );
  };

  useEffect(() => {
    return () => {
      clearStatus();
    };
  }, [clearStatus]);

  const errorText = String(error || "").toLowerCase();
  const isNoScanError =
    Boolean(error) &&
    ((errorText.includes("no") && (errorText.includes("scan found") || errorText.includes("scans found") || errorText.includes("scans available"))) ||
      errorText.includes("scan not found") ||
      errorText.includes("scan not initiated") ||
      errorText.includes("not found"));
  const isNoApiDiscovered =
    Boolean(error) &&
    (errorText.includes("no api paths could be extracted") ||
      errorText.includes("no api discovered"));

  const shouldShowHeader = !isCveDetailsRoute && canFetchScan;

  const isScanOpsEmpty =
    !isCveDetailsRoute &&
    (!canFetchScan ||
      startingScan ||
      pollingScan ||
      loading ||
      (error && isNoApiDiscovered) ||
      (error && !isNoScanError) ||
      ((error && isNoScanError) || !latestScan));

  const renderScanStatus = () => {
    if (startingScan || pollingScan) {
      return (
        <div className="flex items-center gap-1.5 text-xs text-[var(--color-primary)] font-medium">
          <RefreshCw size={12} className="animate-spin flex-shrink-0" />
          <span>Scan in progress...</span>
        </div>
      );
    }
    if (refreshingScan) {
      return (
        <div className="flex items-center gap-1.5 text-xs text-[var(--muted)] font-medium">
          <RefreshCw size={12} className="animate-spin flex-shrink-0" />
          <span>Refreshing scan...</span>
        </div>
      );
    }
    if (latestScan?.created_at) {
      return (
        <div className="flex items-center gap-1.5 text-xs text-[var(--muted)]">
          <Calendar size={13} className="text-[var(--muted)] flex-shrink-0" />
          <span>Last scanned:</span>
          <TimeZoneDisplay time={latestScan.created_at} format="full" />
        </div>
      );
    }
    if (loading) {
      return (
        <div className="flex items-center gap-1.5 text-xs text-[var(--muted)] font-medium">
          <RefreshCw size={12} className="animate-spin flex-shrink-0" />
          <span>Loading scan data...</span>
        </div>
      );
    }
    return <span className="text-xs text-[var(--muted)]">Ready to scan</span>;
  };

  return (
    <ProtectedLayout>
      <div
        data-scanops-shell
        className="relative flex h-screen overflow-hidden bg-[var(--bg)] p-3 gap-3"
      >
        {/* Desktop sidebar */}
        <aside aria-label="Scan operations sidebar" className={`hidden sm:flex shrink-0 h-full bg-transparent transition-all duration-300 ease-in-out ${desktopSidebarOpen ? "w-[272px]" : "w-[72px]"}`}>
          <Sidebar isOpen={desktopSidebarOpen} showToggle={true} onToggle={() => setDesktopSidebarOpen((prev) => !prev)} />
        </aside>

        {/* Mobile sidebar */}
        <aside
          aria-label="Scan operations mobile sidebar"
          className={`fixed sm:hidden top-0 left-0 z-50 h-full w-[18.5rem] shrink-0 p-2.5 bg-transparent
            transform transition-transform duration-300 ease-in-out
            ${mobileSidebarOpen ? "translate-x-0" : "-translate-x-full"}`}
        >
          <Sidebar isOpen={true} />
        </aside>

        {/* Mobile overlay */}
        {mobileSidebarOpen && (
          <div
            className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm sm:hidden"
            onClick={() => setMobileSidebarOpen(false)}
          />
        )}

        {/* Main content area */}
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] backdrop-blur-xl transition-all duration-200">

          {/* Navbar */}
          {!isCveDetailsRoute && (
            <header className="shrink-0 border-b border-[var(--border)]">
              <RepoNavbar
                onToggleSidebar={() => setMobileSidebarOpen(!mobileSidebarOpen)}
                hideSelectors={isCveDetailsRoute}
              />
            </header>
          )}

          {/* Scan header (consistently mounted when repo selected) */}
          {shouldShowHeader && (
            <div className="shrink-0 px-4 sm:px-6 pt-4 sm:pt-6 pb-0 w-full">
              <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] shadow-1 px-4 sm:px-6 py-3.5 transition-all duration-200">
                <ScanHeader
                  scanTitle={currentScanTitle}
                  scanStatus={renderScanStatus()}
                  onStartNewScan={handleStartNewScan}
                  onRefresh={handleRefresh}
                  refreshing={refreshingScan}
                  tabs={aiScanTabs}
                  activeTabId={activeTab === "cis" ? "cis" : "skill-scanner"}
                  onTabChange={(id) => router.replace(id === "cis" ? `${pathname}?tab=cis` : pathname)}
                  newScanDisabled={startingScan || pollingScan || refreshingScan || bulkOverviewScanBlocked || !canStartScan}
                />
              </div>
            </div>
          )}

          {/* Scrollable page area */}
          <main
            id="main-content"
            aria-label="Scan operations"
            data-scanops-content
            className="flex-1 overflow-y-auto scrollbar-hide-lg relative"
          >
            {isCveDetailsRoute ? (
              children
            ) : !canFetchScan ? (
              <EmptyState
                icon={<FolderOpen className="w-12 h-12 text-[var(--muted)]" />}
                title="Select a Repository"
                description="Choose an installation, repository and branch from the toolbar above to get started."
              />
            ) : tabbedAiRoute ? (
              // AI Security Scanner hosts two independent scans as tabs; the tab
              // bar must stay visible even when the active scan hasn't run, so
              // its panels render their own loading/empty/in-progress states.
              children
            ) : startingScan || pollingScan ? (
              <InfoState
                title="Scan in Progress"
                message={`Running security scan for '${selectedBranch?.name || "main"}' branch.\nPlease wait while the scan completes.`}
                onAction={handleStartNewScan}
                isPolling={true}
              />
            ) : loading ? (
              <div className="flex h-full min-h-[350px] items-center justify-center p-8">
                <div className="flex flex-col items-center gap-3">
                  <div className="relative flex h-14 w-14 items-center justify-center">
                    <RefreshCw className="h-6 w-6 animate-spin text-[var(--color-primary)]" />
                  </div>
                  <p className="text-sm font-medium text-[var(--muted)]">Loading {currentScanTitle} scan data...</p>
                </div>
              </div>
            ) : error && isNoApiDiscovered ? (
              <EmptyState
                icon={<Info className="w-12 h-12 text-[var(--muted)]" />}
                title="No API Discovered"
                description="No API paths could be extracted from this repository. Add an OpenAPI/Swagger spec or API routes, then try again."
                action={
                  <CustomButton
                    label="Try Again"
                    icon={<RefreshCw size={15} />}
                    onClick={handleStartNewScan}
                    disabled={bulkOverviewScanBlocked || !canStartScan}
                    title={bulkOverviewScanBlocked ? BULK_OVERVIEW_DISABLED_HINT : (!canStartScan ? "Select an installation to start a new scan" : undefined)}
                  />
                }
              />
            ) : error && !isNoScanError ? (
              <EmptyState
                icon={<AlertCircle className="w-12 h-12 text-red-400/60" />}
                title="Scan Error"
                description={String(error)}
                action={
                  <CustomButton
                    label="Try Again"
                    icon={<RefreshCw size={15} />}
                    onClick={handleStartNewScan}
                    disabled={bulkOverviewScanBlocked || !canStartScan}
                    title={bulkOverviewScanBlocked ? BULK_OVERVIEW_DISABLED_HINT : (!canStartScan ? "Select an installation to start a new scan" : undefined)}
                  />
                }
              />
            ) : (error && isNoScanError) || !latestScan ? (
              <InfoState
                title="Scan Not Initiated"
                message="Start a new scan to find issues."
                onAction={handleStartNewScan}
                isPolling={false}
                actionDisabled={bulkOverviewScanBlocked || !canStartScan}
                actionTitle={bulkOverviewScanBlocked ? BULK_OVERVIEW_DISABLED_HINT : (!canStartScan ? "Select an installation to start a new scan" : undefined)}
              />
            ) : (
              children
            )}
          </main>
        </div>
      </div>
    </ProtectedLayout>
  );
}