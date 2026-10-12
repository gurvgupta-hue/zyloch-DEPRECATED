"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { useGithubStore } from "@/store/useGithubStore";

export const useNavbar = () => {
  const {
    installations,
    repositories,
    branches,
    summaryAnalysis,
    selectedInstallation,
    selectedRepo,
    selectedBranch,
    loading,
    error,
    userRole,
    setSelectedInstallation,
    setSelectedRepo,
    setSelectedBranch,
    fetchInstallations,
    fetchRepositories,
    fetchBranches,
    startSummaryAnalysis,
  } = useGithubStore();

  const [activeDropdown, setActiveDropdown] = useState(null);
  const [dropdownLock, setDropdownLock] = useState(false);

  const dropdownRefs = {
    installation: useRef(null),
    repo: useRef(null),
    branch: useRef(null),
  };

  // ---------------------------------------------------------------
  // Handle click outside dropdowns
  // ---------------------------------------------------------------
  const handleClickOutside = useCallback(
    (e) => {
      if (dropdownLock) return;

      const clickedInside = Object.values(dropdownRefs).some(
        (ref) => ref.current && ref.current.contains(e.target)
      );

      const clickedButton = e.target.closest('[data-dropdown-button="true"]');
      if (clickedInside || clickedButton) return;

      setActiveDropdown(null);
    },
    [dropdownLock]
  );

  useEffect(() => {
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [handleClickOutside]);

  // ---------------------------------------------------------------
  // Installation selection logic
  // ---------------------------------------------------------------
  const handleInstallationSelect = useCallback(
    async (installation) => {
      if (dropdownLock) return;
      setDropdownLock(true);
      setActiveDropdown(null);

      try {
        setSelectedInstallation(installation);

        if (installation?.installationId) {
          // Sequential loading for smoother UX
          await startSummaryAnalysis(installation.installationId);
          await fetchRepositories(installation.installationId);
        }
      } catch (err) {
        console.error("Error selecting installation:", err);
      } finally {
        setDropdownLock(false);
      }
    },
    [dropdownLock, setSelectedInstallation, startSummaryAnalysis, fetchRepositories]
  );

  // ---------------------------------------------------------------
  // Repository selection logic
  // ---------------------------------------------------------------
  const handleRepoSelect = useCallback(
    async (repo) => {
      if (dropdownLock) return;
      setDropdownLock(true);
      setActiveDropdown(null);

      try {
        setSelectedRepo(repo);

        if (repo?.full_name) {
          const [owner, repoName] = repo.full_name.split("/");
          await fetchBranches(owner, repoName);
        }
      } catch (err) {
        console.error("Error selecting repository:", err);
      } finally {
        setDropdownLock(false);
      }
    },
    [dropdownLock, setSelectedRepo, fetchBranches]
  );

  // ---------------------------------------------------------------
  // Branch selection logic
  // ---------------------------------------------------------------
  const handleBranchSelect = useCallback(
    (branch) => {
      if (dropdownLock) return;
      setSelectedBranch(branch);
      setActiveDropdown(null);
    },
    [dropdownLock, setSelectedBranch]
  );

  // ---------------------------------------------------------------
  // Dropdown toggler
  // ---------------------------------------------------------------
  const toggleDropdown = useCallback(
    (type) => {
      if (dropdownLock) return;
      setActiveDropdown((prev) => (prev === type ? null : type));
    },
    [dropdownLock]
  );

  // ---------------------------------------------------------------
  // Reset selections with hierarchy awareness
  // ---------------------------------------------------------------
  const resetSelection = useCallback(
    (level) => {
      if (dropdownLock) return;
      setDropdownLock(true);

      try {
        switch (level) {
          case "installation":
            setSelectedInstallation(null);
            setSelectedRepo(null);
            setSelectedBranch(null);
            break;
          case "repo":
            setSelectedRepo(null);
            setSelectedBranch(null);
            break;
          case "branch":
            setSelectedBranch(null);
            break;
          default:
            break;
        }

        setActiveDropdown(null);
      } catch (err) {
        console.error("Error resetting selection:", err);
      } finally {
        setTimeout(() => setDropdownLock(false), 100);
      }
    },
    [dropdownLock, setSelectedInstallation, setSelectedRepo, setSelectedBranch]
  );

  // ---------------------------------------------------------------
  // Manual summary refresh
  // ---------------------------------------------------------------
  const refreshAnalysis = useCallback(async () => {
    if (dropdownLock || !selectedInstallation?.installationId) return;

    try {
      await startSummaryAnalysis(selectedInstallation.installationId);
    } catch (err) {
      console.error("Error refreshing analysis:", err);
    }
  }, [dropdownLock, selectedInstallation, startSummaryAnalysis]);

  // ---------------------------------------------------------------
  // Utility: determine account icon type
  // ---------------------------------------------------------------
  const getAccountIcon = useCallback((type) => {
    if (!type) return "user";
    const normalized = type.toLowerCase();
    if (normalized === "organization") return "organization";
    if (normalized === "enterprise") return "enterprise";
    return "user";
  }, []);

  // ---------------------------------------------------------------
  // Utility: summarize analysis stats
  // ---------------------------------------------------------------
  const getSummaryStats = useCallback(() => {
    const data = summaryAnalysis?.data;
    if (!data) return null;

    return {
      totalRepos: data.totalRepositories || data.totalRepos || 0,
      totalBranches: data.totalBranches || 0,
      languagesCount: data.languages?.length || data.languageCount || 0,
      lastUpdated: data.lastUpdated || new Date().toISOString(),
    };
  }, [summaryAnalysis]);

  // ---------------------------------------------------------------
  // Utility: track analysis status
  // ---------------------------------------------------------------
  const getAnalysisStatus = useCallback(() => {
    const status = summaryAnalysis?.status || "idle";
    return {
      status,
      progress: summaryAnalysis?.progress || 0,
      error: summaryAnalysis?.error || null,
      hasData: Boolean(summaryAnalysis?.data),
      isLoading: status === "loading" || status === "in_progress",
    };
  }, [summaryAnalysis]);

  // ---------------------------------------------------------------
  // Utility: enable/disable dropdowns based on hierarchy
  // ---------------------------------------------------------------
  const isDropdownEnabled = useCallback(
    (type) => {
      if (dropdownLock) return false;
      if (type === "repo") return Boolean(selectedInstallation);
      if (type === "branch") return Boolean(selectedRepo);
      return true;
    },
    [dropdownLock, selectedInstallation, selectedRepo]
  );

  // ---------------------------------------------------------------
  // Utility: fetch correct dropdown options
  // ---------------------------------------------------------------
  const getDropdownOptions = useCallback(
    (type) => {
      if (type === "installation") return installations;
      if (type === "repo") return repositories;
      if (type === "branch") return branches;
      return [];
    },
    [installations, repositories, branches]
  );

  // ---------------------------------------------------------------
  // Utility: track dropdown loading states
  // ---------------------------------------------------------------
  const getDropdownLoading = useCallback(
    (type) => {
      if (type === "installation") return loading.installations;
      if (type === "repo") return loading.repos;
      if (type === "branch") return loading.branches;
      return false;
    },
    [loading]
  );

  // ---------------------------------------------------------------
  // Expose controlled state and actions
  // ---------------------------------------------------------------
  return {
    installations,
    repositories,
    branches,
    summaryAnalysis,
    selectedInstallation,
    selectedRepo,
    selectedBranch,
    loading,
    error,
    userRole,
    activeDropdown,
    dropdownLock,
    dropdownRefs,

    // Core handlers
    handleInstallationSelect,
    handleRepoSelect,
    handleBranchSelect,
    fetchInstallations,
    fetchRepositories,
    fetchBranches,
    startSummaryAnalysis,

    // UI controls
    setActiveDropdown: toggleDropdown,
    resetSelection,
    refreshAnalysis,

    // Utilities
    getAccountIcon,
    getSummaryStats,
    getAnalysisStatus,
    isDropdownEnabled,
    getDropdownOptions,
    getDropdownLoading,

    // Store accessors
    setSelectedInstallation,
    setSelectedRepo,
    setSelectedBranch,
  };
};
