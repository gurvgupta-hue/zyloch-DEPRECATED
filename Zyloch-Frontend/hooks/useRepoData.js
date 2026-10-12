"use client";

import { useGithubStore } from "@/store/useGithubStore";

export const useRepoData = () => {
  const {
    summaryAnalysis,
    loading,
    startSummaryAnalysis,
    refreshSummary,
    retryFailedSummary,
    selectedInstallation,
    repoSelection,
    fetchRepoSelection,
    connectingInstallation,
    waitForInstallation,
    cancelWaitForInstallation,
  } = useGithubStore();

  const installationId = selectedInstallation?.installationId;
  const accountLogin = selectedInstallation?.account?.login;

  const data = summaryAnalysis?.data || {};
  const summary = data.summary || data;

  const repositoriesArray =
    Array.isArray(data.repositories) && data.repositories.length
      ? data.repositories
      : Array.isArray(summary.repositories)
      ? summary.repositories
      : [];

  const languagesArray =
    Array.isArray(data.languages) && data.languages.length
      ? data.languages
      : Array.isArray(summary.languages)
      ? summary.languages
      : [];

  const totalRepositories =
    Number(data.totalRepositories) ||
    Number(summary.totalRepositories) ||
    Number(summary?.totals?.totalRepositories) ||
    repositoriesArray.length ||
    0;

  const totalBranches =
    Number(data.totalBranches) ||
    Number(summary.totalBranches) ||
    Number(summary?.totals?.totalBranches) ||
    repositoriesArray.reduce(
      (acc, repo) => acc + Number(repo.branchCount || repo.branches || 0),
      0
    ) ||
    0;

  const totalTeams =
    Number(data.totalTeams) ||
    Number(summary.totalTeams) ||
    Number(summary?.totals?.totalTeams) ||
    0;

  const totalTeamMembers =
    Number(data.totalTeamMembers) ||
    Number(summary.totalTeamMembers) ||
    Number(summary?.totals?.totalTeamMembers) ||
    0;

  const teamsArray =
    Array.isArray(data.teams) && data.teams.length
      ? data.teams
      : Array.isArray(summary.teams)
      ? summary.teams
      : [];

  // 🎯 Only major languages (≥5%) + "Others"
  const processedLanguages = (() => {
    if (!languagesArray?.length) return [];
    const main = [];
    let others = 0;

    languagesArray.forEach((lang) => {
      const percentage = Number(lang.percentage) || 0;
      if (percentage >= 5) main.push(lang);
      else others += percentage;
    });

    if (others > 0) {
      main.push({
        name: "Others",
        percentage: Math.round(others * 100) / 100,
        color: "#6B7280",
      });
    }

    return main.sort((a, b) => b.percentage - a.percentage);
  })();

  return {
    summaryAnalysis,
    selectedInstallation,
    installationId,
    accountLogin,
    loading,
    startSummaryAnalysis,
    refreshSummary,
    retryFailedSummary,
    repoSelection,
    fetchRepoSelection,
    connectingInstallation,
    waitForInstallation,
    cancelWaitForInstallation,
    totalRepositories,
    totalBranches,
    totalTeams,
    totalTeamMembers,
    teamsArray,
    repositoriesArray,
    allLanguages: languagesArray, // ✅ Full list
    processedLanguages, // ✅ Only major ones
    summary,
  };
};
