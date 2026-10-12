"use client";

import React, { useState, useMemo } from "react";
import LanguageDistributionCard from "./LanguageDistributionCard";
import RepositoryActivityCard from "./RepositoryActivityCard";
import { formatChartLabel } from "@/components/charts/labelFormatter";

const RepoChartsSection = ({ processedLanguages = [], repositories = [] }) => {
  // Set initial chart types to match what ChartSwitcher expects
  const [languageChartType, setLanguageChartType] = useState("bar"); // Changed from "donut" to "bar"
  const [activityChartType, setActivityChartType] = useState("bar"); // Changed from "pie" to "bar"

  // Calculate active repos with useMemo for performance
  const activeRepos = useMemo(() => {
    return repositories
      ?.filter((r) => r?.lastCommit)
      ?.sort((a, b) => new Date(b.lastCommit) - new Date(a.lastCommit))
      ?.slice(0, 6)
      ?.map((repo) => {
        const rawName = String(repo?.name || "").trim();
        const shortName = rawName.length > 12 ? `${rawName.substring(0, 10)}...` : rawName;
        return {
          name: formatChartLabel(shortName),
          fullName: repo.name,
          commits: repo.commits || 0,
          stars: repo.stars || 0,
          lastUpdated: repo.lastCommit,
        };
      }) || [];
  }, [repositories]);

  // Process language data with useMemo
  const languageData = useMemo(() =>
    Array.isArray(processedLanguages) ? processedLanguages.slice(0, 6) : [],
    [processedLanguages]
  );

  // Calculate total commits with useMemo
  const totalCommits = useMemo(() =>
    activeRepos.reduce((sum, repo) => sum + (repo.commits || 0), 0),
    [activeRepos]
  );

  const COLORS = [
    "var(--color-primary)",
    "var(--color-secondary)",
    "var(--color-accent)",
    "var(--info)",
    "var(--success)",
    "var(--warning)",
  ];

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      <LanguageDistributionCard
        languageData={languageData}
        chartType={languageChartType}
        setChartType={setLanguageChartType}
        colors={COLORS}
      />

      <RepositoryActivityCard
        activeRepos={activeRepos}
        totalCommits={totalCommits}
        chartType={activityChartType}
        setChartType={setActivityChartType}
        colors={COLORS}
      />
    </div>
  );
};

export default RepoChartsSection;