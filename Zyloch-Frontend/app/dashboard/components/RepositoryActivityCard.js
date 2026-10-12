"use client";

import React from "react";
import { BarChart3 } from "lucide-react";
import BarChart3D from "@/components/charts/BarChartUI";
import ChartSwitcher from "./ChartSwitcher";
import DonutChartUI from "@/components/charts/DonutChartUI";

const RepositoryActivityCard = ({
  activeRepos = [],
  totalCommits = 0,
  chartType,
  setChartType,
  colors = [],
}) => {
  return (
    <div
      className="rounded-xl p-6 w-full"
      style={{
        background: "var(--surface)",
        borderRadius: "var(--radius-lg)",
        boxShadow: "var(--shadow-2)",
        border: "1px solid var(--border)",
      }}
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3
            className="text-lg font-semibold mb-1"
            style={{ color: "var(--text)" }}
          >
            Repository Activity
          </h3>
          <p className="text-sm" style={{ color: "var(--muted)" }}>
            Recent commits across repositories
          </p>
        </div>
        <ChartSwitcher type={chartType} setType={setChartType} />
      </div>

      <div className="h-[260px]">
        {activeRepos.length > 0 ? (
          chartType === "pie" ? (
            <DonutChartUI
              data={activeRepos.map((repo, index) => ({
                name: repo.name,
                value: repo.commits || 0,
                percentage: totalCommits
                  ? (((repo.commits || 0) / totalCommits) * 100).toFixed(1)
                  : "0",
              }))}
              dataKey="value"
              nameKey="name"
              colors={colors}
              height={260}
              innerRadius={70} // Adjust donut hole size
              outerRadius={100}
            />
          ) : (
            <BarChart3D
              data={activeRepos.map((repo) => ({
                name: repo.name,
                value: repo.commits || 0,
                commits: repo.commits || 0,
              }))}
              dataKey="value"
              nameKey="name"
              colors={colors}
              height={260}
              barSize={40}
              showGlow={true}
              hideLabels={true}
            />
          )
        ) : (
          <div
            className="h-full flex flex-col items-center justify-center p-4"
            style={{ color: "var(--muted)" }}
          >
            <div
              className="w-12 h-12 rounded-full flex items-center justify-center mb-4"
              style={{ background: "var(--elevated-surface)" }}
            >
              <BarChart3 className="w-6 h-6" />
            </div>
            <p className="text-sm mb-1">No recent activity data</p>
            <p className="text-xs">Commit activity will appear here</p>
          </div>
        )}
      </div>

      {activeRepos.length > 0 && (
        <div
          className="mt-6 pt-6"
          style={{ borderTop: "1px solid var(--border)" }}
        >
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center">
                <p className="text-xs mb-1" style={{ color: "var(--muted)" }}>
                  Active Repositories
                </p>
                <p
                  className="text-xl font-semibold"
                  style={{ color: "var(--text)" }}
                >
                  {activeRepos.length}
                </p>
              </div>
              <div className="text-center">
                <p className="text-xs mb-1" style={{ color: "var(--muted)" }}>
                  Total Commits
                </p>
                <p
                  className="text-xl font-semibold"
                  style={{ color: "var(--success)" }}
                >
                  {totalCommits.toLocaleString()}
                </p>
              </div>
              <div className="text-center">
                <p className="text-xs mb-1" style={{ color: "var(--muted)" }}>
                  Avg. Commits
                </p>
                <p
                  className="text-xl font-semibold"
                  style={{ color: "var(--color-primary)" }}
                >
                  {Math.round(totalCommits / activeRepos.length)}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RepositoryActivityCard;
