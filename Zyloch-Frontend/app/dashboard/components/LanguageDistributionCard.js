"use client";

import React from "react";
import { PieChart as PieChartIcon, Code2 } from "lucide-react";
import LanguageBarChart3D from "@/components/charts/LanguageBarChart3D";
import PieChart3D from "@/components/charts/PieChartUI";
import ChartSwitcher from "./ChartSwitcher";
import { languageIcons } from "./languageIcons";

const LanguageDistributionCard = ({
  languageData,
  chartType,
  setChartType,
  colors,
}) => {
  const getLanguageIcon = (languageName) => {
    const normalizedName = languageName.toLowerCase();
    return languageIcons[normalizedName] || Code2;
  };

  const enhancedLanguageData = languageData.map((lang) => ({
    ...lang,
    icon: getLanguageIcon(lang.name),
  }));

  const languageIconsArray = enhancedLanguageData.map((lang) => lang.icon);

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
            Language Distribution
          </h3>
          <p className="text-sm" style={{ color: "var(--muted)" }}>
            Top programming languages across repositories
          </p>
        </div>
        <ChartSwitcher type={chartType} setType={setChartType} />
      </div>

      <div className="h-[260px]">
        {enhancedLanguageData.length > 0 ? (
          chartType === "pie" ? (
            <PieChart3D
              data={enhancedLanguageData}
              dataKey="percentage"
              nameKey="name"
              colors={colors}
              height={260}
              showLabel={false}
              labelFormatter={(entry) => {
                const IconComponent = entry.icon;
                return <IconComponent className="w-4 h-4" />;
              }}
            />
          ) : (
            <LanguageBarChart3D
              data={enhancedLanguageData}
              dataKey="percentage"
              nameKey="name"
              icons={languageIconsArray}
              colors={colors}
              height={240}
              barSize={40}
              showGlow={true}
              showLabels={false}
              hideXAxis={true}
              tooltipFormatter={(value, name) => {
                const entry = enhancedLanguageData.find(
                  (item) => item.name === name,
                );
                const IconComponent = entry?.icon;

                return IconComponent ? (
                  <div className="flex items-center gap-3 p-3">
                    <IconComponent className="w-5 h-5" />
                    <div>
                      <div
                        style={{
                          color: "var(--text)",
                          fontWeight: "var(--weight-semibold)",
                        }}
                      >
                        {name}
                      </div>
                      <div
                        style={{
                          color: "var(--muted)",
                          fontSize: "var(--font-size-sm)",
                        }}
                      >
                        {value}%
                      </div>
                    </div>
                  </div>
                ) : null;
              }}
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
              <PieChartIcon className="w-6 h-6" />
            </div>
            <p className="text-sm mb-1">No language data available</p>
            <p className="text-xs">
              Add repositories to see language distribution
            </p>
          </div>
        )}
      </div>

      {enhancedLanguageData.length > 0 && (
        <div
          className="mt-4 pt-4"
          style={{ borderTop: "1px solid var(--border)" }}
        >
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {enhancedLanguageData.map((lang, index) => {
                const color = colors[index % colors.length];
                return (
                  <div
                    key={lang.name}
                    className="group flex items-center justify-between p-3 rounded-lg transition-all duration-200 hover:shadow-md"
                    style={{
                      background: "var(--elevated-surface)",
                      borderRadius: "var(--radius-md)",
                      border: "1px solid var(--border)",
                    }}
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className="w-3 h-3 rounded-full flex-shrink-0"
                        style={{
                          background: color,
                          boxShadow: `0 1px 8px ${color}80`,
                        }}
                      />

                      <div className="flex flex-col">
                        <span
                          className="font-medium text-sm"
                          style={{ color: "var(--text)" }}
                        >
                          {lang.name}
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-col items-end leading-tight">
                      <span
                        className="font-bold text-sm"
                        style={{ color: color }}
                      >
                        {lang.percentage}%
                      </span>
                      <span
                        className="text-[10px] opacity-80"
                        style={{ color: "var(--muted)" }}
                      >
                        {lang.commits ? `${lang.commits} commits` : ""}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LanguageDistributionCard;
