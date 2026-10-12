"use client";

import React from "react";
import TechStackIcon from "@/components/common/TechStackIcon";
import { OVERVIEW_DS, OVERVIEW_CARD_STYLE } from "../overview/designSystem";
import InfoCard from "../overview/metrics/InfoCard";
import { formatApiText, formatDuration } from "../overview/utils";
import {
  GitCommitHorizontal,
  UserRound,
  ScanSearch,
  GitBranch,
  Clock3,
  Calendar,
} from "lucide-react";

export default function ScanMetadataOverview({
  scanMetadata = {},
  scanType = null,
  duration = null,
  title = "Repository Overview",
  cards = null,
  className = "",
  style = {},
}) {
  const repositoryName = [
    scanMetadata?.organization || scanMetadata?.repo_org || scanMetadata?.org_name,
    scanMetadata?.repository || scanMetadata?.repo_name,
  ]
    .filter(Boolean)
    .join("/") || scanMetadata?.repository || scanMetadata?.repo_name || "N/A";

  const branchName = scanMetadata?.branch || "main";
  const commitMessage = String(scanMetadata?.commit_message ?? "").trim() || "N/A";
  const commitAuthor = String(scanMetadata?.commit_author ?? scanMetadata?.author ?? "").trim() || "N/A";
  const authorInitial = commitAuthor?.trim()?.charAt(0)?.toUpperCase() || "N";
  
  const displayScanType = scanType || scanMetadata?.scan_type || "N/A";
  const displayEventType = scanMetadata?.event_type || "N/A";
  
  const isDurationNumber = typeof duration === "number" && duration > 0;
  const durationValue = isDurationNumber
    ? formatDuration(duration)
    : duration || (scanMetadata?.scan_timestamp || scanMetadata?.created_at
      ? new Date(scanMetadata.scan_timestamp || scanMetadata.created_at).toLocaleDateString()
      : "N/A");

  const defaultCards = [
    {
      label: "Last Commit",
      value: commitMessage,
      icon: <GitCommitHorizontal />,
    },
    {
      label: "Commit Author",
      value: (
        <div className="inline-flex items-center gap-2 min-w-0">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-[color-mix(in_srgb,var(--color-primary)_14%,var(--surface))] text-xs font-semibold text-[var(--color-primary)]">
            {authorInitial}
          </span>
          <span className="truncate text-base font-semibold leading-tight text-[var(--text)]">
            {commitAuthor}
          </span>
        </div>
      ),
      icon: <UserRound />,
    },
    {
      label: "Scan Type",
      value: formatApiText(displayScanType),
      icon: <ScanSearch />,
    },
    {
      label: "Event Type",
      value: formatApiText(displayEventType),
      icon: <GitBranch />,
    },
    {
      label: isDurationNumber ? "Duration" : "Scan Date",
      value: (
        <div className="inline-flex items-center gap-2 min-w-0">
          <span className="inline-flex h-5 w-5 items-center justify-center rounded-md bg-[color-mix(in_srgb,var(--color-primary)_12%,var(--surface))] text-[var(--color-primary)] [&_svg]:h-3 [&_svg]:w-3">
            {isDurationNumber ? <Clock3 /> : <Calendar />}
          </span>
          <span className="truncate text-base font-semibold leading-tight text-[var(--text)]">
            {durationValue}
          </span>
        </div>
      ),
      icon: isDurationNumber ? <Clock3 /> : <Calendar />,
    },
  ];

  const overviewCards = cards || defaultCards;

  return (
    <div
      style={{
        position: "relative",
        ...OVERVIEW_CARD_STYLE,
        padding: OVERVIEW_DS.spacing.x3,
        ...style,
      }}
      className={`w-full ${className}`}
    >
      <div className="space-y-4">
        <div>
          <div className="flex flex-wrap items-center gap-3 text-sm md:text-base">
            <div className="flex items-center gap-2 whitespace-nowrap">
              <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-[color-mix(in_srgb,var(--color-primary)_14%,var(--surface))]">
                <TechStackIcon name="github" size={18} />
              </span>
              <span
                className="font-semibold text-[var(--text)]"
                style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.body }}
              >
                {title}
              </span>
            </div>

            <span
              className="break-all font-semibold text-[var(--muted)]"
              style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.label }}
            >
              {repositoryName}
            </span>
            <span
              className="font-semibold text-[var(--muted)]"
              style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.micro }}
            >
              {branchName}
            </span>
          </div>
        </div>

        <div className={`grid grid-cols-1 sm:grid-cols-2 ${overviewCards.length >= 5 ? "xl:grid-cols-5" : overviewCards.length === 4 ? "xl:grid-cols-4" : "xl:grid-cols-3"} gap-4 border-t border-[var(--border)] pt-4`}>
          {overviewCards.map((card) => (
            <InfoCard
              key={card.label}
              label={card.label}
              value={card.value}
              icon={card.icon}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
