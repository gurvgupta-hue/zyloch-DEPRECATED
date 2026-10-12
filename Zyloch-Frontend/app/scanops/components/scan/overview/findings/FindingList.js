import React from "react";
import { COLORS, formatScannerDisplayName } from "../utils";
import FindingSection from "./FindingSection";
import EmptyState from "../common/EmptyState";

const FindingList = ({ scansFindings, scoreSummary }) => {
  if (!scansFindings || typeof scansFindings !== 'object') {
    return <EmptyState message="No findings available" />;
  }

  const scoreBySubscan = scoreSummary?.score_by_subscan || {};

  const normalizeScannerKey = (value) =>
    String(value || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "_")
      .replace(/-/g, "_");

  const extractScannerKey = (rawKey) =>
    String(rawKey || "")
      .replace(/[-_]findings$/i, "")
      .trim();

  const getScannerColor = (scannerKey) => {
    const normalized = normalizeScannerKey(scannerKey);

    return (
      COLORS[normalized] ||
      (normalized.startsWith("terraform") ? COLORS.warning : null) ||
      (normalized.startsWith("secret") ? COLORS.secret : null) ||
      (normalized.includes("yaml") ? COLORS.medium : null) ||
      COLORS.primary
    );
  };

  const toFindingItems = (items) => {
    if (Array.isArray(items)) return items;
    if (!items || typeof items !== "object") return [];

    const values = Object.values(items);
    if (values.every((entry) => Array.isArray(entry))) {
      return values.flat();
    }

    return values.filter((entry) => typeof entry === "object" && entry !== null);
  };

  const getScoreForScanner = (scannerType) => {
    const normalized = normalizeScannerKey(scannerType);
    const dashKey = normalized.replace(/_/g, "-");

    return (
      scoreBySubscan[scannerType] ??
      scoreBySubscan[normalized] ??
      scoreBySubscan[dashKey] ??
      null
    );
  };

  // Dynamically create sections from the data
  const sections = Object.entries(scansFindings)
    .map(([key, rawItems]) => {
      const items = toFindingItems(rawItems);

      // Skip if items is not an array or is empty
      if (!Array.isArray(items) || items.length === 0) {
        return null;
      }

      const scannerType = extractScannerKey(key);
      const label = `${formatScannerDisplayName(scannerType)} Findings`;
      const score = getScoreForScanner(scannerType);

      // Get color based on scanner type
      const color = getScannerColor(scannerType);

      // Calculate total violations
      const count = items.reduce(
        (acc, item) => {
          const violations = item?.violated_policies;
          if (Array.isArray(violations)) return acc + violations.length;

          // Some scanners return one item as one issue without violated_policies array.
          return acc + 1;
        },
        0
      );

      return (
        <FindingSection
          key={key}
          title={label}
          scannerType={scannerType}
          count={count}
          files={items.length}
          color={color}
          score={score}
          className="h-full"
        />
      );
    })
    .filter(Boolean);

  return sections.length ? (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-3">
      {sections}
    </div>
  ) : (
    <EmptyState message="No security findings detected" />
  );
};

export default FindingList;
