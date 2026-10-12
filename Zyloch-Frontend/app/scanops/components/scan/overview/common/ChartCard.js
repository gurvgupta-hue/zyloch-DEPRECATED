"use client";

import React, { useState } from "react";
import { ChevronUp, ChevronDown } from "lucide-react";
import { OVERVIEW_CARD_STYLE, OVERVIEW_DS, OVERVIEW_EYEBROW_STYLE } from "../designSystem";

const ChartCard = ({
  title,
  description,
  children,
  className = "",
  collapse = false,
  defaultExpanded = true,
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  const toggleExpand = () => {
    if (collapse) {
      setIsExpanded(!isExpanded);
    }
  };

  return (
    <div
      className={`
        flex flex-col 
        rounded-xl
        transition-all duration-300 
        hover:shadow-xl hover:translate-y-[-2px]
        ${collapse && !isExpanded ? "min-h-[auto]" : "min-h-[350px]"}
        ${className}
      `}
      style={{
        ...OVERVIEW_CARD_STYLE,
      }}
    >
      {/* Header with toggle */}
      <div
        className={`p-5 ${collapse ? "cursor-pointer" : ""}`}
        onClick={toggleExpand}
      >
        <div className="flex items-center justify-between gap-2">
          {/* Title */}
          <div className="flex-1">
            <h4
              className="mb-1"
              style={OVERVIEW_EYEBROW_STYLE}
              title={title}
            >
              {title}
            </h4>

            {/* Description - shows only when expanded */}
            {isExpanded && description && (
              <span
                className="block mt-2"
                style={{
                  fontFamily: OVERVIEW_DS.typography.family,
                  fontSize: OVERVIEW_DS.typography.label,
                  lineHeight: "18px",
                  color: "var(--muted)",
                  opacity: 0.8,
                }}
                title={description}
              >
                {description}
              </span>
            )}
          </div>

          {/* Collapse Toggle with Text */}
          {collapse && (
            <div className="flex items-center gap-2 text-[var(--muted)] hover:text-[var(--text)] transition-colors">
              <span
                className="font-medium"
                style={{
                  fontFamily: OVERVIEW_DS.typography.family,
                  fontSize: OVERVIEW_DS.typography.label,
                  lineHeight: "16px",
                }}
              >
                {isExpanded ? "Show Less" : "View All"}
              </span>
              {isExpanded ? (
                <ChevronUp className="w-4 h-4" />
              ) : (
                <ChevronDown className="w-4 h-4" />
              )}
            </div>
          )}
        </div>
      </div>

      {/* Chart Content - Only shows when expanded */}
      {isExpanded && (
        <div className="flex-1 overflow-visible p-5 pt-0 min-h-[250px]">
          {children}
        </div>
      )}
    </div>
  );
};

export default ChartCard;
