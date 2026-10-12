// StatCard.js
"use client";

import React from "react";
import SmartTruncate from "@/components/ui/SmartTruncate";
import TechStackIcon from "@/components/common/TechStackIcon";
import { OVERVIEW_CARD_STYLE, OVERVIEW_DS } from "../designSystem";

const StatCard = ({
  label,
  value,
  icon: Icon,
  iconNode,
  iconName,
  iconVariant,
  color = "var(--color-primary)",
  status,
}) => {
  // Map color names to design system variables
  const getColorVariable = (inputColor) => {
    if (!inputColor) return "var(--color-primary)";
    if (inputColor.includes("var(")) return inputColor;

    const colorMap = {
      critical: "var(--critical)",
      high: "var(--high)",
      medium: "var(--medium)",
      low: "var(--low)",
      success: "var(--success)",
      warning: "var(--warning)",
      danger: "var(--danger)",
      info: "var(--info)",
      workflow: "var(--color-primary)",
      primary: "var(--color-primary)",
      secondary: "var(--color-secondary)",
      accent: "var(--color-accent)",
      "#EF4444": "var(--critical)",
      "#F97316": "var(--high)",
      "#EAB308": "var(--medium)",
      "#6366F1": "var(--low)",
      "#22C55E": "var(--success)",
      "#06B6D4": "var(--color-primary)",
    };

    return colorMap[inputColor] || inputColor;
  };

  const colorVar = getColorVariable(color);
  const resolvedIconNode = iconNode ||
    (iconName ? <TechStackIcon name={iconName} size={16} variant={iconVariant} /> : null);

  return (
    <div
      style={{
        boxSizing: "border-box",
        display: "flex",
        flexDirection: "row",
        alignItems: "center",
        padding: OVERVIEW_DS.spacing.x2,
        gap: "12px",
        width: "100%",
        minHeight: "98.75px",
        background: `color-mix(in srgb, ${colorVar} 4%, var(--surface))`,
        border: `1px solid color-mix(in srgb, ${colorVar} 15%, var(--border))`,
        borderRadius: OVERVIEW_DS.radius.lg,
        flex: "1 1 auto",
        transition: OVERVIEW_CARD_STYLE.transition,
        position: "relative",
        overflow: "hidden",
        boxShadow: "var(--shadow-2)",
      }}
      className="group hover:translate-y-[-2px] hover:shadow-xl"
    >
      {/* ICON AREA */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: "0",
          width: "36px",
          height: "36px",
          flexShrink: 0,
        }}
      >
        <div
          style={{
            boxSizing: "border-box",
            display: "flex",
            flexDirection: "row",
            justifyContent: "center",
            alignItems: "center",
            width: "36px",
            height: "36px",
            background: `color-mix(in srgb, ${colorVar} 4%, var(--surface))`,
            border: `1px solid color-mix(in srgb, ${colorVar} 15%, var(--border))`,
            borderRadius: "12px",
            transform: "translateZ(0)",
            backfaceVisibility: "hidden",
          }}
        >
          {resolvedIconNode || (
            <Icon
              style={{
                width: "18px",
                height: "18px",
                color: colorVar,
                shapeRendering: "geometricPrecision",
              }}
            />
          )}
        </div>
      </div>

      {/* CONTENT AREA */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-start",
          padding: "0px",
          gap: "2px",
          flex: "1 1 auto",
          minWidth: 0,
        }}
      >
        {/* VALUE CONTAINER */}
        <div
          style={{
            width: "100%",
            display: "flex",
            alignItems: "center",
          }}
        >
          <div
            style={{
              width: "100%",
              fontFamily: OVERVIEW_DS.typography.family,
              fontStyle: "normal",
              fontWeight: "700",
              fontSize: "28px",
              lineHeight: "1.1",
              color: "var(--text)",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            <SmartTruncate text={value?.toString()} type="auto" threshold={12} showIcon={false} />
          </div>
        </div>

        {/* LABEL CONTAINER */}
        <div
          style={{
            width: "100%",
          }}
        >
          <span
            style={{
              display: "block",
              fontFamily: OVERVIEW_DS.typography.family,
              fontStyle: "normal",
              fontWeight: "500",
              fontSize: OVERVIEW_DS.typography.label,
              lineHeight: "1.2",
              color: "var(--muted)",
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            {label}
          </span>
        </div>

        {/* OPTIONAL STATUS */}
        {status && (
          <div style={{
            fontSize: "10px",
            fontWeight: "500",
            color: "var(--success)",
            lineHeight: "1",
            marginTop: "2px"
          }}>
            {status}
          </div>
        )}
      </div>
    </div>
  );
};

export default StatCard;
