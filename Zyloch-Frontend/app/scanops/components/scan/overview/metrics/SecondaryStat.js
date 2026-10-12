// SecondaryStat.js
"use client";

import React from "react";
import SmartTruncate from "@/components/ui/SmartTruncate";

const SecondaryStat = ({ label, value, icon: Icon, color }) => (
  <div
    style={{
      width: "128px",
      height: "160px",
      opacity: 1,
      padding: "16px",
      borderRadius: "12px",
      border: `2px solid color-mix(in srgb, ${color} 25%, var(--border))`,
      backgroundColor: "var(--surface)",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      textAlign: "center",
      gap: "8px",
      boxShadow: "var(--shadow-1)",
      transition: "transform var(--transition-normal), box-shadow var(--transition-normal)",
    }}
    className="hover:translate-y-[-2px] hover:shadow-2"
  >
    {/* ICON - Top */}
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        marginBottom: "4px",
      }}
    >
      <div
        style={{
          backgroundColor: `color-mix(in srgb, ${color} 15%, var(--surface))`,
          padding: "12px",
          borderRadius: "10px",
          transition: "transform var(--transition-normal)",
        }}
        className="hover:scale-105 hover:rotate-3"
      >
        <Icon
          style={{
            color: color,
            width: "24px",
            height: "24px",
          }}
        />
      </div>
    </div>

    {/* LABEL - Middle */}
    <span
      style={{
        fontSize: "12px",
        fontWeight: "var(--weight-medium)",
        color: "var(--muted)",
        textAlign: "center",
        lineHeight: "1.4",
      }}
    >
      {label}
    </span>

    {/* VALUE - Bottom */}
    <div
      style={{
        fontSize: "16px",
        fontWeight: "var(--weight-semibold)",
        color: "var(--text)",
        textAlign: "center",
        lineHeight: "1.2",
        marginTop: "4px",
      }}
    >
      <SmartTruncate
        text={value?.toString()}
        type="auto"
        threshold={10}
        showIcon={false}
        iconSize={12}
      />
    </div>
  </div>
);

export default SecondaryStat;
