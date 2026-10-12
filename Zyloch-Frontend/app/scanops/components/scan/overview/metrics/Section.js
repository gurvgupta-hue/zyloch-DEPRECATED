"use client";

import React from "react";
import { OVERVIEW_CARD_STYLE, OVERVIEW_DS } from "../designSystem";

const Section = ({ title, subtitle, children }) => (
  <div
    style={{
      position: "relative",
      ...OVERVIEW_CARD_STYLE,
      padding: OVERVIEW_DS.spacing.x3,
    }}
  >
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "var(--space-4)",
      }}
    >
      {(title || subtitle) && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "var(--space-2)",
          }}
        >
          {title && (
            <h2
              style={{
                fontFamily: OVERVIEW_DS.typography.family,
                fontSize: OVERVIEW_DS.typography.headingSm,
                lineHeight: "28px",
                fontWeight: "700",
                color: "var(--text)",
                margin: 0,
              }}
            >
              {title}
            </h2>
          )}
          {subtitle && (
            <p
              style={{
                fontFamily: OVERVIEW_DS.typography.family,
                fontSize: OVERVIEW_DS.typography.body,
                lineHeight: OVERVIEW_DS.typography.bodyLineHeight,
                color: "var(--muted)",
                margin: 0,
              }}
            >
              {subtitle}
            </p>
          )}
        </div>
      )}
      {children}
    </div>
  </div>
);

export default Section;
