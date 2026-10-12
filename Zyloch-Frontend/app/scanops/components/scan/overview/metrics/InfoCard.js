"use client";

import React from "react";
import SmartTruncate from "@/components/ui/SmartTruncate";
import { OVERVIEW_DS } from "../designSystem";

const InfoCard = ({ label, value, icon, type = "default" }) => (
  <div
    className="flex flex-col items-start gap-2"
    style={{
      "--info-card-label-color": "var(--muted)",
      "--info-card-value-color": "var(--text)",
      "--info-card-icon-color": OVERVIEW_DS.colors.primary,
    }}
  >
    {/* Label Row */}
    <div className="flex items-center gap-1.5">
      {icon && (
        <span className="inline-flex h-4 w-4 items-center justify-center text-[var(--info-card-icon-color)] [&_svg]:h-3.5 [&_svg]:w-3.5">
          {icon}
        </span>
      )}
      <span
        className="font-medium text-[var(--info-card-label-color)]"
        style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.label }}
      >
        {label}
      </span>
    </div>

    {/* VALUE */}
    <div className="min-w-0">
      {typeof value === "string" || typeof value === "number" ? (
        <SmartTruncate
          text={String(value)}
          type={type}
          threshold={25}
          showIcon={false}
          className="font-semibold leading-tight text-[var(--info-card-value-color)]"
          style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.body }}
        />
      ) : (
        value
      )}
    </div>
  </div>
);

export default InfoCard;
