import React from "react";

const RiskBadge = ({ riskLevel, colorConfig }) => (
  <div
    className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border"
    style={{
      backgroundColor: `color-mix(in srgb, ${colorConfig.background} 15%, transparent)`,
      color: colorConfig.background,
      borderColor: `color-mix(in srgb, ${colorConfig.background} 30%, transparent)`
    }}
  >
    {riskLevel}
  </div>
);

export default RiskBadge;
