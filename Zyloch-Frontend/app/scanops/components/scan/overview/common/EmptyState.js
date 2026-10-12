import React from "react";
import SmartTruncate from "@/components/ui/SmartTruncate";
import { OVERVIEW_CARD_STYLE, OVERVIEW_DS } from "../designSystem";

const EmptyState = ({ title, message = "Start a new scan to find issues." }) => (
  <div
    className="flex min-h-[200px] flex-col items-center justify-center gap-1.5 p-6 text-center"
  >
    {title && (
      <h3 className="text-[15px] font-semibold text-[var(--text)]">
        {title}
      </h3>
    )}
    <div className="text-[var(--muted)] font-medium" style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.body }}>
      <SmartTruncate
        text={message}
        type="auto"
        className=""
        iconSize={12}
        threshold={60}
        showIcon={false}
      />
    </div>
  </div>
);

export default EmptyState;
