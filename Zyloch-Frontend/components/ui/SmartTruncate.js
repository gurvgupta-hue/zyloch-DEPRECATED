"use client";

import React, { useState } from "react";
import { createPortal } from "react-dom";
import { Eye } from "lucide-react";

export const smartTruncate = (text, threshold = 27) => {
  if (!text || text.length <= threshold) return text || "N/A";
  return `${text.slice(0, threshold - 3)}...`;
};

const SmartTruncate = ({
  text,
  threshold = 20,
  className = "",
  iconSize = 12,
  tooltipTitle = "Full content",
  showTooltip = true,
  ...rest
}) => {
  const [isTooltipVisible, setIsTooltipVisible] = useState(false);
  const [coords, setCoords] = useState({ x: 0, y: 0 });

  const safeProps = Object.fromEntries(
    Object.entries(rest).filter(([key]) =>
      key.startsWith("data-") || key.startsWith("aria-")
    )
  );

  const shouldTruncate = text && text.length > threshold;
  const displayText = shouldTruncate ? smartTruncate(text, threshold) : text;

  if (!text) return <span className={className}>N/A</span>;

  const handleHover = (e) => {
    const rect = e.target.getBoundingClientRect();
    setCoords({
      x: rect.right,     // ⭐ start at the RIGHT of the element
      y: rect.bottom,    // ⭐ start at the BOTTOM of the element
    });
    setIsTooltipVisible(true);
  };

  const triggerContent = (
    <div className={`inline-flex items-center gap-1 ${className}`}>
      <span className="truncate">{displayText}</span>

      {shouldTruncate && (
        <Eye
          size={iconSize}
          className="text-[var(--muted)] flex-shrink-0 cursor-pointer"
          onMouseEnter={handleHover}
          onMouseLeave={() => setIsTooltipVisible(false)}
        />
      )}
    </div>
  );

  if (!shouldTruncate || !showTooltip) return triggerContent;

  return (
    <>
      <span {...safeProps}>{triggerContent}</span>

      {isTooltipVisible &&
        createPortal(
          <div
            className="
              fixed z-[9999]
              bg-[var(--bg)] border border-[var(--border)]
              rounded-lg shadow-xl p-3
              w-[260px] pointer-events-none
            "
            style={{
              top: coords.y + 6,   // ⭐ small gap below element
              right: window.innerWidth - coords.x + 6,  // ⭐ small gap to the right
            }}
          >
            <div className="text-xs font-medium text-[var(--text)] mb-1">
              {tooltipTitle}:
            </div>

            <div className="text-sm text-[var(--muted)] font-mono break-all">
              {text}
            </div>
          </div>,
          document.body
        )}
    </>
  );
};

export default SmartTruncate;
