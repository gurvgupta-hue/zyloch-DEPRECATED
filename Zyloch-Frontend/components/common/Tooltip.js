"use client";
import React, { useState, useRef } from "react";

export default function Tooltip({
  children,
  content,
  placement = "top",
  delay = 200,
  className = "",
  ...props
}) {
  const [visible, setVisible] = useState(false);
  const timerRef = useRef(null);

  const placements = {
    top: "bottom-full left-1/2 -translate-x-1/2 mb-2",
    bottom: "top-full left-1/2 -translate-x-1/2 mt-2",
    left: "right-full top-1/2 -translate-y-1/2 mr-2",
    right: "left-full top-1/2 -translate-y-1/2 ml-2",
  };

  const handleMouseEnter = () => {
    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setVisible(true), delay);
  };

  const handleMouseLeave = () => {
    clearTimeout(timerRef.current);
    setVisible(false);
  };

  return (
    <div
      className={`relative inline-block ${className}`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      {...props}
    >
      {children}

      {visible && (
        <div
          className={`
            absolute
            z-tooltip
            bg-surface
            text
            border border-border
            rounded-md
            shadow-2
            whitespace-nowrap
            animate-fadeIn
            ${placements[placement]}
          `}
          style={{
            padding: "var(--space-2) var(--space-3)",
            transition: "opacity var(--transition-fast)",
          }}
        >
          {content}
        </div>
      )}
    </div>
  );
}
