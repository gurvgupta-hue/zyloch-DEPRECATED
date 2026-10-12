// /components/ui/charts/ChartWrapper.jsx
import React from "react";

export default function ChartWrapper({ children, className = "", minHeight = 220 }) {
  return (
    <div
      className={`w-full flex justify-center items-center ${className}`.trim()}
      style={{ minHeight }}
    >
      {children}
    </div>
  );
}
