"use client";

import React, { useState, useEffect } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { formatChartLabel } from "./labelFormatter";

const LanguageBarChart3D = ({
  data = [],
  dataKey = "value",
  nameKey = "name",
  colors = null,
  className = "",
  height = 300,
}) => {
  const [hoveredBar, setHoveredBar] = useState(null);
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);
  }, []);

  const defaultColors = [
    "var(--color-primary)",
    "var(--color-secondary)",
    "var(--color-accent)",
    "var(--info)",
    "var(--success)",
  ];

  const chartColors = colors || defaultColors;

  // Sort data by value (descending)
  const sortedData = [...data].sort((a, b) => b[dataKey] - a[dataKey]);

  // Custom tooltip component
  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;

    const value = payload[0].value;
    const label = payload[0].payload[nameKey];
    const formattedLabel = formatChartLabel(label);
    const index = sortedData.findIndex(item => item[nameKey] === label);
    const color = chartColors[index % chartColors.length];

    return (
      <div
        style={{
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          padding: "10px 14px",
          boxShadow: "0 8px 32px rgba(0,0,0,0.18)",
          fontSize: "13px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <div
            style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: color }}
          />
          <span style={{ fontWeight: 500, color: "var(--text)" }}>
            {formattedLabel}
          </span>
        </div>
        <div style={{ fontSize: "18px", fontWeight: 700, color }}>
          {value}%
        </div>
      </div>
    );
  };

  // Custom bar component with 3D effect
  const CustomBar = ({ x, y, width, height, index, fill }) => {
    const isHovered = hoveredBar === index;

    return (
      <g>
        {/* Depth shadow (3D effect) */}
        <rect
          x={x}
          y={y + 4}
          width={width}
          height={height}
          rx={4}
          fill="var(--border)"
          fillOpacity={0.3}
        />

        {/* Main bar */}
        <rect
          x={x}
          y={y}
          width={width}
          height={height}
          rx={4}
          fill={fill}
          fillOpacity={isHovered ? 0.9 : 0.8}
          className="transition-all duration-200"
          onMouseEnter={() => setHoveredBar(index)}
          onMouseLeave={() => setHoveredBar(null)}
          style={{
            boxShadow: isHovered
              ? `0 4px 12px ${fill}40`
              : "none",
          }}
        />

        {/* Highlight on top */}
        <rect
          x={x + 2}
          y={y + 2}
          width={width - 4}
          height={2}
          rx={1}
          fill="rgba(255, 255, 255, 0.4)"
        />
      </g>
    );
  };

  if (data.length === 0) {
    return (
      <div className={`flex items-center justify-center h-full ${className}`}>
        <p className="text-[var(--muted)]">No data available</p>
      </div>
    );
  }

  return (
    <div className={`w-full ${className}`} style={{ height }}>
      {isClient && <ResponsiveContainer width="100%" height={height}>
        <BarChart
          data={sortedData}
          layout="vertical"
          margin={{ top: 8, right: 16, bottom: 8, left: 40 }}
        >
          <CartesianGrid
            stroke="var(--border)"
            strokeDasharray="3 3"
            horizontal={false}
          />

          <XAxis
            type="number"
            domain={[0, 100]}
            axisLine={false}
            tickLine={false}
            tick={{
              fill: "var(--muted)",
              fontSize: 11,
            }}
          />

          <YAxis
            type="category"
            dataKey={nameKey}
            axisLine={false}
            tickLine={false}
            tickFormatter={(value) => formatChartLabel(value)}
            tick={{
              fill: "var(--text)",
              fontSize: 12,
              fontWeight: 500,
            }}
          />

          <Tooltip
            content={<CustomTooltip />}
            cursor={false}
          />

          <Bar
            dataKey={dataKey}
            shape={<CustomBar />}
            animationDuration={800}
          >
            {sortedData.map((_, index) => (
              <Cell
                key={`cell-${index}`}
                fill={chartColors[index % chartColors.length]}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>}
    </div>
  );
};

export default LanguageBarChart3D;