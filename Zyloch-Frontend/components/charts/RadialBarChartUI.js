// /components/ui/charts/RadialBarChartUI.jsx
"use client";
import React from "react";
import {
  ResponsiveContainer,
  RadialBarChart,
  RadialBar,
  Legend,
  Tooltip,
} from "recharts";

import { CHART_SERIES, ROOT_COLORS } from "@/lib/charts/chartColors";
import ChartWrapper from "./ChartWrapper";
import { formatChartLabel } from "./labelFormatter";

export default function RadialBarChartUI({
  data = [],
  dataKey = "value",
  nameKey = "name",
  colors = CHART_SERIES,
  height = 300,
  showGlow = true
}) {
  return (
    <ChartWrapper minHeight={height}>
      <ResponsiveContainer width="100%" height={height}>
        <RadialBarChart
          cx="50%"
          cy="50%"
          innerRadius="30%"
          outerRadius="90%"
          barSize={14}
          data={data}
        >
          {/* Custom Gradient */}
          <defs>
            {colors.map((color, index) => (
              <linearGradient
                key={index}
                id={`radialGradient-${index}`}
                x1="0"
                y1="0"
                x2="1"
                y2="1"
              >
                <stop offset="0%" stopColor={color} stopOpacity={0.95} />
                <stop offset="60%" stopColor={color} stopOpacity={0.7} />
                <stop offset="100%" stopColor={color} stopOpacity={0.45} />
              </linearGradient>
            ))}
          </defs>

          {/* Radial Bar */}
          <RadialBar
            clockWise
            dataKey={dataKey}
            cornerRadius={8}
            background={{
              fill: ROOT_COLORS.border,
              opacity: 0.25,
            }}
            fill={`url(#radialGradient-0)`}
            animationBegin={200}
            animationDuration={900}
            animationEasing="ease-out"
            style={{
              filter: showGlow ? `drop-shadow(0 4px 10px ${colors[0]}40)` : "none",
            }}
          />

          {/* Custom Tooltip */}
          <Tooltip
            content={({ active, payload }) => {
              if (!active || !payload?.length) return null;
              const item = payload[0];
              const color = item.fill || colors[item.index % colors.length] || colors[0];
              return (
                <div
                  style={{
                    background: ROOT_COLORS.surface,
                    border: `1px solid ${ROOT_COLORS.border}`,
                    borderRadius: "var(--radius)",
                    padding: "10px 14px",
                    boxShadow: "0 8px 32px rgba(0,0,0,0.18)",
                    fontSize: "13px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: color }} />
                    <span style={{ fontWeight: 600, color: ROOT_COLORS.text }}>{formatChartLabel(item.payload[nameKey])}</span>
                  </div>
                  <div style={{ color: ROOT_COLORS.muted, fontSize: "12px" }}>
                    Value:{" "}
                    <span style={{ color: ROOT_COLORS.text, fontWeight: 600 }}>{item.value}</span>
                  </div>
                </div>
              );
            }}
          />

          {/* Legend */}
          <Legend
            layout="horizontal"
            verticalAlign="bottom"
            align="center"
            formatter={(value) => formatChartLabel(value)}
            wrapperStyle={{ color: ROOT_COLORS.muted, fontSize: "12px", fontWeight: "500" }}
            iconType="circle"
            iconSize={8}
          />
        </RadialBarChart>
      </ResponsiveContainer>
    </ChartWrapper>
  );
}
