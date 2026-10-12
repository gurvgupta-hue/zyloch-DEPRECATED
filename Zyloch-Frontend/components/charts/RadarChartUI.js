// /components/ui/charts/RadarChartUI.jsx
"use client";
import React from "react";
import {
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Tooltip,
  Legend,
} from "recharts";

import { CHART_SERIES, ROOT_COLORS } from "@/lib/charts/chartColors";
import ChartWrapper from "./ChartWrapper";
import { formatChartLabel } from "./labelFormatter";

export default function RadarChartUI({
  data = [],
  dataKey = "value",
  nameKey = "subject",
  colors = CHART_SERIES,
  height = 320,
  showGlow = true
}) {
  return (
    <ChartWrapper minHeight={height}>
      <ResponsiveContainer width="100%" height={height}>
        <RadarChart cx="50%" cy="50%" outerRadius="75%" data={data}>
          
          {/* Light modern grid */}
          <PolarGrid
            stroke={ROOT_COLORS.border}
            strokeOpacity={0.3}
          />

          {/* Axis Labels */}
          <PolarAngleAxis
            dataKey={nameKey}
            tickFormatter={(value) => formatChartLabel(value)}
            tick={{
              fill: ROOT_COLORS.muted,
              fontSize: 12,
              fontWeight: 500,
            }}
          />

          <PolarRadiusAxis
            tick={{
              fill: ROOT_COLORS.muted,
              fontSize: 11,
            }}
            stroke={ROOT_COLORS.border}
          />

          {/* Custom Gradient */}
          <defs>
            <linearGradient id="radarGradient" x1="0" y1="0" x2="1" y2="1">
              <stop
                offset="0%"
                stopColor={colors[0]}
                stopOpacity={0.7}
              />
              <stop
                offset="100%"
                stopColor={colors[0]}
                stopOpacity={0.2}
              />
            </linearGradient>
          </defs>

          {/* Radar Shape */}
          <Radar
            name={dataKey}
            dataKey={dataKey}
            stroke={colors[0]}
            strokeWidth={2}
            fill="url(#radarGradient)"
            fillOpacity={0.8}
            style={{
              filter: showGlow ? `drop-shadow(0 4px 10px ${colors[0]}40)` : "none",
            }}
            animationBegin={200}
            animationDuration={900}
            animationEasing="ease-out"
          />

          {/* Custom Tooltip */}
          <Tooltip
            content={({ active, payload }) => {
              if (!active || !payload?.length) return null;
              return (
                <div
                  style={{
                    background: ROOT_COLORS.surface,
                    border: `1px solid ${ROOT_COLORS.border}`,
                    borderRadius: "var(--radius)",
                    padding: "10px 14px",
                    boxShadow: "0 8px 32px rgba(0,0,0,0.18)",
                    color: ROOT_COLORS.text,
                    fontSize: "13px",
                  }}
                >
                  <div style={{ fontWeight: 600, color: colors[0], marginBottom: 4 }}>
                    {formatChartLabel(payload[0].payload[nameKey])}
                  </div>
                  <div style={{ color: ROOT_COLORS.muted, fontSize: "12px" }}>
                    Value:{" "}
                    <span style={{ color: ROOT_COLORS.text, fontWeight: 600 }}>
                      {payload[0].value}
                    </span>
                  </div>
                </div>
              );
            }}
          />

          {/* Legend */}
          <Legend
            formatter={(value) => formatChartLabel(value)}
            wrapperStyle={{ color: ROOT_COLORS.muted, fontSize: "12px", fontWeight: "500" }}
            iconType="circle"
            iconSize={8}
          />
        </RadarChart>
      </ResponsiveContainer>
    </ChartWrapper>
  );
}
