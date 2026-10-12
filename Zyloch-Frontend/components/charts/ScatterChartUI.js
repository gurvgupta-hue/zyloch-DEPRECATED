// /components/ui/charts/ScatterChartUI.jsx
"use client";
import React from "react";
import { ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from "recharts";
import { CHART_SERIES } from "@/lib/charts/chartColors";
import ChartWrapper from "./ChartWrapper";

const tooltipStyle = {
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  color: "var(--text)",
  fontSize: "13px",
  boxShadow: "0 8px 32px rgba(0,0,0,0.18)",
};

const tickStyle = { fill: "var(--muted)", fontSize: 12 };
const legendStyle = { color: "var(--muted)", fontSize: "12px", fontWeight: "500" };

export default function ScatterChartUI({ data = [], xKey = "x", yKey = "y", colors = CHART_SERIES, height = 320 }) {
  return (
    <ChartWrapper minHeight={height}>
      <ResponsiveContainer width="100%" height={height}>
        <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" strokeOpacity={0.5} />
          <XAxis dataKey={xKey} tick={tickStyle} axisLine={false} tickLine={false} />
          <YAxis dataKey={yKey} tick={tickStyle} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={tooltipStyle}
            labelStyle={{ color: "var(--text)", fontWeight: 600 }}
            itemStyle={{ color: "var(--muted)" }}
            cursor={{ strokeDasharray: "3 3", stroke: "var(--border)" }}
          />
          <Legend wrapperStyle={legendStyle} iconType="circle" iconSize={8} />
          <Scatter name="points" data={data} fill={colors[0]} fillOpacity={0.85} />
        </ScatterChart>
      </ResponsiveContainer>
    </ChartWrapper>
  );
}

