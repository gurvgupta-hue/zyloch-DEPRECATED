// /components/ui/charts/ComposedChartUI.jsx
"use client";
import React from "react";
import {
  ResponsiveContainer,
  ComposedChart,
  Line,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import { CHART_SERIES } from "@/lib/charts/chartColors";
import ChartWrapper from "./ChartWrapper";
import { formatChartLabel } from "./labelFormatter";

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

export default function ComposedChartUI({ data = [], barKey = "bar", lineKey = "line", nameKey = "name", colors = CHART_SERIES, height = 320 }) {
  return (
    <ChartWrapper minHeight={height}>
      <ResponsiveContainer width="100%" height={height}>
        <ComposedChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" strokeOpacity={0.5} />
          <XAxis dataKey={nameKey} tick={tickStyle} axisLine={false} tickLine={false} tickFormatter={(value) => formatChartLabel(value)} />
          <YAxis tick={tickStyle} axisLine={false} tickLine={false} />
          <Tooltip
            labelFormatter={(label) => formatChartLabel(label)}
            contentStyle={tooltipStyle}
            labelStyle={{ color: "var(--text)", fontWeight: 600 }}
            itemStyle={{ color: "var(--muted)" }}
            cursor={{ stroke: "var(--border)", strokeWidth: 1 }}
          />
          <Legend wrapperStyle={legendStyle} iconType="circle" iconSize={8} />
          <Bar dataKey={barKey} barSize={24} fill={colors[0]} fillOpacity={0.9} radius={[6, 6, 0, 0]} />
          <Line type="monotone" dataKey={lineKey} stroke={colors[1]} strokeWidth={2} dot={false} activeDot={{ r: 4, strokeWidth: 0 }} />
        </ComposedChart>
      </ResponsiveContainer>
    </ChartWrapper>
  );
}
