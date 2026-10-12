// /components/ui/charts/AreaChartUI.jsx
"use client";
import React from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
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

export default function AreaChartUI({ data = [], series = [{ key: "value", name: "Value" }], colors = CHART_SERIES, height = 300 }) {
  return (
    <ChartWrapper minHeight={height}>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
          <defs>
            {series.map((s, i) => (
              <linearGradient key={s.key} id={`areaGrad-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={colors[i % colors.length]} stopOpacity={0.35} />
                <stop offset="95%" stopColor={colors[i % colors.length]} stopOpacity={0.03} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" strokeOpacity={0.5} />
          <XAxis dataKey="name" tick={tickStyle} axisLine={false} tickLine={false} tickFormatter={(value) => formatChartLabel(value)} />
          <YAxis tick={tickStyle} axisLine={false} tickLine={false} />
          <Tooltip
            labelFormatter={(label) => formatChartLabel(label)}
            contentStyle={tooltipStyle}
            labelStyle={{ color: "var(--text)", fontWeight: 600 }}
            itemStyle={{ color: "var(--muted)" }}
            cursor={{ stroke: "var(--border)", strokeWidth: 1 }}
          />
          <Legend wrapperStyle={legendStyle} iconType="circle" iconSize={8} />
          {series.map((s, i) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.name || s.key}
              stroke={colors[i % colors.length]}
              strokeWidth={2}
              fill={`url(#areaGrad-${s.key})`}
              dot={false}
              activeDot={{ r: 4, strokeWidth: 0 }}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </ChartWrapper>
  );
}
