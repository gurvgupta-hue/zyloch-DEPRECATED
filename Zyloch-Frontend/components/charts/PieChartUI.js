"use client";

import React, { useState } from "react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  Sector
} from "recharts";

import { CHART_SERIES, ROOT_COLORS } from "@/lib/charts/chartColors";
import ChartWrapper from "./ChartWrapper";
import { formatChartLabel } from "./labelFormatter";

/* ---------- 3D Active Slice ---------- */
const renderActiveShape = (props) => {
  const {
    cx,
    cy,
    innerRadius,
    outerRadius,
    startAngle,
    endAngle,
    fill
  } = props;

  return (
    <g>
      {/* Shadow */}
      <Sector
        cx={cx + 3}
        cy={cy + 3}
        innerRadius={innerRadius}
        outerRadius={outerRadius}
        startAngle={startAngle}
        endAngle={endAngle}
        fill="rgba(0,0,0,0.15)"
      />

      {/* Main slice */}
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius + 4}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
        stroke={ROOT_COLORS.surface}
        strokeWidth={3}
        style={{
          filter: `drop-shadow(0 4px 10px ${fill}40)`
        }}
      />
    </g>
  );
};

export default function PieChart3D({
  data = [],
  dataKey = "value",
  nameKey = "name",
  colors = CHART_SERIES,
  height = 340,
  showCenterText = true,
  innerRadius,
  outerRadius,
  showLegend = true
}) {
  const [activeIndex, setActiveIndex] = useState(null);

  const total = data.reduce((sum, d) => sum + d[dataKey], 0);
  
  // Calculate default radii based on height if not provided
  const derivedInner = innerRadius || Math.floor(height * 0.2);
  const derivedOuter = outerRadius || Math.floor(height * 0.35);

  return (
    <ChartWrapper minHeight={height}>
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          {/* No gradients to avoid clipping issues in small containers */}

          <Pie
            data={data}
            dataKey={dataKey}
            nameKey={nameKey}
            cx="50%"
            cy="50%"
            innerRadius={derivedInner}
            outerRadius={derivedOuter}
            paddingAngle={2}
            activeIndex={activeIndex}
            activeShape={renderActiveShape}
            onMouseEnter={(_, i) => setActiveIndex(i)}
            onMouseLeave={() => setActiveIndex(null)}
          >
            {data.map((entry, i) => {
              const gradId = `pieGrad-${entry[nameKey]}-${i}`;
              return (
                <Cell
                  key={`cell-${entry[nameKey]}-${i}`}
                  fill={entry.color || colors[i % colors.length]}
                  stroke={ROOT_COLORS.surface}
                  strokeWidth={2} // Reduced stroke for smaller charts
                  opacity={activeIndex === i ? 1 : 0.9}
                  className="transition-all duration-200 cursor-pointer"
                />
              );
            })}
          </Pie>

          {/* Tooltip */}
          <Tooltip
            cursor={false}
            labelFormatter={(label) => formatChartLabel(label)}
            formatter={(value, name) => [value, formatChartLabel(name)]}
            contentStyle={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              color: "var(--text)",
              fontSize: "13px",
              fontFamily: "'SF Pro', var(--font-ui)",
              boxShadow: "0 8px 32px rgba(0,0,0,0.18)",
            }}
            labelStyle={{ color: "var(--text)", fontWeight: 600, fontFamily: "'SF Pro', var(--font-ui)" }}
            itemStyle={{ color: "var(--muted)", fontFamily: "'SF Pro', var(--font-ui)" }}
          />

          {/* Legend */}
          {showLegend && (
            <Legend
              iconType="circle"
              iconSize={8}
              formatter={(value) => formatChartLabel(value)}
              wrapperStyle={{ 
                fontFamily: "'SF Pro', var(--font-ui)",
                color: "var(--muted)", 
                fontSize: "12px", 
                fontWeight: "500" 
              }}
            />
          )}

          {showCenterText && (
            <>
              <text
                x="50%"
                y="47%"
                textAnchor="middle"
                fontSize="22"
                fontWeight="600"
                fill="var(--color-primary)"
                style={{ fontFamily: "'SF Pro', var(--font-ui)" }}
              >
                {total.toLocaleString()}
              </text>
              <text
                x="50%"
                y="57%"
                textAnchor="middle"
                fontSize="12"
                fill="var(--muted)"
                style={{ fontFamily: "'SF Pro', var(--font-ui)" }}
              >
                Total
              </text>
            </>
          )}
        </PieChart>
      </ResponsiveContainer>
    </ChartWrapper>
  );
}
