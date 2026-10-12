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
import ChartWrapper from "./ChartWrapper";
import { formatChartLabel } from "./labelFormatter";

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;

  const data = payload[0].payload;
  const value = data.value;
  const name = data.name;
  const formattedName = formatChartLabel(name);
  const color = data.color;

  return (
    <div className="bg-background/90 backdrop-blur-xl border border-border/50 rounded-lg px-3 py-2 shadow-xl">
      <div className="flex items-center gap-2 mb-1">
        <span
          className="w-2 h-2 rounded-full"
          style={{ backgroundColor: color }}
        />
        <span className="text-xs font-medium text-foreground">
          {formattedName}
        </span>
      </div>
      <div className="text-xl font-bold" style={{ color }}>
        {value.toLocaleString()} commits
      </div>
      {data.percentage && (
        <div className="text-xs text-muted-foreground mt-1">
          {data.percentage}% of total
        </div>
      )}
    </div>
  );
};

const renderActiveShape = (props) => {
  const {
    cx,
    cy,
    innerRadius,
    outerRadius,
    startAngle,
    endAngle,
    fill,
    payload,
    percent,
    value
  } = props;

  return (
    <g>
      {/* 3D Shadow Effect */}
      <Sector
        cx={cx + 3}
        cy={cy + 3}
        innerRadius={innerRadius}
        outerRadius={outerRadius}
        startAngle={startAngle}
        endAngle={endAngle}
        fill="rgba(0,0,0,0.1)"
      />
      
      {/* Main Segment with enhanced 3D look */}
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
        stroke="var(--background)"
        strokeWidth={3}
        className="transition-all duration-200"
        style={{
          filter: `drop-shadow(0 2px 8px ${fill}40)`,
        }}
      />
      
      {/* Inner Glow */}
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius + 2}
        outerRadius={innerRadius + 8}
        startAngle={startAngle}
        endAngle={endAngle}
        fill="rgba(255,255,255,0.3)"
      />
      
      {/* Top Highlight */}
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius - 2}
        startAngle={startAngle}
        endAngle={startAngle + (endAngle - startAngle) * 0.3}
        fill="rgba(255,255,255,0.2)"
      />
    </g>
  );
};

export default function DonutChart3D({
  data = [],
  dataKey = "value",
  nameKey = "name",
  colors = [],
  height = 280,
  innerRadius = 70,
  outerRadius = 100,
  showLegend = true,
  className = ""
}) {
  const [activeIndex, setActiveIndex] = useState(null);

  const onPieEnter = (_, index) => {
    setActiveIndex(index);
  };

  const onPieLeave = () => {
    setActiveIndex(null);
  };

  const chartColors = colors.length > 0 ? colors : [
    "var(--color-primary)",
    "var(--color-secondary)",
    "var(--color-accent)",
    "var(--info)",
    "var(--success)",
    "var(--warning)",
  ];

  // Calculate total and percentages
  const total = data.reduce((sum, item) => sum + item[dataKey], 0);
  const processedData = data.map((item, index) => ({
    ...item,
    color: chartColors[index % chartColors.length],
    percentage: ((item[dataKey] / total) * 100).toFixed(1)
  }));

  return (
    <div className={`relative w-full h-full ${className}`}>
      <ResponsiveContainer width="100%" height="100%" minHeight={height}>
        <PieChart>
          <Pie
            activeIndex={activeIndex}
            activeShape={renderActiveShape}
            data={processedData}
            dataKey={dataKey}
            nameKey={nameKey}
            cx="50%"
            cy="50%"
            innerRadius={innerRadius}
            outerRadius={outerRadius}
            paddingAngle={2}
            onMouseEnter={onPieEnter}
            onMouseLeave={onPieLeave}
          >
            {processedData.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={entry.color}
                stroke="var(--surface)"
                strokeWidth={3}
                opacity={activeIndex === index ? 1 : 0.9}
                className="transition-all duration-200 cursor-pointer"
              />
            ))}
          </Pie>
          
          <Tooltip
            content={<CustomTooltip />}
            cursor={false}
          />
          
          {showLegend && (
            <Legend
              wrapperStyle={{
                color: "var(--text)",
                fontSize: "12px",
                fontWeight: "500",
              }}
              iconType="circle"
              iconSize={10}
              formatter={(value) => {
                return (
                  <span style={{ color: "var(--text)", opacity: 0.8 }}>
                    {formatChartLabel(value)}
                  </span>
                );
              }}
            />
          )}
          
          {/* Center label */}
<text
  x="50%"
  y="45%"
  textAnchor="middle"
  fill="var(--color-primary)"
  fontSize="24"
  fontWeight="var(--weight-bold)"
  className="drop-shadow-sm"
>
  {total.toLocaleString()}
</text>
<text
  x="50%"
  y="55%"
  textAnchor="middle"
  fill="var(--muted)"
  fontSize="12"
  fontWeight="var(--weight-medium)"
>
  Total Commits
</text>
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}