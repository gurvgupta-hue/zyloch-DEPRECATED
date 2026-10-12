"use client";
import React, { useState, useEffect } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Cell,
} from "recharts";
import ChartWrapper from "./ChartWrapper";
import { formatChartLabel } from "./labelFormatter";

export default function BarChart3D({
  data = [],
  dataKey = "value",
  nameKey = "name",
  colors = [
    "var(--color-primary)",
    "var(--color-secondary)",
    "var(--color-accent)",
    "var(--info)",
    "var(--success)",
  ],
  height = 340,
  barSize = 60,
  showGlow = false,
  showLegend = false,
  showGrid = true,
  borderRadius = 6,
  title,
  subtitle,
}) {
  const [isClient, setIsClient] = useState(false);
  const [chartData, setChartData] = useState([]);
  const [hoveredBar, setHoveredBar] = useState(null);

  useEffect(() => {
    setIsClient(true);
    if (data && Array.isArray(data)) {
      const sorted = [...data]
        .map((item) => ({
          ...item,
          [dataKey]: Number(item[dataKey]) || 0,
        }))
        .sort((a, b) => b[dataKey] - a[dataKey]);
      setChartData(sorted);
    }
  }, [data, dataKey]);

  const CustomBar = (props) => {
    const { x, y, width, height: barHeight, index, fill } = props;
    const isHovered = hoveredBar === index;

    // Increased multiplier for wider bars
    const barWidth = Math.max(0, width * 1.3); // Changed from 1.2 to 1.3
    const adjustedX = x - (barWidth - width) / 2;
    const safeHeight = Math.max(0, barHeight);

    if (barWidth <= 0 || safeHeight <= 0) return null;

    return (
      <g>
        {/* Depth shadow */}
        <rect
          x={adjustedX + 4}
          y={y + 4}
          width={barWidth}
          height={safeHeight}
          fill="var(--border)"
          fillOpacity={0.25}
        />

        {/* Main bar body - NO radius */}
        <rect
          x={adjustedX}
          y={y}
          width={barWidth}
          height={safeHeight}
          fill={fill}
          fillOpacity={isHovered ? 1 : 0.9}
          className="transition-all duration-300 ease-out"
          style={{
            filter: isHovered
              ? `drop-shadow(0 8px 16px ${fill}55)`
              : showGlow
              ? "drop-shadow(0 3px 6px rgba(0,0,0,0.15))"
              : "none",
          }}
          onMouseEnter={() => setHoveredBar(index)}
          onMouseLeave={() => setHoveredBar(null)}
        />

        {/* Top cap with radius - this is the ONLY rounded part */}
        <rect
          x={adjustedX}
          y={y}
          width={barWidth}
          height={4} // Thin top surface
          rx={borderRadius}
          fill={fill}
          fillOpacity={isHovered ? 1 : 0.9}
        />

        {/* Top gloss highlight on rounded cap */}
        <rect
          x={adjustedX + 2}
          y={y + 1}
          width={barWidth - 4}
          height={2}
          rx={Math.max(0, borderRadius - 1)}
          fill="rgba(255,255,255,0.35)"
        />
      </g>
    );
  };

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;

    const value = payload[0].value;
    const itemName = payload[0].payload[nameKey];
    const formattedItemName = formatChartLabel(itemName);
    const index = chartData.findIndex((item) => item[nameKey] === itemName);
    const color = colors[index % colors.length];

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
          <span
            style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", backgroundColor: color }}
          />
          <span style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--muted)" }}>
            {formattedItemName}
          </span>
        </div>
        <div style={{ fontSize: "20px", fontWeight: 700, color }}>
          {value}
        </div>
      </div>
    );
  };

  if (!isClient) return null;

  if (!chartData || chartData.length === 0)
    return (
      <ChartWrapper minHeight={height}>
        <div className="flex items-center justify-center h-full text-[var(--muted)]">
          No chart data available
        </div>
      </ChartWrapper>
    );

  return (
    <ChartWrapper minHeight={height} className="p-4">
      {title && (
        <div className="mb-4">
          <h3 className="text-xl font-semibold" style={{ color: "var(--text)" }}>
            {title}
          </h3>
          {subtitle && (
            <p className="text-sm mt-1" style={{ color: "var(--muted)" }}>{subtitle}</p>
          )}
        </div>
      )}

      <ResponsiveContainer width="100%" height={height}>
        <BarChart
          data={chartData}
          layout="horizontal"
          margin={{ top: 10, right: 10, left: 10, bottom: 10 }}
          // FIXED: Removed barCategoryGap to prevent width conflicts
          // Using only barSize to control bar width
          barGap={0}
          barSize={barSize}
        >
          {showGrid && (
            <CartesianGrid
              stroke="var(--border)"
              strokeDasharray="4 3"
              vertical={false}
            />
          )}

          <XAxis
            type="category"
            dataKey={nameKey}
            axisLine={false}
            tickLine={false}
            tickFormatter={(value) => formatChartLabel(value)}
            tick={{
              fill: "var(--text)",
              fontSize: 13,
              fontWeight: 600,
              fontFamily: "'SF Pro', var(--font-ui)",
            }}
            padding={{ left: 10, right: 10 }}
          />

          <YAxis
            type="number"
            axisLine={false}
            tickLine={false}
            tick={{
              fill: "var(--muted)",
              fontSize: 12,
              fontFamily: "'SF Pro', var(--font-ui)",
            }}
          />

          <Tooltip content={<CustomTooltip />} cursor={false} />

          {showLegend && <Legend wrapperStyle={{ fontFamily: "'SF Pro', var(--font-ui)", color: "var(--muted)" }} />}

          <Bar
            dataKey={dataKey}
            shape={(props) => <CustomBar {...props} />}
            barSize={barSize}
            isAnimationActive={true}
            animationDuration={900}
            animationEasing="ease-out"
          >
            {chartData.map((_, index) => (
              <Cell
                key={`cell-${index}`}
                fill={colors[index % colors.length]}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartWrapper>
  );
}