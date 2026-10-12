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

export default function HorizontalBarChart3D({
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
  barSize = 30,
  showGlow = false,
  showLegend = false,
  showGrid = true,
  borderRadius = 6,
  title,
  subtitle,
  yAxisWidth = 100,
}) {
  const [isClient, setIsClient] = useState(false);
  const [chartData, setChartData] = useState([]);
  const [hoveredBar, setHoveredBar] = useState(null);

  useEffect(() => {
    setIsClient(true);

    if (Array.isArray(data)) {
      const processed = data.map((item) => ({
        ...item,
        [dataKey]: Number(item[dataKey]) || 0,
      }));

      setChartData(processed);
    }
  }, [data, dataKey]);

  const CustomBar = (props) => {
    const { x, y, width, height: barHeight, index, fill } = props;

    const barLength = Math.max(0, width || 0);
    const isHovered = hoveredBar === index;

    if (barLength <= 0) return null;

    return (
      <g>
        {/* Shadow */}
        <rect
          x={x + 4}
          y={y + 4}
          width={barLength}
          height={barHeight}
          fill="var(--border)"
          fillOpacity={0.25}
          rx={borderRadius}
        />

        {/* Main Bar */}
        <rect
          x={x}
          y={y}
          width={barLength}
          height={barHeight}
          fill={fill}
          fillOpacity={isHovered ? 1 : 0.9}
          rx={borderRadius}
          className="transition-all duration-300"
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

        {/* Highlight */}
        {barLength > 6 && (
          <rect
            x={x + barLength - 3}
            y={y + 2}
            width={2}
            height={barHeight - 4}
            fill="rgba(255,255,255,0.35)"
            rx={Math.max(0, borderRadius - 1)}
          />
        )}
      </g>
    );
  };

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;

    const value = payload[0].value;
    const itemName = payload[0].payload[nameKey];
    const formattedItemName = formatChartLabel(itemName);

    const index = chartData.findIndex((d) => d[nameKey] === itemName);
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
          fontFamily: "'SF Pro', var(--font-ui)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <span
            style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", backgroundColor: color }}
          />
          <span style={{ fontSize: "11px", letterSpacing: "0.05em", color: "var(--muted)" }}>
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

  if (!chartData.length)
    return (
      <ChartWrapper minHeight={height}>
        <div className="flex items-center justify-center h-full text-[var(--muted)]">
          No chart data available
        </div>
      </ChartWrapper>
    );

  return (
    <ChartWrapper minHeight={height}>
      {title && (
        <div className="mb-3">
          <h3 className="text-xl font-semibold" style={{ color: "var(--text)" }}>{title}</h3>
          {subtitle && <p className="text-sm mt-1" style={{ color: "var(--muted)" }}>{subtitle}</p>}
        </div>
      )}

      <ResponsiveContainer width="100%" height={height - (title ? 40 : 0)}>
        <BarChart
          data={chartData}
          layout="vertical"
          margin={{ top: 10, right: 20, left: 10, bottom: 5 }}
          barSize={barSize}
        >
          {showGrid && (
            <CartesianGrid
              stroke="var(--border)"
              strokeDasharray="4 3"
              horizontal={false}
              vertical={true}
            />
          )}

          <XAxis
            type="number"
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--muted)", fontSize: 12, fontFamily: "'SF Pro', var(--font-ui)" }}
            domain={[0, "dataMax"]}
          />

          <YAxis
            type="category"
            dataKey={nameKey}
            axisLine={false}
            tickLine={false}
            width={yAxisWidth}
            tickFormatter={(value) => formatChartLabel(value)}
            tick={{
              fill: "var(--text)",
              fontSize: 13,
              fontWeight: 600,
              fontFamily: "'SF Pro', var(--font-ui)",
            }}
          />

          <Tooltip content={<CustomTooltip />} cursor={false} />

          {showLegend && <Legend wrapperStyle={{ fontFamily: "'SF Pro', var(--font-ui)" }} />}

          <Bar
            dataKey={dataKey}
            shape={(props) => <CustomBar {...props} />}
            animationDuration={900}
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