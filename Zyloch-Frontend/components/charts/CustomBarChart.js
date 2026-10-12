// components/charts/CustomBarChart.jsx
import React from 'react';

const CustomBarChart = ({
  data = [],
  barHeight = 20,
  gap = 12,
  labelWidth = 72,
}) => {
  const maxValue = Math.max(...data.map(item => item.value), 1);

  return (
    <div
      className="w-full"
      style={{
        padding: '16px',
        borderRadius: 'var(--radius)',
        border: '1px solid var(--border)',
        background: 'var(--surface)',
      }}
    >
      <div className="flex flex-col" style={{ gap: `${gap}px` }}>
        {data.map((item, index) => (
          <div key={index} className="flex items-center" style={{ height: `${barHeight}px` }}>
            {/* Label */}
            <div
              className="shrink-0 text-right pr-2 text-sm font-medium"
              style={{ width: `${labelWidth}px`, color: 'var(--muted)', fontSize: '12px' }}
            >
              {item.label}
            </div>

            {/* Bar + value */}
            <div className="flex items-center gap-2 flex-1 min-w-0">
              {item.value > 0 && (
                <div
                  className="rounded transition-all duration-300 ease-in-out shrink-0"
                  style={{
                    width: `${(item.value / maxValue) * 100}%`,
                    height: `${barHeight}px`,
                    backgroundColor: item.color || 'var(--color-primary)',
                    opacity: 0.9,
                  }}
                />
              )}
              <span
                className="text-sm font-medium shrink-0"
                style={{ color: 'var(--text)', fontSize: '12px' }}
              >
                {item.hasData ? item.displayValue : '-'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default CustomBarChart;