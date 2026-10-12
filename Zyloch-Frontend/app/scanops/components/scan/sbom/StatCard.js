import React from "react";

const StatCard = ({ label, value, status, icon: Icon, color }) => (
  <div
    className="flex flex-col items-start p-6 gap-3 w-full bg-[var(--surface)] border border-[var(--border)] shadow-[var(--shadow-soft)] transition-all duration-300 hover:shadow-[var(--shadow-md)] group"
    style={{
      borderRadius: "var(--radius-lg)",
      height: "auto",
      borderLeft: `4px solid ${color}`
    }}
  >
    <div className="flex justify-between items-start w-full">
      <div
        className="flex items-center justify-center p-2 rounded-lg transition-colors duration-300"
        style={{ background: `color-mix(in srgb, ${color} 10%, transparent)` }}
      >
        <Icon size={20} style={{ color }} className="group-hover:scale-110 transition-transform duration-300" />
      </div>
      {status && (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider"
          style={{ background: `color-mix(in srgb, ${color} 10%, transparent)`, color }}>
          {status}
        </span>
      )}
    </div>
    <div className="flex flex-col gap-1">
      <span className="text-2xl font-bold tracking-tight text-[var(--text)] font-sans">{value}</span>
      <span className="text-xs font-semibold uppercase tracking-widest text-[var(--muted)] font-sans">{label}</span>
    </div>
  </div>
);

export default StatCard;
