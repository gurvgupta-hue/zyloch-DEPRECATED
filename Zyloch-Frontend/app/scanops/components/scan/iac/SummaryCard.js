// components/dashboard/SummaryCard.jsx
import React from 'react';

const SummaryCard = ({ label, value, icon: Icon, color }) => (
  <div
    className="group relative overflow-hidden rounded-2xl border border-default bg-surface p-4 shadow-1 transition-fast hover:shadow-2"
    style={{ "--card-accent": color }}
  >
    {/* Accent top bar */}
    <div
      className="absolute inset-x-0 top-0 h-[3px] rounded-t-2xl opacity-80"
      style={{ background: color }}
    />

    {/* Subtle hover glow */}
    <div
      className="pointer-events-none absolute inset-0 rounded-2xl opacity-0 transition-opacity duration-300 group-hover:opacity-100"
      style={{ background: `radial-gradient(ellipse at 50% 0%, ${color}14, transparent 70%)` }}
    />

    <div className="relative flex items-start justify-between gap-3">
      <div className="min-w-0">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-muted">{label}</p>
        <p className="mt-1.5 text-3xl font-bold tabular-nums text-text">{value ?? 0}</p>
      </div>
      <span
        className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl"
        style={{ background: `${color}20` }}
      >
        <Icon className="h-5 w-5" style={{ color }} />
      </span>
    </div>
  </div>
);

export default SummaryCard;