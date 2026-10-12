// components/dashboard/EmptyState.jsx
import React from 'react';
import { CheckCircle2, RefreshCw } from 'lucide-react';

const EmptyState = ({ title = "No AI Security Issues Found", message = "No AI security issues were detected in this scan." }) => {
  const isProgress = String(title || "").toLowerCase().includes("in progress");

  return (
    <div className="flex h-full min-h-[350px] items-center justify-center p-8">
      <div className="text-center p-6 max-w-md flex flex-col items-center gap-3">
        {isProgress ? (
          <RefreshCw className="w-8 h-8 animate-spin text-[var(--color-primary)] mx-auto mb-2" />
        ) : (
          <CheckCircle2 className="w-12 h-12 text-success mx-auto mb-2" />
        )}
        <h2 className="text-lg font-semibold text-[var(--text)]">{title}</h2>
        <p className="text-sm text-[var(--muted)] leading-relaxed">{message}</p>
      </div>
    </div>
  );
};

export default EmptyState;