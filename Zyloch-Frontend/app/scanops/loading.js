import React from "react";
import { RefreshCw } from "lucide-react";

export default function ScanOpsLoading() {
  return (
    <div className="flex h-full min-h-[400px] flex-col items-center justify-center p-8">
      <div className="flex flex-col items-center gap-3">
        <div className="relative flex h-14 w-14 items-center justify-center rounded-2xl border border-[var(--border)] bg-[var(--surface)] shadow-md">
          <RefreshCw className="h-6 w-6 animate-spin text-[var(--color-primary)]" />
        </div>
        <p className="text-sm font-medium text-[var(--muted)]">Loading scan details...</p>
      </div>
    </div>
  );
}
