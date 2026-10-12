"use client";

import React from "react";
import { Loader2 } from "lucide-react";

export default function Loading() {
  return (
    <div className="flex flex-col items-center justify-center h-screen w-full bg-[var(--bg)] animate-fadeIn">

      {/* Glow Ring */}
      <div className="relative flex items-center justify-center">
        <div
          className="
            absolute w-32 h-32 rounded-full
            bg-[var(--color-primary)] 
            opacity-20 blur-2xl
            animate-pulse
          "
        ></div>

        {/* Main Loader */}
        <Loader2
          className="
            relative z-10
            w-20 h-20 
            text-[var(--color-primary)]
            animate-spin
            drop-shadow-[0_0_12px_var(--color-primary)]
          "
        />
      </div>

      {/* Title */}
      <h1 className="text-3xl font-semibold mt-8 tracking-tight text-[var(--text)]">
        Scan in Progress
      </h1>

      {/* Subtext */}
      <p className="text-sm mt-2 text-[var(--muted)]">
        Please wait while we update your data...
      </p>
    </div>
  );
}
