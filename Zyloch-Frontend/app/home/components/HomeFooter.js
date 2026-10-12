"use client";

import React from "react";

export default function HomeFooter() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="w-full flex items-center justify-between gap-3 pt-4 border-t border-[var(--border-subtle)] text-[12px] font-medium text-[var(--muted)] shrink-0 transition-colors duration-200">
      <div>
        © {currentYear} Zyloch Security, Inc.
      </div>
      <div className="flex items-center gap-1">
        <span>Need help?</span>
        <a
          href="mailto:support@zyloch.com"
          className="font-semibold text-[var(--color-primary)] hover:underline"
        >
          Contact support
        </a>
      </div>
    </footer>
  );
}
