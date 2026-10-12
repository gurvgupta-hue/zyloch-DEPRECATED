"use client";

import React from "react";
import Link from "next/link";
import Image from "next/image";
import { useTheme } from "@/context/ThemeContext";
import LogoDark from "@/public/zyloch_logo.webp";
import LogoLight from "@/public/zyloch-black-logo.png";

export default function HomeHeader() {
  const { theme } = useTheme();

  return (
    <header className="w-full flex items-center justify-between pb-4 sm:pb-5 border-b border-[var(--border-subtle)] shrink-0 transition-colors duration-200">
      {/* Brand Logo with exact original asset */}
      <Link href="/home" className="flex items-center gap-3 group transition-transform hover:scale-[1.01]">
        <div className="relative h-8 w-32 flex items-center">
          <Image
            src={theme === "dark" ? LogoDark : LogoLight}
            alt="Zyloch"
            fill
            sizes="128px"
            className="object-contain object-left"
            priority
          />
        </div>
      </Link>

      {/* Purchase Complete Badge */}
      <div className="inline-flex items-center gap-2 px-[14px] py-2 rounded-full border border-[var(--badge-cyan-border)] bg-[var(--surface)] shadow-2xs">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--color-primary)] opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--color-primary)]" />
        </span>
        <span className="text-[11px] font-semibold text-[var(--color-primary)] uppercase tracking-[1.76px]">
          Purchase complete
        </span>
      </div>
    </header>
  );
}
