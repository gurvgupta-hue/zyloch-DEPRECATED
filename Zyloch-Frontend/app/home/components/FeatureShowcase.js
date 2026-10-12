"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import RepoIntelligenceIcon from "@/public/assets/icons/scan/installation/repo-intelligence.svg";
import SecretDetectionIcon from "@/public/assets/icons/scan/installation/secret-detection.svg";
import SBOMIcon from "@/public/assets/icons/scan/installation/sbom.svg";
import AIScannerIcon from "@/public/assets/icons/scan/installation/ai-scanner.svg";
import DependencyAnalysisIcon from "@/public/assets/icons/scan/installation/dependency-analysis.svg";
import PrioritizedFixesIcon from "@/public/assets/icons/scan/installation/prioritized-fixes.svg";
import CheckIcon from "@/public/assets/icons/scan/installation/check.svg";

export const slides = [
  {
    id: "repo-intelligence",
    badge: "REPO INTELLIGENCE",
    badgeBg: "var(--badge-cyan-bg)",
    badgeColor: "var(--badge-cyan-text)",
    badgeBorder: "var(--badge-cyan-border)",
    iconBg: "var(--badge-cyan-bg)",
    iconColor: "var(--color-primary)",
    statValue: "142",
    statColor: "var(--color-primary)",
    statLabel: "REPOS INDEXED",
    title: "Every repository, one view",
    description:
      "Live inventory across every connected workspace — source code, dependencies, and active maintainers — so nothing slips through.",
    icon: RepoIntelligenceIcon,
    renderPreview: () => (
      <div className="rounded-[16px] border border-[var(--border-subtle)] bg-[var(--surface)] overflow-hidden text-xs shadow-xs">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)]">
          <span className="font-bold text-[11px] text-[var(--color-primary)] uppercase tracking-wider">
            REPOSITORY INTELLIGENCE
          </span>
          <span className="text-[11px] text-[var(--muted)] hover:text-[var(--color-primary)] font-medium cursor-pointer transition-colors">
            View All →
          </span>
        </div>

        {/* Rows */}
        <div className="divide-y divide-[var(--border-subtle)]">
          <div className="flex items-center justify-between px-4 py-2.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <div className="flex items-center gap-3">
              <span className="w-5 h-5 rounded-[4px] flex items-center justify-center bg-[var(--elevated-surface)] text-[10px] font-bold text-[var(--text-secondary)] shrink-0 border border-[var(--border-subtle)]">
                F
              </span>
              <span className="font-semibold text-[var(--text)]">payment-api</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[var(--muted)] text-xs font-normal">Platform Team</span>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-[var(--badge-red-bg)] text-[var(--badge-red-text)] border border-[var(--badge-red-border)]">
                High
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between px-4 py-2.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <div className="flex items-center gap-3">
              <span className="w-5 h-5 rounded-[4px] flex items-center justify-center bg-[var(--elevated-surface)] text-[10px] font-bold text-[var(--text-secondary)] shrink-0 border border-[var(--border-subtle)]">
                F
              </span>
              <span className="font-semibold text-[var(--text)]">user-portal</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[var(--muted)] text-xs font-normal">Product Team</span>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-[var(--badge-yellow-bg)] text-[var(--badge-yellow-text)] border border-[var(--badge-yellow-border)]">
                Medium
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between px-4 py-2.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <div className="flex items-center gap-3">
              <span className="w-5 h-5 rounded-[4px] flex items-center justify-center bg-[var(--elevated-surface)] text-[10px] font-bold text-[var(--text-secondary)] shrink-0 border border-[var(--border-subtle)]">
                F
              </span>
              <span className="font-semibold text-[var(--text)]">ai-assistant</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[var(--muted)] text-xs font-normal">AI Team</span>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-[var(--badge-red-bg)] text-[var(--badge-red-text)] border border-[var(--badge-red-border)]">
                High
              </span>
            </div>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: "secrets-detection",
    badge: "SECRETS DETECTION",
    badgeBg: "var(--badge-red-bg)",
    badgeColor: "var(--badge-red-text)",
    badgeBorder: "var(--badge-red-border)",
    iconBg: "var(--badge-red-bg)",
    iconColor: "var(--critical)",
    statValue: "38",
    statColor: "var(--critical)",
    statLabel: "OPEN FINDINGS",
    title: "Exposed credentials found fast",
    description:
      "Scans every commit and file for leaked API keys, tokens, and passwords before they reach production.",
    icon: SecretDetectionIcon,
    renderPreview: () => (
      <div className="rounded-[16px] border border-[var(--border-subtle)] bg-[var(--surface)] overflow-hidden text-xs shadow-xs">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)]">
          <span className="font-bold text-[11px] text-[var(--critical)] uppercase tracking-wider">
            OPEN FINDINGS
          </span>
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-[var(--badge-red-bg)] text-[var(--badge-red-text)] border border-[var(--badge-red-border)]">
            38 total
          </span>
        </div>

        {/* Rows */}
        <div className="divide-y divide-[var(--border-subtle)]">
          <div className="flex items-center justify-between px-4 py-2.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-[var(--critical)] shrink-0" />
              <span className="font-semibold text-[var(--text)]">AWS Access Key</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[var(--muted)] text-xs font-normal">payment-api</span>
              <span className="text-xs font-semibold text-[var(--critical)]">
                Critical
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between px-4 py-2.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-[var(--high)] shrink-0" />
              <span className="font-semibold text-[var(--text)]">GitHub Token</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[var(--muted)] text-xs font-normal">data-pipeline</span>
              <span className="text-xs font-semibold text-[var(--high)]">
                High
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between px-4 py-2.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-[var(--high)] shrink-0" />
              <span className="font-semibold text-[var(--text)]">Database Password</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[var(--muted)] text-xs font-normal">user-portal</span>
              <span className="text-xs font-semibold text-[var(--high)]">
                High
              </span>
            </div>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: "sbom",
    badge: "SBOM",
    badgeBg: "var(--badge-purple-bg)",
    badgeColor: "var(--badge-purple-text)",
    badgeBorder: "var(--badge-purple-border)",
    iconBg: "var(--badge-purple-bg)",
    iconColor: "var(--color-secondary)",
    statValue: "1.2K",
    statColor: "var(--color-secondary)",
    statLabel: "PACKAGES TRACKED",
    title: "Software Bill of Materials",
    description:
      "Generate and export a complete SBOM for every repository — ready for compliance, audits, and vendor procurement reviews.",
    icon: SBOMIcon,
    renderPreview: () => (
      <div className="rounded-[16px] border border-[var(--border-subtle)] bg-[var(--surface)] overflow-hidden text-xs shadow-xs">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)]">
          <span className="font-bold text-[11px] text-[var(--color-secondary)] uppercase tracking-wider">
            SBOM · PAYMENT-API
          </span>
          <span className="text-[11px] text-[var(--muted)] hover:text-[var(--color-secondary)] font-medium cursor-pointer transition-colors">
            Export →
          </span>
        </div>

        {/* Rows */}
        <div className="divide-y divide-[var(--border-subtle)]">
          <div className="flex items-center justify-between px-4 py-2.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <span className="font-semibold text-[var(--text)]">lodash</span>
            <div className="flex items-center gap-3">
              <span className="text-[var(--muted)] text-xs font-normal">4.17.21</span>
              <span className="text-[var(--muted)] text-xs font-normal">MIT</span>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-[var(--badge-red-bg)] text-[var(--badge-red-text)] border border-[var(--badge-red-border)]">
                Vuln
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between px-4 py-2.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <span className="font-semibold text-[var(--text)]">express</span>
            <div className="flex items-center gap-3">
              <span className="text-[var(--muted)] text-xs font-normal">4.18.2</span>
              <span className="text-[var(--muted)] text-xs font-normal">MIT</span>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-[var(--badge-green-bg)] text-[var(--badge-green-text)] border border-[var(--badge-green-border)]">
                OK
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between px-4 py-2.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <span className="font-semibold text-[var(--text)]">openssl</span>
            <div className="flex items-center gap-3">
              <span className="text-[var(--muted)] text-xs font-normal">3.0.7</span>
              <span className="text-[var(--muted)] text-xs font-normal">Apache</span>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-[var(--badge-red-bg)] text-[var(--badge-red-text)] border border-[var(--badge-red-border)]">
                Vuln
              </span>
            </div>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: "ai-scanner",
    badge: "AI SCANNER",
    badgeBg: "var(--badge-purple-bg)",
    badgeColor: "var(--badge-purple-text)",
    badgeBorder: "var(--badge-purple-border)",
    iconBg: "var(--badge-purple-bg)",
    iconColor: "var(--color-secondary)",
    statValue: "94%",
    statColor: "var(--color-secondary)",
    statLabel: "DETECTION RATE",
    title: "AI-powered risk detection",
    description:
      "LLM-assisted analysis surfaces logic flaws, insecure patterns, and novel vulnerabilities that rule-based scanners miss.",
    icon: AIScannerIcon,
    renderPreview: () => (
      <div className="rounded-[16px] border border-[var(--border-subtle)] bg-[var(--surface)] overflow-hidden text-xs shadow-xs">
        {/* Header */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--border-subtle)]">
          <span className="w-4 h-4 rounded-full bg-[var(--color-secondary)] text-white flex items-center justify-center text-[9px] font-bold shrink-0">
            AI
          </span>
          <span className="font-bold text-[11px] text-[var(--color-secondary)] uppercase tracking-wider">
            AI SCANNER · AI-ASSISTANT
          </span>
        </div>

        {/* Content */}
        <div className="p-4 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-medium text-[var(--text-secondary)]">Risk score</span>
            <span className="text-base font-bold text-[var(--high)]">7.4 / 10</span>
          </div>

          <div className="w-full h-2 rounded-full bg-[var(--elevated-surface)] border border-[var(--border-subtle)] overflow-hidden">
            <div className="h-full bg-gradient-to-r from-[var(--medium)] to-[var(--high)] rounded-full w-[74%]" />
          </div>

          <div className="pt-2 border-t border-[var(--border-subtle)] space-y-2">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[var(--high)] shrink-0" />
                <span className="font-medium text-[var(--text)]">
                  SQL injection risk in query builder
                </span>
              </div>
              <span className="text-xs font-semibold text-[var(--high)]">High</span>
            </div>

            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[var(--medium)] shrink-0" />
                <span className="font-medium text-[var(--text)]">
                  Unsafe deserialization pattern
                </span>
              </div>
              <span className="text-xs font-semibold text-[var(--medium)]">Medium</span>
            </div>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: "dependency-analysis",
    badge: "DEPENDENCY ANALYSIS",
    badgeBg: "var(--badge-yellow-bg)",
    badgeColor: "var(--badge-yellow-text)",
    badgeBorder: "var(--badge-yellow-border)",
    iconBg: "var(--badge-yellow-bg)",
    iconColor: "var(--color-accent)",
    statValue: "96%",
    statColor: "var(--color-accent)",
    statLabel: "COVERAGE",
    title: "Vulnerable paths visualized",
    description:
      "Trace every vulnerable package to the code paths that import it, so you know what's reachable and what's safe to skip.",
    icon: DependencyAnalysisIcon,
    renderPreview: () => (
      <div className="rounded-[16px] border border-[var(--border-subtle)] bg-[var(--surface)] overflow-hidden text-xs shadow-xs">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)]">
          <span className="font-bold text-[11px] text-[var(--color-accent)] uppercase tracking-wider">
            LIVE RISK DASHBOARD
          </span>
          <div className="flex items-center gap-1.5 text-xs font-medium text-[var(--success)]">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)] animate-pulse" />
            <span>Synced</span>
          </div>
        </div>

        {/* 3-Column Stats */}
        <div className="grid grid-cols-3 divide-x divide-[var(--border-subtle)] border-b border-[var(--border-subtle)] py-3 text-center">
          <div>
            <div className="text-[10px] uppercase font-semibold text-[var(--muted)] tracking-wider">Open</div>
            <div className="text-lg font-bold text-[var(--critical)] mt-0.5">42</div>
          </div>
          <div>
            <div className="text-[10px] uppercase font-semibold text-[var(--muted)] tracking-wider">Resolved</div>
            <div className="text-lg font-bold text-[var(--success)] mt-0.5">137</div>
          </div>
          <div>
            <div className="text-[10px] uppercase font-semibold text-[var(--muted)] tracking-wider">Coverage</div>
            <div className="text-lg font-bold text-[var(--color-accent)] mt-0.5">96%</div>
          </div>
        </div>

        {/* Severity Metrics with Mini Bars */}
        <div className="p-4 space-y-3">
          <div>
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[var(--critical)] shrink-0" />
                <span className="font-medium text-[var(--text-secondary)]">Critical</span>
              </div>
              <span className="font-bold text-[var(--text)]">2</span>
            </div>
            <div className="w-full h-1.5 rounded-full bg-[var(--elevated-surface)] border border-[var(--border-subtle)] overflow-hidden mt-1.5">
              <div className="h-full bg-[var(--critical)] rounded-full w-[15%]" />
            </div>
          </div>

          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[var(--high)] shrink-0" />
              <span className="font-medium text-[var(--text-secondary)]">High</span>
            </div>
            <span className="font-bold text-[var(--text)]">5</span>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: "prioritized-fixes",
    badge: "PRIORITIZED FIXES",
    badgeBg: "var(--badge-green-bg)",
    badgeColor: "var(--success)",
    badgeBorder: "var(--badge-green-border)",
    iconBg: "var(--badge-green-bg)",
    iconColor: "var(--success)",
    statValue: "<2 min",
    statColor: "var(--success)",
    statLabel: "AVG TRIAGE TIME",
    title: "Guidance lands with context",
    description:
      "Findings include owner, urgency, and a fix suggestion — routed directly to the right team without leaving your workflow.",
    icon: PrioritizedFixesIcon,
    renderPreview: () => (
      <div className="rounded-[16px] border border-[var(--border-subtle)] bg-[var(--surface)] overflow-hidden text-xs shadow-xs">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)]">
          <span className="font-bold text-[11px] text-[var(--success)] uppercase tracking-wider">
            PRIORITIZED FIXES
          </span>
          <span className="text-[11px] text-[var(--muted)] font-normal">
            3 actionable
          </span>
        </div>

        {/* Rows */}
        <div className="divide-y divide-[var(--border-subtle)]">
          <div className="p-3.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className="px-2 py-0.5 rounded-[6px] text-[10px] font-bold bg-[var(--badge-red-bg)] text-[var(--badge-red-text)] border border-[var(--badge-red-border)]">
                  P1
                </span>
                <span className="font-semibold text-[var(--text)]">payment-api</span>
              </div>
              <span className="text-[var(--muted)] text-xs font-normal">Platform Team</span>
            </div>
            <p className="text-xs text-[var(--text-secondary)] mt-1 font-normal leading-relaxed">
              Rotate exposed AWS key immediately
            </p>
          </div>

          <div className="p-3.5 hover:bg-[var(--elevated-surface)] transition-colors">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className="px-2 py-0.5 rounded-[6px] text-[10px] font-bold bg-[var(--badge-yellow-bg)] text-[var(--badge-yellow-text)] border border-[var(--badge-yellow-border)]">
                  P1
                </span>
                <span className="font-semibold text-[var(--text)]">ai-assistant</span>
              </div>
              <span className="text-[var(--muted)] text-xs font-normal">AI Team</span>
            </div>
            <p className="text-xs text-[var(--text-secondary)] mt-1 font-normal leading-relaxed">
              Patch openssl to 3.1.0 or later
            </p>
          </div>
        </div>
      </div>
    ),
  },
];

export default function FeatureShowcase() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isPaused, setIsPaused] = useState(false);

  useEffect(() => {
    if (isPaused) return;
    const timer = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % slides.length);
    }, 6000);
    return () => clearInterval(timer);
  }, [isPaused]);

  const activeSlide = slides[currentIndex];
  const Icon = activeSlide.icon;

  return (
    <div
      className="w-full h-full flex flex-col justify-between rounded-[32px] border border-[var(--border)] bg-[var(--surface)] p-6 sm:p-7 xl:p-8 shadow-xs relative transition-colors duration-200"
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
    >
      <div className="flex flex-col">
        {/* Top Tag Label */}
        <div className="pb-1.5">
          <span className="text-[12px] font-semibold tracking-[1.92px] text-[var(--color-primary)] uppercase">
            Welcome to continuous coverage
          </span>
        </div>

        {/* Hero Title */}
        <h1 className="text-2xl sm:text-3xl lg:text-[34px] xl:text-[36px] font-bold leading-[1.15] text-[var(--text)] tracking-tight">
          Protect repositories <br />
          <span className="text-[var(--color-primary)]">
            without slowing delivery.
          </span>
        </h1>

        {/* Hero Description */}
        <p className="pt-2 text-xs sm:text-sm lg:text-[14px] text-[var(--text-secondary)] leading-relaxed max-w-xl">
          Zyloch continuously evaluates your source, dependencies and pipelines, then delivers prioritized fixes with ownership-ready context.
        </p>

        {/* Flow Pills */}
        <div className="pt-3.5 flex flex-wrap items-center gap-2">
          {["Discover", "Analyze", "Prioritize", "Deliver"].map((step, idx) => (
            <React.Fragment key={step}>
              <span className="inline-flex items-center px-3.5 py-1 rounded-full text-[12px] font-semibold border border-[var(--border)] bg-[var(--elevated-surface)] text-[var(--text)] shadow-2xs hover:border-[var(--color-primary)] transition-colors">
                {step}
              </span>
              {idx < 3 && (
                <span className="text-[var(--muted)] text-[12px] font-mono">→</span>
              )}
            </React.Fragment>
          ))}
        </div>

        {/* Dynamic Carousel Feature Box matching Exact Figma Card Design */}
        <div className="mt-5 rounded-[24px] border border-[var(--border-subtle)] bg-[var(--elevated-surface)] p-5 sm:p-6 relative shadow-xs transition-colors duration-200">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeSlide.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.28, ease: "easeOut" }}
            >
              {/* Header row with Icon, Badge, Title and Large Stat */}
              <div className="flex items-start justify-between gap-3 pb-3">
                <div className="flex items-start gap-3.5">
                  <div
                    className="w-11 h-11 rounded-[14px] flex items-center justify-center shrink-0 shadow-2xs border border-[var(--border-subtle)]"
                    style={{ backgroundColor: activeSlide.iconBg, color: activeSlide.iconColor }}
                  >
                    <Icon className="w-6 h-6" />
                  </div>
                  <div>
                    <span
                      className="inline-block px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase border"
                      style={{
                        backgroundColor: activeSlide.badgeBg,
                        color: activeSlide.badgeColor,
                        borderColor: activeSlide.badgeBorder,
                      }}
                    >
                      {activeSlide.badge}
                    </span>
                    <h2 className="text-base sm:text-lg font-bold text-[var(--text)] mt-0.5 tracking-tight">
                      {activeSlide.title}
                    </h2>
                  </div>
                </div>

                <div className="text-right shrink-0">
                  <div
                    className="text-2xl sm:text-3xl font-extrabold tracking-tight leading-none"
                    style={{ color: activeSlide.statColor }}
                  >
                    {activeSlide.statValue}
                  </div>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)] mt-1">
                    {activeSlide.statLabel}
                  </div>
                </div>
              </div>

              {/* Slide Description */}
              <p className="text-xs sm:text-[13px] text-[var(--text-secondary)] leading-relaxed pb-3.5">
                {activeSlide.description}
              </p>

              {/* Render specific slide mock */}
              <div>{activeSlide.renderPreview()}</div>
            </motion.div>
          </AnimatePresence>

          {/* Carousel Pagination Indicator Bar */}
          <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
            <div className="flex items-center gap-2" role="tablist" aria-label="Feature slides">
              {slides.map((s, idx) => {
                const isActive = idx === currentIndex;
                return (
                  <button
                    key={s.id}
                    onClick={() => setCurrentIndex(idx)}
                    className="focus:outline-none transition-all duration-300 py-1 cursor-pointer"
                    aria-label={`View ${s.badge}`}
                    role="tab"
                    aria-selected={isActive}
                  >
                    <span
                      className={`block rounded-full transition-all duration-300 ${
                        isActive
                          ? "w-[24px] h-[7px] bg-[var(--color-primary)] shadow-xs"
                          : "w-[7px] h-[7px] bg-[var(--border)] hover:bg-[var(--muted)]"
                      }`}
                    />
                  </button>
                );
              })}
            </div>
            <span className="text-[11px] font-bold text-[var(--muted)]">
              {currentIndex + 1} / {slides.length}
            </span>
          </div>
        </div>
      </div>

      {/* Bottom Trust Banner */}
      <div className="mt-4 rounded-[22px] bg-[#0C1733] text-white p-3.5 sm:px-5 sm:py-4 flex items-center justify-between gap-3 shadow-md border border-[#1E2D4A] shrink-0">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-[14px] bg-[#00D4F0] flex items-center justify-center shrink-0 shadow-sm">
            <CheckIcon className="w-5 h-5 text-[#0C1733] stroke-[3.5]" />
          </div>
          <div>
            <h4 className="text-[15px] sm:text-base font-bold text-white leading-snug">
              Read-only by design
            </h4>
            <p className="text-xs sm:text-[13px] text-[#8FA0BE] leading-snug mt-0.5">
              No write permissions. No data retention.
            </p>
          </div>
        </div>

        <div className="px-4 py-1.5 rounded-full bg-[#16233B]/80 border border-[#2A3C5E] text-[11px] font-semibold text-white uppercase tracking-[1.6px] shrink-0">
          SETUP &lt; 2 MIN
        </div>
      </div>
    </div>
  );
}
