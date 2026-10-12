"use client";

import React from "react";
import { motion } from "framer-motion";
import Link from "next/link";

import CompleteIcon from "@/public/assets/icons/complete.svg";
import PullIcon from "@/public/assets/icons/git-pull-request.svg";
import SettingsIcon from "@/public/assets/icons/install.svg";
import MetadataIcon from "@/public/assets/icons/metadata.svg";
import RepoIcon from "@/public/assets/icons/security-report.svg";
import SecureIcon from "@/public/assets/icons/secure.svg";

const permissionCards = [
  {
    title: "Repository Contents",
    access: "Read-only",
    desc: "Scans source, manifests and dependencies for policy and vulnerability exposure.",
    icon: RepoIcon,
    tone: "cyan",
  },
  {
    title: "Pull Requests",
    access: "Read-only",
    desc: "Reviews changed files and reports contextual risk before merge.",
    icon: PullIcon,
    tone: "purple",
  },
  {
    title: "Repository Metadata",
    access: "Read-only",
    desc: "Uses repo structure and branch context for accurate triage.",
    icon: MetadataIcon,
    tone: "green",
  },
];

const timeline = [
  {
    step: "01",
    title: "Pick Repositories",
    detail: "Start with critical repos or cover your full organization in one click.",
  },
  {
    step: "02",
    title: "Review Permissions",
    detail: "Approve read-only scopes so Zyloch can analyze risk without write access.",
  },
  {
    step: "03",
    title: "Activate Baseline",
    detail: "Continuous scanning starts immediately for pushes, PRs and dependencies.",
  },
];

const trustPills = [
  { icon: SecureIcon, text: "Zero Retention", cls: "badge-green", tone: "green" },
  { icon: CompleteIcon, text: "2-Minute Setup", cls: "badge-cyan", tone: "cyan" },
  { icon: SettingsIcon, text: "No Manual Config", cls: "badge-purple", tone: "purple" },
];

const quickStats = [
  { label: "Setup Time", value: "<2 min" },
  { label: "Write Access", value: "None" },
  { label: "Coverage Start", value: "Instant" },
  { label: "Default Mode", value: "Read-only" },
];

const iconToneMap = {
  cyan: {
    from: "#06b6d4",
    to: "#0e7490",
    shadow: "0 6px 18px rgba(6,182,212,0.50)",
    ring: "ring-cyan-400/60",
    shine: "bg-cyan-200/25",
  },
  purple: {
    from: "#8b5cf6",
    to: "#6d28d9",
    shadow: "0 6px 18px rgba(139,92,246,0.50)",
    ring: "ring-violet-400/60",
    shine: "bg-violet-200/25",
  },
  green: {
    from: "#22c55e",
    to: "#15803d",
    shadow: "0 6px 18px rgba(34,197,94,0.50)",
    ring: "ring-emerald-400/60",
    shine: "bg-emerald-200/25",
  },
};

const iconSizeMap = {
  sm: { tile: "h-7 w-7", icon: "h-3.5 w-3.5", radius: "rounded-xl", dark: "h-[40%]", float: [0, 0, 0] },
  md: { tile: "h-10 w-10", icon: "h-5 w-5", radius: "rounded-2xl", dark: "h-1/2", float: [0, -3, 0] },
  lg: { tile: "h-12 w-12", icon: "h-6 w-6", radius: "rounded-2xl", dark: "h-1/2", float: [0, -4, 0] },
};

function Floating3DIcon({ icon: Icon, tone = "cyan", size = "md" }) {
  const t = iconToneMap[tone] || iconToneMap.cyan;
  const s = iconSizeMap[size] || iconSizeMap.md;

  return (
    <motion.span
      className={`relative inline-flex flex-shrink-0 items-center justify-center overflow-hidden ring-1 ${s.tile} ${s.radius} ${t.ring}`}
      style={{
        background: `linear-gradient(145deg, ${t.from}, ${t.to})`,
        boxShadow: t.shadow,
      }}
      animate={{ y: s.float }}
      transition={{ duration: 4.8, repeat: Infinity, ease: "easeInOut" }}
      whileHover={{ scale: 1.1, y: s.float[1] - 1 }}
    >
      <span className={`pointer-events-none absolute left-0 top-0 w-full ${s.dark} ${s.radius} ${t.shine}`} />
      <span className={`pointer-events-none absolute bottom-0 right-0 w-full ${s.dark} ${s.radius} bg-black/20`} />
      <Icon
        className={`relative z-10 ${s.icon} [&_*]:fill-white [&_path]:fill-white [&_rect]:fill-white [&_circle]:fill-white [&_g]:fill-white drop-shadow-[0_1px_4px_rgba(0,0,0,0.7)]`}
      />
    </motion.span>
  );
}

function PremiumFrame({ children }) {
  return (
    <div className="relative h-full overflow-hidden rounded-[22px] border border-[var(--border)] bg-[var(--surface)]/92 backdrop-blur">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-14 -top-16 h-44 w-64 rounded-full bg-[var(--color-primary)]/12 blur-3xl" />
        <div className="absolute -right-14 top-1/4 h-56 w-64 rounded-full bg-[var(--color-secondary)]/14 blur-3xl" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_10%,rgba(6,182,212,0.1),transparent_42%),radial-gradient(circle_at_90%_20%,rgba(139,92,246,0.09),transparent_38%),radial-gradient(circle_at_50%_100%,rgba(34,197,94,0.08),transparent_38%)]" />
        <motion.div
          className="absolute left-1/2 top-6 h-px w-64 -translate-x-1/2 bg-gradient-to-r from-transparent via-white/50 to-transparent"
          animate={{ opacity: [0.22, 0.7, 0.22], scaleX: [0.9, 1.08, 0.9] }}
          transition={{ duration: 5, repeat: Infinity, ease: "easeInOut" }}
        />
        <motion.div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(circle at 16% 26%, rgba(255,255,255,0.12), transparent 44%), radial-gradient(circle at 80% 14%, rgba(255,255,255,0.1), transparent 40%)",
          }}
          animate={{ opacity: [0.14, 0.3, 0.14] }}
          transition={{ duration: 10, repeat: Infinity, ease: "easeInOut" }}
        />
        <div
          className="absolute inset-0 opacity-70"
          style={{
            backgroundImage:
              "linear-gradient(to right, rgba(148,163,184,0.07) 1px, transparent 1px), linear-gradient(to bottom, rgba(148,163,184,0.07) 1px, transparent 1px)",
            backgroundSize: "24px 24px",
            maskImage: "radial-gradient(circle at center, black 30%, transparent 86%)",
            WebkitMaskImage: "radial-gradient(circle at center, black 30%, transparent 86%)",
          }}
        />
      </div>

      <div className="relative z-10 h-full p-4 md:p-5 lg:p-6">{children}</div>
    </div>
  );
}

export default function InstallationStep() {
  const appUrl = process.env.NEXT_PUBLIC_GITHUB_APP_URL || "#";

  return (
    <PremiumFrame>
      <div className="flex h-full min-h-0 flex-col gap-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="inline-flex items-center gap-2 rounded-full border border-[var(--badge-cyan-border)] bg-[var(--badge-cyan-bg)] px-3 py-1.5">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[var(--color-primary)]" />
            <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--badge-cyan-text)]">
              Installation Experience
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {trustPills.map((item) => {
              const Icon = item.icon;

              return (
                <span
                  key={item.text}
                  className={`${item.cls} inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-medium`}
                >
                  <Floating3DIcon icon={Icon} tone={item.tone} size="sm" />
                  {item.text}
                </span>
              );
            })}
          </div>
        </div>

        <div className="grid flex-1 min-h-0 grid-cols-1 gap-4 xl:grid-cols-[1.08fr_0.92fr]">
          <div className="flex min-h-0 flex-col gap-4">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35 }}
              whileHover={{ y: -3 }}
              className="rounded-[18px] border border-[var(--border-subtle)] bg-[var(--surface)]/92 p-4 md:p-5 shadow-[var(--shadow-2)]"
            >
              <h2 className="font-[var(--font-elegant)] text-2xl font-extrabold leading-tight text-[var(--text)] md:text-3xl">
                Go Live in Minutes,
                <br />
                <span className="gradient-text">Stay Read-Only by Design.</span>
              </h2>

              <p className="mt-2 max-w-xl text-sm leading-relaxed text-[var(--muted)]">
                Install the GitHub App once and start continuous coverage across code, pull requests
                and dependencies with zero write permissions.
              </p>

              <div className="mt-4 grid grid-cols-2 gap-2.5 md:grid-cols-4">
                {quickStats.map((stat, idx) => (
                  <motion.div
                    key={stat.label}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.28, delay: idx * 0.05 }}
                    className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--elevated-surface)] p-2"
                  >
                    <p className="text-[9px] uppercase tracking-[0.1em] text-[var(--muted)]">{stat.label}</p>
                    <p className="mt-1 text-sm font-bold text-[var(--text)]">{stat.value}</p>
                  </motion.div>
                ))}
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.08 }}
              whileHover={{ y: -2 }}
              className="flex flex-1 flex-col rounded-[18px] border border-[var(--border-subtle)] bg-[var(--surface)]/90 p-4"
            >
              <div className="mb-3.5 flex items-center justify-between">
                <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--muted)]">
                  Guided Setup Flow
                </p>
                <span className="rounded-full bg-[var(--badge-purple-bg)] px-2 py-0.5 text-[10px] font-semibold text-[var(--badge-purple-text)]">
                  under 2 min
                </span>
              </div>

              <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto pr-1">
                {timeline.map((item, idx) => (
                  <motion.div
                    key={item.step}
                    initial={{ opacity: 0, x: 8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3, delay: 0.05 + idx * 0.07 }}
                    whileHover={{ x: 3 }}
                    className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--elevated-surface)] px-3 py-2.5"
                  >
                    <div className="mb-1.5 flex items-center gap-2">
                      <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--color-primary)]/12 text-[10px] font-bold text-[var(--color-primary)]">
                        {item.step}
                      </span>
                      <p className="text-xs font-semibold text-[var(--text)]">{item.title}</p>
                    </div>
                    <p className="pl-7 text-[11px] leading-relaxed text-[var(--muted)]">{item.detail}</p>
                  </motion.div>
                ))}
              </div>

              <div className="mt-3 grid grid-cols-3 gap-2">
                {[
                  { k: "Write Access", v: "None" },
                  { k: "Data Retention", v: "Zero" },
                  { k: "Permission Mode", v: "Least" },
                ].map((stat) => (
                  <div
                    key={stat.k}
                    className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--elevated-surface)] px-2 py-1.5 text-center"
                  >
                    <p className="text-[9px] text-[var(--muted)]">{stat.k}</p>
                    <p className="text-[11px] font-semibold text-[var(--text)]">{stat.v}</p>
                  </div>
                ))}
              </div>
            </motion.div>
          </div>

          <div className="flex min-h-0 flex-col gap-4">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.12 }}
              whileHover={{ y: -2 }}
              className="flex min-h-0 flex-1 flex-col rounded-[18px] border border-[var(--border-subtle)] bg-[var(--surface)]/90 p-4 shadow-[var(--shadow-2)]"
            >
              <div className="mb-3.5 flex items-center justify-between">
                <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--muted)]">
                  Permission Matrix
                </p>
                <span className="inline-flex items-center gap-1 rounded-full bg-[var(--badge-green-bg)] px-2 py-0.5 text-[10px] font-semibold text-[var(--badge-green-text)]">
                  <CompleteIcon className="h-3 w-3 fill-[var(--badge-green-text)]" />
                  Read-only
                </span>
              </div>

              <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto pr-1">
                {permissionCards.map((item, idx) => {
                  const Icon = item.icon;

                  return (
                    <motion.div
                      key={item.title}
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3, delay: 0.08 + idx * 0.06 }}
                      whileHover={{ y: -2 }}
                      className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--elevated-surface)] p-3"
                    >
                      <div className="flex items-start gap-3">
                        <span className="shrink-0 mt-0.5">
                          <Floating3DIcon icon={Icon} tone={item.tone} size="md" />
                        </span>
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-xs font-semibold text-[var(--text)]">{item.title}</p>
                            <span className="rounded-full bg-[var(--badge-green-bg)] px-1.5 py-0.5 text-[9px] font-semibold text-[var(--badge-green-text)]">
                              {item.access}
                            </span>
                          </div>
                          <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">{item.desc}</p>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.18 }}
              className="rounded-[18px] border border-[var(--border-subtle)] bg-[var(--surface)]/92 p-4"
            >
              <Link
                href={appUrl}
                className="group relative inline-flex w-full items-center justify-center gap-2 overflow-hidden rounded-[var(--radius-lg)] border border-white/10 bg-[var(--color-primary)] px-5 py-3 text-sm font-semibold !text-[var(--text-on-primary)] transition-all duration-200 hover:!text-[var(--text-on-primary)] hover:brightness-110 active:scale-[0.98] visited:!text-[var(--text-on-primary)]"
                style={{ color: "var(--text-on-primary)", textDecoration: "none" }}
              >
                <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/20 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
                <span className="relative z-10 flex-shrink-0">
                  <SettingsIcon className="h-4 w-4 [&_*]:fill-white [&_path]:fill-white drop-shadow-sm" />
                </span>
                <span className="relative z-10 !text-[var(--text-on-primary)]" style={{ color: "var(--text-on-primary)" }}>
                  Install GitHub App
                </span>
              </Link>
              <p className="mt-2 text-center text-[10px] text-[var(--muted)]">
                Free for public repositories. No credit card required.
              </p>
            </motion.div>
          </div>
        </div>

        <p className="pt-1 text-center text-[10px] text-[var(--muted)]">
          By installing, you agree to our{" "}
          <Link href="/terms" className="text-[var(--color-primary)] hover:underline">Terms</Link>
          {" "}and{" "}
          <Link href="/privacy" className="text-[var(--color-primary)] hover:underline">Privacy Policy</Link>.
        </p>
      </div>
    </PremiumFrame>
  );
}