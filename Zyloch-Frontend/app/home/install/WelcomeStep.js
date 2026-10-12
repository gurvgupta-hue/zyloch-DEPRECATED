"use client";

import React, { useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";

import PieChart3D from "@/components/charts/PieChartUI";
import CicdIcon from "@/public/assets/icons/cicd.svg";
import CodeIcon from "@/public/assets/icons/code.svg";
import CodeScanIcon from "@/public/assets/icons/iac.svg";
import MetadataIcon from "@/public/assets/icons/metadata.svg";
import SecretIcon from "@/public/assets/icons/secret.svg";
import SecurityReportIcon from "@/public/assets/icons/security-report.svg";
import GitPrivate from "@/public/assets/icons/pending.svg";

const slides = [
  { id: "overview", label: "Overview" },
  { id: "scans", label: "Security Scans" },
  { id: "workflow", label: "How It Works" },
];

const scans = [
  {
    icon: CodeScanIcon,
    title: "IaC Scanning",
    desc: "Terraform, Kubernetes and Docker policy checks before deployment.",
    tone: "cyan",
    value: "Policy-aware",
  },
  {
    icon: CicdIcon,
    title: "CI/CD Security",
    desc: "Permission drift, risky actions and workflow hardening coverage.",
    tone: "purple",
    value: "Build-time",
  },
  {
    icon: MetadataIcon,
    title: "SBOM Analysis",
    desc: "Dependency intelligence with licensing and supply-chain insights.",
    tone: "blue",
    value: "Deep graph",
  },
  {
    icon: SecretIcon,
    title: "Secret Scanning",
    desc: "Credential leak detection across branches and commit history.",
    tone: "red",
    value: "Commit deep",
  },
  {
    icon: SecurityReportIcon,
    title: "CVE Detection",
    desc: "Severity-ranked vulnerabilities with prioritized remediation context.",
    tone: "amber",
    value: "Continuous",
  },
];

const fillMap = {
  cyan: "text-[var(--badge-cyan-text)]",
  purple: "text-[var(--badge-purple-text)]",
  blue: "text-[var(--badge-blue-text)]",
  red: "text-[var(--badge-red-text)]",
  amber: "text-[var(--badge-yellow-text)]",
};

const trendBars = [45, 54, 58, 63, 68, 73, 84];

const riskBreakdown = [
  { label: "Critical", value: 2, color: "var(--critical)", progress: 18 },
  { label: "High", value: 5, color: "var(--high)", progress: 36 },
  { label: "Medium", value: 11, color: "var(--medium)", progress: 52 },
  { label: "Low", value: 24, color: "var(--success)", progress: 88 },
];

const iconToneMap = {
  cyan: {
    from: "#06b6d4",
    to: "#0e7490",
    shadow: "0 8px 24px rgba(6,182,212,0.55)",
    ring: "ring-cyan-400/80",
    shine: "bg-cyan-300/30",
  },
  purple: {
    from: "#8b5cf6",
    to: "#6d28d9",
    shadow: "0 8px 24px rgba(139,92,246,0.55)",
    ring: "ring-violet-400/80",
    shine: "bg-violet-300/30",
  },
  blue: {
    from: "#38bdf8",
    to: "#0369a1",
    shadow: "0 8px 24px rgba(56,189,248,0.55)",
    ring: "ring-sky-400/80",
    shine: "bg-sky-300/30",
  },
  red: {
    from: "#fb7185",
    to: "#be123c",
    shadow: "0 8px 24px rgba(251,113,133,0.55)",
    ring: "ring-rose-400/80",
    shine: "bg-rose-300/30",
  },
  amber: {
    from: "#fbbf24",
    to: "#b45309",
    shadow: "0 8px 24px rgba(251,191,36,0.55)",
    ring: "ring-amber-400/80",
    shine: "bg-amber-300/30",
  },
  green: {
    from: "#22c55e",
    to: "#15803d",
    shadow: "0 8px 24px rgba(34,197,94,0.55)",
    ring: "ring-emerald-400/80",
    shine: "bg-emerald-300/30",
  },
};

function Floating3DIcon({ icon: Icon, tone = "cyan", iconClassName = "" }) {
  const t = iconToneMap[tone] || iconToneMap.cyan;

  return (
    <motion.span
      className={`relative inline-flex h-10 w-10 flex-shrink-0 items-center justify-center overflow-hidden rounded-2xl ring-1 ${t.ring}`}
      style={{
        background: `linear-gradient(145deg, ${t.from}, ${t.to})`,
        boxShadow: t.shadow,
      }}
      animate={{ y: [0, -3, 0] }}
      transition={{ duration: 4.8, repeat: Infinity, ease: "easeInOut" }}
      whileHover={{ scale: 1.12, y: -4 }}
    >
      {/* top-left shine for 3D depth */}
      <span className={`pointer-events-none absolute left-0 top-0 h-1/2 w-full rounded-t-2xl ${t.shine}`} />
      {/* bottom-right dark edge */}
      <span className="pointer-events-none absolute bottom-0 right-0 h-1/2 w-full rounded-b-2xl bg-black/20" />
      <Icon
        className={`relative z-10 h-5 w-5 [&_*]:fill-white [&_path]:fill-white [&_rect]:fill-white [&_g]:fill-white drop-shadow-[0_1px_3px_rgba(0,0,0,0.6)] ${iconClassName}`}
      />
    </motion.span>
  );
}

function PremiumFrame({ children }) {
  return (
    <div className="relative h-full overflow-hidden rounded-[22px] border border-[var(--border)] bg-[var(--surface)]/92 backdrop-blur">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-8 top-5 h-24 w-24 rounded-full bg-[var(--color-primary)]/12 blur-2xl" />
        <div className="absolute right-6 top-8 h-28 w-28 rounded-full bg-[var(--color-secondary)]/12 blur-2xl" />
        <motion.div
          className="absolute left-1/2 top-4 h-px w-56 -translate-x-1/2 bg-gradient-to-r from-transparent via-white/50 to-transparent"
          animate={{ opacity: [0.25, 0.75, 0.25], scaleX: [0.9, 1.07, 0.9] }}
          transition={{ duration: 4.8, repeat: Infinity, ease: "easeInOut" }}
        />
        <motion.div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(circle at 18% 24%, rgba(255,255,255,0.15), transparent 44%), radial-gradient(circle at 78% 16%, rgba(255,255,255,0.12), transparent 40%)",
          }}
          animate={{ opacity: [0.16, 0.34, 0.16] }}
          transition={{ duration: 9.5, repeat: Infinity, ease: "easeInOut" }}
        />
      </div>
      <div className="relative z-10 h-full p-4 md:p-5">{children}</div>
    </div>
  );
}

function StatCard({ icon: Icon, value, label, delay = 0, tone = "cyan" }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay }}
      className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--surface)]/85 px-3 py-3"
    >
      <div className="mb-2">
        <Floating3DIcon icon={Icon} tone={tone} iconClassName="fill-current stroke-current text-[var(--badge-cyan-text)]" />
      </div>
      <p className="text-base font-bold leading-none text-[var(--text)]">{value}</p>
      <p className="mt-1 text-[10px] text-[var(--muted)]">{label}</p>
    </motion.div>
  );
}

function OverviewSlide() {
  const [insightView, setInsightView] = useState("distribution");
  const severityChartData = riskBreakdown.map((item) => ({
    name: item.label,
    value: item.value,
    color: item.color,
  }));

  return (
    <PremiumFrame>
      <div className="grid h-full grid-cols-1 gap-4 xl:grid-cols-[1.05fr_0.95fr]">
        <div className="flex flex-col justify-center gap-4">
          <div className="inline-flex w-fit items-center gap-2 rounded-full border border-[var(--badge-cyan-border)] bg-[var(--badge-cyan-bg)] px-3 py-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-primary)] animate-pulse" />
            <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--badge-cyan-text)]">
              Security Command Center
            </span>
          </div>

          <div>
            <h2 className="font-[var(--font-elegant)] text-2xl font-extrabold leading-tight text-[var(--text)] md:text-3xl">
              Protect Repositories
              <br />
              <span className="gradient-text">Without Slowing Delivery</span>
            </h2>
            <p className="mt-3 max-w-xl text-sm leading-relaxed text-[var(--muted)] md:text-[15px]">
              Zyloch continuously evaluates source, dependencies and pipelines, then delivers
              prioritized fixes with ownership-ready context.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <StatCard icon={CodeScanIcon} value="5" label="Scan Engines" delay={0.05} tone="cyan" />
            <StatCard icon={GitPrivate} value="24/7" label="Monitoring" delay={0.1} tone="green" />
            <StatCard icon={CodeIcon} value="90s" label="Setup Time" delay={0.15} tone="purple" />
            <StatCard icon={SecurityReportIcon} value="Auto" label="Reports" delay={0.2} tone="amber" />
          </div>
        </div>

        <div className="flex h-full min-h-0 items-center">
          <div className="w-full rounded-[18px] border border-[var(--border-subtle)] bg-[var(--surface)]/90 p-3.5 shadow-[var(--shadow-2)] backdrop-blur">
            <div className="mb-3 flex items-center justify-between">
              <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--muted)]">
                Live Risk Dashboard
              </p>
              <span className="inline-flex items-center gap-1 rounded-full bg-[var(--badge-green-bg)] px-2 py-0.5 text-[10px] font-semibold text-[var(--badge-green-text)]">
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--success)] animate-pulse" />
                Synced
              </span>
            </div>

            <div className="mb-3 grid grid-cols-3 gap-2">
              {[
                { label: "Open", value: "42", color: "var(--critical)" },
                { label: "Resolved", value: "137", color: "var(--success)" },
                { label: "Coverage", value: "96%", color: "var(--color-primary)" },
              ].map((item) => (
                <div
                  key={item.label}
                  className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--elevated-surface)] px-2 py-2 text-center"
                >
                  <p className="text-[9px] uppercase tracking-[0.1em] text-[var(--muted)]">{item.label}</p>
                  <p className="text-sm font-bold" style={{ color: item.color }}>
                    {item.value}
                  </p>
                </div>
              ))}
            </div>

            <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--elevated-surface)] p-2.5">
              <div className="mb-2 flex items-center justify-between">
                <p className="text-[10px] font-semibold uppercase tracking-[0.13em] text-[var(--muted)]">
                  Security Insights
                </p>
                <div className="inline-flex rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--surface)] p-0.5">
                  <button
                    onClick={() => setInsightView("distribution")}
                    className={`rounded-[4px] px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.08em] transition-all ${insightView === "distribution"
                      ? "bg-[var(--color-primary)]/15 text-[var(--color-primary)]"
                      : "text-[var(--muted)]"
                      }`}
                  >
                    Donut
                  </button>
                  <button
                    onClick={() => setInsightView("trend")}
                    className={`rounded-[4px] px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.08em] transition-all ${insightView === "trend"
                      ? "bg-[var(--color-primary)]/15 text-[var(--color-primary)]"
                      : "text-[var(--muted)]"
                      }`}
                  >
                    Trend
                  </button>
                </div>
              </div>

              <AnimatePresence mode="wait" initial={false}>
                {insightView === "distribution" ? (
                  <motion.div
                    key="distribution"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    className="h-[132px]"
                  >
                    <PieChart3D
                      data={severityChartData}
                      dataKey="value"
                      nameKey="name"
                      height={132}
                      innerRadius={24}
                      outerRadius={50}
                      showLegend={false}
                      showCenterText={true}
                    />
                  </motion.div>
                ) : (
                  <motion.div
                    key="trend"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    className="pt-2"
                  >
                    <div className="flex h-[94px] items-end justify-between gap-1.5">
                      {trendBars.map((point, idx) => (
                        <motion.div
                          key={`${point}-${idx}`}
                          className="w-3 rounded-t-sm bg-gradient-to-t from-[var(--color-primary)] via-[var(--color-secondary)] to-[var(--color-accent)]"
                          initial={{ height: 10, opacity: 0.5 }}
                          animate={{ height: `${point}px`, opacity: [0.65, 1, 0.78] }}
                          transition={{ duration: 0.7, delay: idx * 0.05 }}
                        />
                      ))}
                    </div>
                    <div className="mt-2 flex items-center justify-between text-[9px] uppercase tracking-[0.1em] text-[var(--muted)]">
                      <span>Week 1</span>
                      <span>Week 4</span>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            <div className="mt-3 space-y-2">
              {riskBreakdown.map((item, idx) => (
                <motion.div
                  key={item.label}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: 0.05 + idx * 0.07 }}
                  className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--elevated-surface)] px-2.5 py-2"
                >
                  <div className="mb-1 flex items-center justify-between text-[11px]">
                    <span className="flex items-center gap-2 text-[var(--text-secondary)]">
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
                      {item.label}
                    </span>
                    <span className="font-semibold text-[var(--text)]">{item.value}</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-[var(--border)]">
                    <motion.div
                      className="h-full rounded-full"
                      style={{ backgroundColor: item.color }}
                      initial={{ width: 0 }}
                      animate={{ width: `${item.progress}%` }}
                      transition={{ duration: 0.8, delay: 0.2 + idx * 0.08 }}
                    />
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </PremiumFrame>
  );
}

function ScansSlide() {
  return (
    <PremiumFrame>
      <div className="flex h-full flex-col gap-3.5">
        <div className="text-center">
          <h3 className="font-[var(--font-grotesk)] text-lg font-bold text-[var(--text)] md:text-xl">
            Multi-Layer Security Coverage
          </h3>
          <p className="mx-auto mt-1 max-w-2xl text-xs text-[var(--muted)] md:text-sm">
            Five dedicated engines scan in parallel and converge into one prioritized remediation queue.
          </p>
        </div>

        <div className="grid flex-1 grid-cols-1 gap-2.5 md:grid-cols-2 xl:grid-cols-3">
          {scans.map((scan, idx) => {
            const Icon = scan.icon;
            const isFeatured = idx === 0;

            return (
              <motion.div
                key={scan.title}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, delay: idx * 0.06 }}
                whileHover={{ y: -4, scale: 1.01 }}
                className={`group rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--surface)]/92 p-3.5 transition-all duration-200 hover:-translate-y-0.5 hover:border-[var(--border-hover)] hover:shadow-[var(--shadow-1)] ${isFeatured ? "xl:col-span-2" : ""
                  }`}
              >
                <div className="mb-3 flex items-center justify-between">
                  <Floating3DIcon icon={Icon} tone={scan.tone} iconClassName={fillMap[scan.tone]} />
                  <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                    {scan.value}
                  </span>
                </div>

                <p className="text-sm font-semibold text-[var(--text)]">{scan.title}</p>
                <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">{scan.desc}</p>

                <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-[var(--border)]">
                  <motion.div
                    className="h-full rounded-full bg-gradient-to-r from-[var(--color-primary)] via-[var(--color-secondary)] to-[var(--color-accent)]"
                    initial={{ width: 0 }}
                    animate={{ width: isFeatured ? "88%" : "70%" }}
                    transition={{ duration: 0.9, delay: 0.2 + idx * 0.08 }}
                  />
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </PremiumFrame>
  );
}

function WorkflowSlide() {
  const steps = [
    {
      id: "01",
      title: "Install GitHub App",
      detail: "Connect repositories with least-privilege defaults.",
      icon: GitPrivate,
      tone: "cyan",
    },
    {
      id: "02",
      title: "Scan On Every Push",
      detail: "Code, CI and dependency checks run automatically.",
      icon: CodeScanIcon,
      tone: "purple",
    },
    {
      id: "03",
      title: "Prioritize Fixes",
      detail: "Actionable reports with severity and ownership context.",
      icon: SecurityReportIcon,
      tone: "green",
    },
  ];

  return (
    <PremiumFrame>
      <div className="flex h-full flex-col gap-4">
        <h3 className="text-center font-[var(--font-grotesk)] text-lg font-bold text-[var(--text)] md:text-xl">
          From Commit to Confidence in 3 Steps
        </h3>

        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-3">
          {steps.map((step, idx) => {
            const Icon = step.icon;
            return (
              <motion.div
                key={step.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, delay: idx * 0.08 }}
                whileHover={{ y: -3 }}
                className="relative rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--surface)]/90 p-3"
              >
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-[10px] font-black tracking-[0.18em] text-[var(--muted)]">STEP {step.id}</span>
                  <Floating3DIcon icon={Icon} tone={step.tone} iconClassName="fill-current stroke-current text-white/90" />
                </div>
                <p className="text-sm font-semibold text-[var(--text)]">{step.title}</p>
                <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">{step.detail}</p>
              </motion.div>
            );
          })}
        </div>

        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--surface)]/90 p-3">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-[var(--muted)]">
                Permission Scope
              </p>
              <span className="rounded-full bg-[var(--badge-green-bg)] px-2 py-0.5 text-[10px] font-medium text-[var(--badge-green-text)]">
                Least Privilege
              </span>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              {[
                { title: "Repository", items: ["Contents", "Metadata", "Pull Requests"] },
                { title: "Organization", items: ["Members", "Teams"] },
                { title: "Events", items: ["Push", "Pull Request"] },
              ].map((group) => (
                <div
                  key={group.title}
                  className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--elevated-surface)] p-2"
                >
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                    {group.title}
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {group.items.map((item) => (
                      <span
                        key={item}
                        className="rounded-full border border-[var(--border)] bg-[var(--surface)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]"
                      >
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--surface)]/90 p-3">
            <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.18em] text-[var(--muted)]">
              Why Teams Pick Zyloch
            </p>
            <div className="space-y-2">
              {[
                "Native GitHub workflow integration",
                "No agent install or code changes required",
                "One pane for policy, severity and remediation",
              ].map((item) => (
                <div
                  key={item}
                  className="flex items-start gap-2 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--elevated-surface)] px-2.5 py-2"
                >
                  <span className="mt-1 h-1.5 w-1.5 rounded-full bg-[var(--color-primary)]" />
                  <span className="text-[11px] text-[var(--text-secondary)]">{item}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </PremiumFrame>
  );
}

const slideVariants = {
  enter: (dir) => ({ x: dir > 0 ? 72 : -72, opacity: 0 }),
  center: { x: 0, opacity: 1 },
  exit: (dir) => ({ x: dir > 0 ? -72 : 72, opacity: 0 }),
};

export default function WelcomeStep() {
  const [[page, direction], setPage] = useState([0, 0]);

  const paginate = (newDir) => {
    setPage(([prev]) => {
      const next = prev + newDir;
      if (next < 0 || next >= slides.length) return [prev, 0];
      return [next, newDir];
    });
  };

  const goTo = (idx) => {
    setPage(([prev]) => [idx, idx > prev ? 1 : -1]);
  };

  const SlideContent = useMemo(() => [OverviewSlide, ScansSlide, WorkflowSlide][page], [page]);

  return (
    <div className="flex h-full w-full flex-col gap-3 p-3 md:gap-4 md:p-4" style={{ minHeight: 0 }}>
      <div className="flex items-center justify-between rounded-[var(--radius-lg)] border border-[var(--border)] bg-[var(--surface)]/70 px-3.5 py-2.5 md:px-4 md:py-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[var(--muted)]">Onboarding</p>
          <h2 className="text-lg font-bold text-[var(--text)]">Welcome to Zyloch</h2>
        </div>
        <span className="rounded-full border border-[var(--border)] bg-[var(--surface)] px-2.5 py-1 text-[10px] font-semibold text-[var(--muted)]">
          Slide {page + 1} of {slides.length}
        </span>
      </div>

      <div className="relative flex-1 overflow-hidden" style={{ minHeight: "360px" }}>
        <AnimatePresence initial={false} custom={direction} mode="wait">
          <motion.div
            key={page}
            custom={direction}
            variants={slideVariants}
            initial="enter"
            animate="center"
            exit="exit"
            transition={{ type: "spring", stiffness: 205, damping: 23 }}
            className="absolute inset-0"
          >
            <SlideContent />
          </motion.div>
        </AnimatePresence>
      </div>

      <div className="flex items-center justify-between border-t border-[var(--border)] pt-4 md:pt-5">
        <motion.button
          onClick={() => paginate(-1)}
          disabled={page === 0}
          whileHover={page !== 0 ? { x: -2 } : {}}
          whileTap={page !== 0 ? { scale: 0.98 } : {}}
          className="flex items-center gap-1.5 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--surface)] px-3.5 py-2 text-xs font-semibold text-[var(--text-secondary)] transition-all duration-200 hover:border-[var(--border-hover)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-40"
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M8.5 3.5L5 7l3.5 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          Prev
        </motion.button>

        <div className="flex items-center gap-2 md:gap-2.5">
          {slides.map((slide, idx) => (
            <button
              key={slide.id}
              onClick={() => goTo(idx)}
              className="group flex items-center gap-1"
            >
              <span
                className={`h-2 rounded-full transition-all duration-300 ${idx === page
                  ? "w-7 bg-[var(--color-primary)]"
                  : idx < page
                    ? "w-2 bg-[var(--success)]"
                    : "w-2 bg-[var(--border)] group-hover:bg-[var(--border-hover)]"
                  }`}
              />
              <span className={`hidden text-[10px] font-medium sm:inline ${idx === page ? "text-[var(--text-secondary)]" : "text-[var(--muted)]"}`}>
                {slide.label}
              </span>
            </button>
          ))}
        </div>

        <motion.button
          onClick={() => paginate(1)}
          disabled={page === slides.length - 1}
          whileHover={page !== slides.length - 1 ? { x: 2 } : {}}
          whileTap={page !== slides.length - 1 ? { scale: 0.98 } : {}}
          className="flex items-center gap-1.5 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--surface)] px-3.5 py-2 text-xs font-semibold text-[var(--text-secondary)] transition-all duration-200 hover:border-[var(--border-hover)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-40"
        >
          Next
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M5.5 3.5L9 7l-3.5 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </motion.button>
      </div>
    </div>
  );
}