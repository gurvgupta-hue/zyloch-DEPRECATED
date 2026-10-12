"use client";

import React, { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronLeft, ChevronRight, Shield, ArrowRight, CheckCircle } from "lucide-react";
import { FaGithub as Github } from "react-icons/fa";
import Link from "next/link";

// Steps content
import WelcomeStep from "./WelcomeStep";
import InstallationStep from "./InstallationStep";

const navToneByStep = {
  1: {
    outer: "from-cyan-200/85 via-cyan-400/35 to-cyan-700/20",
    inner: "from-cyan-100 to-cyan-300/35",
    ring: "ring-cyan-300/40",
  },
  2: {
    outer: "from-violet-200/85 via-violet-400/35 to-violet-700/20",
    inner: "from-violet-100 to-violet-300/35",
    ring: "ring-violet-300/40",
  },
};

function Nav3DIcon({ icon: Icon, stepId, active, completed }) {
  const tone = navToneByStep[stepId] || navToneByStep[1];

  if (completed) {
    return (
      <span className="inline-flex h-9 w-9 items-center justify-center rounded-[12px] bg-[var(--success)] text-[var(--text-on-success)] shadow-[0_8px_20px_rgba(16,185,129,0.25)]">
        <CheckCircle className="h-4 w-4" />
      </span>
    );
  }

  return (
    <motion.span
      className={`relative inline-flex h-9 w-9 items-center justify-center overflow-hidden rounded-[12px] bg-gradient-to-br ${tone.outer} ring-1 ${tone.ring} shadow-[0_8px_18px_rgba(15,23,42,0.2)]`}
      animate={active ? { y: [0, -2, 0], rotateZ: [0, 1.2, 0], scale: [1, 1.03, 1] } : { y: [0, -1, 0], scale: [1, 1.015, 1] }}
      transition={{ duration: active ? 5.2 : 6.8, repeat: Infinity, ease: "easeInOut" }}
      whileHover={{ y: -2, scale: 1.04, rotateX: 6, rotateY: -8 }}
    >
      <span className={`absolute inset-[1px] rounded-[11px] bg-gradient-to-b ${tone.inner}`} />
      <motion.span
        className="absolute top-1 h-2.5 w-5 rounded-full bg-white/55 blur-[1px]"
        animate={{ x: [2, 8, 2], opacity: [0.4, 0.72, 0.4] }}
        transition={{ duration: active ? 4.2 : 5.8, repeat: Infinity, ease: "easeInOut" }}
      />
      <Icon className={`relative z-10 h-4 w-4 ${active ? "text-white" : "text-white/85"}`} />
    </motion.span>
  );
}

function AnimatedStageBackdrop({ step }) {
  const isWelcome = step === 1;
  const floatingAbstracts = [
    {
      key: "orb-cyan",
      cls: "-left-16 top-8 h-40 w-40",
      bg: isWelcome
        ? "radial-gradient(circle at 30% 30%, rgba(255,255,255,0.65), rgba(6,182,212,0.34) 48%, rgba(6,182,212,0) 72%)"
        : "radial-gradient(circle at 30% 30%, rgba(255,255,255,0.62), rgba(34,197,94,0.3) 48%, rgba(34,197,94,0) 72%)",
      blur: "blur-[1px]",
      shadow: isWelcome ? "0 22px 58px rgba(6,182,212,0.24)" : "0 22px 58px rgba(34,197,94,0.2)",
      duration: 9,
      delay: 0,
      movement: { y: [0, -10, 0], x: [0, 6, 0], rotateZ: [0, 8, 0] },
    },
    {
      key: "orb-purple",
      cls: "right-8 top-4 h-34 w-34",
      bg: isWelcome
        ? "radial-gradient(circle at 70% 26%, rgba(255,255,255,0.6), rgba(139,92,246,0.28) 50%, rgba(139,92,246,0) 74%)"
        : "radial-gradient(circle at 70% 26%, rgba(255,255,255,0.58), rgba(245,158,11,0.28) 50%, rgba(245,158,11,0) 74%)",
      blur: "blur-[1px]",
      shadow: isWelcome ? "0 22px 56px rgba(139,92,246,0.2)" : "0 22px 56px rgba(245,158,11,0.2)",
      duration: 10.5,
      delay: 0.3,
      movement: { y: [0, 12, 0], x: [0, -8, 0], rotateZ: [0, -9, 0] },
    },
    {
      key: "glass-plane",
      cls: "left-1/3 top-1/2 h-36 w-60 -translate-x-1/2 -translate-y-1/2",
      bg: isWelcome
        ? "linear-gradient(130deg, rgba(255,255,255,0.5), rgba(6,182,212,0.1) 42%, rgba(139,92,246,0.14) 100%)"
        : "linear-gradient(130deg, rgba(255,255,255,0.5), rgba(34,197,94,0.1) 42%, rgba(245,158,11,0.14) 100%)",
      blur: "backdrop-blur-[2px]",
      shadow: "0 16px 40px rgba(15,23,42,0.12)",
      duration: 12,
      delay: 0.5,
      movement: { y: [0, -8, 0], rotateZ: [-8, -2, -8], rotateX: [24, 18, 24] },
      border: "1px solid rgba(255,255,255,0.34)",
      radius: "18px",
    },
  ];

  return (
    <div className="pointer-events-none absolute inset-0">
      <div className="absolute -left-14 -top-16 h-44 w-64 rounded-full bg-[var(--color-primary)]/10 blur-3xl" />
      <div className="absolute -right-14 top-1/4 h-56 w-64 rounded-full bg-[var(--color-secondary)]/12 blur-3xl" />
      <div
        className="absolute inset-0 opacity-40"
        style={{
          background: isWelcome
            ? "radial-gradient(circle at 15% 20%, rgba(6,182,212,0.16), transparent 42%), radial-gradient(circle at 85% 15%, rgba(139,92,246,0.14), transparent 36%), radial-gradient(circle at 50% 90%, rgba(234,179,8,0.08), transparent 44%)"
            : "radial-gradient(circle at 15% 20%, rgba(34,197,94,0.14), transparent 42%), radial-gradient(circle at 85% 15%, rgba(245,158,11,0.14), transparent 36%), radial-gradient(circle at 50% 90%, rgba(59,130,246,0.08), transparent 44%)",
        }}
      />
      <div className="absolute inset-0 [perspective:1000px]">
        {floatingAbstracts.map((shape) => (
          <motion.div
            key={shape.key}
            className={`absolute rounded-full ${shape.cls} ${shape.blur}`}
            style={{
              background: shape.bg,
              boxShadow: shape.shadow,
              border: shape.border,
              borderRadius: shape.radius,
              transformStyle: "preserve-3d",
            }}
            animate={shape.movement}
            transition={{ duration: shape.duration, repeat: Infinity, ease: "easeInOut", delay: shape.delay }}
          />
        ))}
        <motion.div
          className="absolute bottom-0 right-1/4 h-48 w-48 rounded-full border border-[var(--border)]/40"
          style={{
            background:
              isWelcome
                ? "conic-gradient(from 0deg, rgba(6,182,212,0.3), rgba(139,92,246,0.14), rgba(234,179,8,0.16), rgba(6,182,212,0.3))"
                : "conic-gradient(from 0deg, rgba(34,197,94,0.28), rgba(245,158,11,0.14), rgba(59,130,246,0.18), rgba(34,197,94,0.28))",
            filter: "blur(0.5px)",
            boxShadow: "inset 0 0 30px rgba(255,255,255,0.28)",
          }}
          animate={{ rotate: [0, 360] }}
          transition={{ duration: 32, repeat: Infinity, ease: "linear" }}
        />
        <motion.div
          className="absolute left-1/2 top-[18%] h-[1px] w-64 -translate-x-1/2 bg-gradient-to-r from-transparent via-white/40 to-transparent"
          animate={{ opacity: [0.25, 0.75, 0.25], scaleX: [0.9, 1.08, 0.9] }}
          transition={{ duration: 4.5, repeat: Infinity, ease: "easeInOut" }}
        />
      </div>
      <motion.div
        className="absolute inset-0 opacity-70"
        animate={{ opacity: [0.54, 0.72, 0.54] }}
        transition={{ duration: 10, repeat: Infinity, ease: "easeInOut" }}
        style={{
          backgroundImage:
            "linear-gradient(to right, rgba(148,163,184,0.07) 1px, transparent 1px), linear-gradient(to bottom, rgba(148,163,184,0.07) 1px, transparent 1px)",
          backgroundSize: "24px 24px",
          maskImage: "radial-gradient(circle at center, black 30%, transparent 86%)",
          WebkitMaskImage: "radial-gradient(circle at center, black 30%, transparent 86%)",
        }}
      />
    </div>
  );
}

export default function SecureCodeAgent() {
  const [step, setStep] = useState(1);

  const steps = useMemo(
    () => [
      {
        id: 1,
        title: "Welcome",
        description: "Discover Zyloch's capabilities",
        icon: Shield,
      },
      {
        id: 2,
        title: "Installation",
        description: "Set up in minutes",
        icon: Github,
      },
    ],
    []
  );

  const nextStep = () => setStep((s) => Math.min(s + 1, steps.length));
  const prevStep = () => setStep((s) => Math.max(s - 1, 1));

  const containerVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.5,
        ease: [0.4, 0, 0.2, 1],
      },
    },
  };

  return (
    <div className="relative h-full w-full overflow-hidden bg-[var(--bg)]">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-32 -top-28 h-72 w-72 rounded-full bg-[var(--color-primary)]/12 blur-3xl" />
        <div className="absolute -right-24 top-1/4 h-72 w-72 rounded-full bg-[var(--color-secondary)]/12 blur-3xl" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_0%_0%,rgba(6,182,212,0.08),transparent_30%),radial-gradient(circle_at_100%_100%,rgba(139,92,246,0.08),transparent_30%)]" />
      </div>
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="relative z-10 flex h-full w-full flex-col"
      >
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="shrink-0 px-4 pb-4 pt-4 text-center md:px-6 md:pb-5 md:pt-5"
        >
          {/* Logo */}
          <div className="flex gap-3 items-center justify-center">


            <div className="inline-flex items-center justify-center gap-2">
              <h1 className="text-xl md:text-2xl font-bold gradient-text">
                Zyloch
              </h1>
            </div>

            {/* Badge */}
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[var(--badge-purple-bg)] border border-[var(--badge-purple-border)]">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-secondary)]" />
              <span className="text-xs font-medium text-[var(--badge-purple-text)]">
                Secure CI · GitHub App
              </span>
            </div>
          </div>

          {/* Trust Message */}
          <p className="mt-2 text-xs text-[var(--muted)]">
            Enterprise-grade security · Zero configuration
          </p>

          <div className="mt-3 flex items-center justify-center gap-2">
            <span className="badge-cyan inline-flex items-center gap-1 rounded-full px-2 py-1 text-[10px] font-medium">
              <span className="h-1 w-1 rounded-full bg-current opacity-60" />
              Live onboarding
            </span>
            <span className="badge-green inline-flex items-center gap-1 rounded-full px-2 py-1 text-[10px] font-medium">
              <span className="h-1 w-1 rounded-full bg-current opacity-60" />
              SOC2-ready
            </span>
          </div>
        </motion.div>

        {/* Main Card */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2, duration: 0.4 }}
          className="
            border border-[var(--border)]
            bg-[var(--surface)]/92 backdrop-blur
            mx-3 mb-3 rounded-[22px] md:mx-4 md:mb-4 md:rounded-[26px]
            shadow-[var(--shadow-2)]
            overflow-hidden
            flex-1 min-h-0
          "
        >
          <div className="flex h-full flex-col lg:flex-row">
            {/* Sidebar */}
            <aside className="
              lg:w-80
              bg-[var(--surface)]/60
              border-b lg:border-b-0 lg:border-r
              border-[var(--border)]
              lg:h-full
            ">
              <div className="p-4 md:p-5 lg:p-6">
                {/* Progress */}
                <div className="mb-6 rounded-[var(--radius-lg)] border border-[var(--border)] bg-[var(--elevated-surface)]/70 p-3.5">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium text-[var(--muted)]">
                      Setup Progress
                    </span>
                    <span className="text-xs font-semibold text-[var(--color-primary)]">
                      {Math.round((step / steps.length) * 100)}%
                    </span>
                  </div>

                  <div className="w-full h-1.5 bg-[var(--border)] rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(step / steps.length) * 100}%` }}
                      transition={{ duration: 0.4, ease: "easeOut" }}
                      className="h-full bg-gradient-to-r from-[var(--color-primary)] to-[var(--color-secondary)] rounded-full"
                    />
                  </div>
                </div>

                {/* Steps Navigation */}
                <nav className="space-y-2">
                  {steps.map(({ id, title, description, icon: Icon }) => {
                    const isActive = step === id;
                    const isCompleted = step > id;

                    return (
                      <motion.button
                        key={id}
                        onClick={() => setStep(id)}
                        whileHover={{ x: 4 }}
                        whileTap={{ scale: 0.98 }}
                        className={`
                          w-full flex items-start gap-3 p-3.5
                          rounded-[var(--radius-lg)]
                          transition-all duration-200
                          ${isActive
                            ? "bg-[var(--color-primary)]/10 border border-[var(--color-primary)]/30 shadow-[var(--shadow-1)]"
                            : "border border-transparent hover:bg-[var(--elevated-surface)]"
                          }
                        `}
                      >
                        {/* Step Indicator */}
                        <Nav3DIcon icon={Icon} stepId={id} active={isActive} completed={isCompleted} />

                        {/* Labels */}
                        <div className="flex-1 text-left">
                          <p className={`
                            text-sm font-semibold mb-0.5
                            ${isActive ? "text-[var(--color-primary)]" : "text-[var(--text)]"}
                          `}>
                            {title}
                          </p>
                          <p className="text-xs text-[var(--muted)]">
                            {description}
                          </p>
                        </div>

                        {/* Active Indicator */}
                        {isActive && (
                          <motion.div
                            initial={{ scale: 0 }}
                            animate={{ scale: 1 }}
                            className="w-1.5 h-1.5 rounded-full bg-[var(--color-primary)]"
                          />
                        )}
                      </motion.button>
                    );
                  })}
                </nav>

                {/* Sidebar Footer */}
                <div className="mt-6 border-t border-[var(--border)] pt-4">
                  <div className="flex items-center gap-2 text-xs text-[var(--muted)]">
                    <div className="w-2 h-2 rounded-full bg-[var(--success)] animate-pulse" />
                    <span>All systems operational</span>
                  </div>
                </div>
              </div>
            </aside>

            {/* Main Content Area */}
            <main className="flex min-h-0 min-w-0 flex-1 flex-col bg-[var(--bg)]/40">
              <div className="flex h-full min-h-0 flex-col p-4 md:p-5 lg:p-6">
                {/* Content with Animation */}
                <motion.div
                  className="relative flex-1 min-h-0 overflow-hidden rounded-[22px] border border-[var(--border)] bg-[var(--surface)]/86"
                  animate={{ y: [0, -1, 0] }}
                  transition={{ duration: 8.5, repeat: Infinity, ease: "easeInOut" }}
                >
                  <AnimatedStageBackdrop step={step} />
                  <div className="relative z-10 h-full">
                    <AnimatePresence mode="wait">
                      <motion.div
                        key={step}
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        transition={{
                          duration: 0.25,
                          ease: [0.4, 0, 0.2, 1]
                        }}
                        className="h-full"
                      >
                        {step === 1 && <WelcomeStep />}
                        {step === 2 && <InstallationStep />}
                      </motion.div>
                    </AnimatePresence>
                  </div>
                </motion.div>

                {/* Navigation Controls */}
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.3 }}
                  className="mt-5 flex flex-col items-stretch gap-3 border-t border-[var(--border)] pt-5 sm:mt-6 sm:flex-row sm:items-center sm:pt-6"
                >
                  {/* Back Button */}
                  <motion.button
                    onClick={prevStep}
                    disabled={step === 1}
                    whileHover={step !== 1 ? { x: -2 } : {}}
                    whileTap={step !== 1 ? { scale: 0.97 } : {}}
                    className={`
                      group
                      flex items-center justify-center gap-2
                      w-full sm:w-auto
                      px-5 py-2.5
                      rounded-[var(--radius-lg)]
                      text-sm font-medium
                      transition-all duration-200
                      ${step === 1
                        ? "cursor-not-allowed bg-[var(--border)]/50 text-[var(--muted)] opacity-50"
                        : "border border-[var(--border)] bg-[var(--surface)] text-[var(--text-secondary)] hover:border-[var(--border-accent)] hover:text-[var(--color-primary)] hover:shadow-[var(--shadow-soft)] active:shadow-[var(--shadow-1)]"
                      }
                    `}
                  >
                    <ChevronLeft className={`
                      w-4 h-4 
                      transition-transform duration-200
                      ${step !== 1 ? "group-hover:-translate-x-0.5" : ""}
                    `} />
                    <span>Back</span>
                  </motion.button>

                  {/* Center Status - Optional Step Indicator */}
                  <div className="hidden sm:flex items-center gap-2 px-1">
                    {steps.map((s) => (
                      <div
                        key={s.id}
                        className={`
                          w-2 h-2 rounded-full transition-all duration-300
                          ${s.id === step
                            ? "bg-[var(--color-primary)] scale-125"
                            : s.id < step
                              ? "bg-[var(--success)]"
                              : "bg-[var(--border)]"
                          }
                        `}
                      />
                    ))}
                  </div>

                  <div className="hidden sm:block sm:flex-1" />

                  {/* =========================================================== */}
                  {/* CONTINUE BUTTON - Same Style as Back Button */}
                  {/* =========================================================== */}
                  {step < steps.length ? (
                    <motion.button
                      onClick={nextStep}
                      whileHover={step !== steps.length ? { x: 2 } : {}}
                      whileTap={step !== steps.length ? { scale: 0.97 } : {}}
                      className="
                        group
                        flex w-full items-center justify-center gap-2 rounded-[var(--radius-lg)]
                        border border-[var(--border)] bg-[var(--surface)] px-5 py-2.5 text-sm font-medium
                        text-[var(--text-secondary)] transition-all duration-200 hover:border-[var(--border-accent)]
                        hover:text-[var(--color-primary)] hover:shadow-[var(--shadow-soft)] active:shadow-[var(--shadow-1)] sm:w-auto
                      "
                    >
                      <span>Continue to {steps[step].title}</span>
                      <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                    </motion.button>
                  ) : (
                    <Link href="/dashboard" className="w-full sm:w-auto">
                      <motion.div
                        initial={{ scale: 0.95 }}
                        animate={{ scale: 1 }}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        className="
                          group
                          flex items-center justify-center gap-2
                          w-full
                          px-5 py-2.5
                          bg-gradient-to-r from-[var(--success)] to-[var(--success)]/90
                          text-white
                          rounded-[var(--radius-lg)]
                          text-sm font-semibold
                          shadow-[var(--shadow-soft)]
                          hover:shadow-[var(--shadow-medium)]
                          transition-all duration-200
                          cursor-pointer
                          relative overflow-hidden
                          before:absolute before:inset-0
                          before:bg-gradient-to-r before:from-transparent before:via-white/20 before:to-transparent
                          before:-skew-x-12
                          before:translate-x-[-100%]
                          hover:before:translate-x-[100%]
                          before:transition-transform before:duration-700
                        "
                      >
                        <span className="relative z-10">Go to Dashboard</span>
                        <ChevronRight className="w-4 h-4 relative z-10 group-hover:translate-x-0.5 transition-transform" />
                      </motion.div>
                    </Link>
                  )}
                </motion.div>

                {/* Keyboard Shortcuts Hint */}
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className="mt-3 flex justify-center text-[10px] text-[var(--muted)] sm:justify-end"
                >
                  <div className="flex items-center gap-3">
                    {step > 1 && (
                      <span className="flex items-center gap-1">
                        <kbd className="px-1.5 py-0.5 bg-[var(--surface)] border border-[var(--border)] rounded-[var(--radius-xs)] text-[9px]">←</kbd>
                        <span>back</span>
                      </span>
                    )}
                    {step < steps.length && (
                      <span className="flex items-center gap-1">
                        <kbd className="px-1.5 py-0.5 bg-[var(--surface)] border border-[var(--border)] rounded-[var(--radius-xs)] text-[9px]">→</kbd>
                        <span>next</span>
                      </span>
                    )}
                  </div>
                </motion.div>
              </div>
            </main>
          </div>
        </motion.div>


      </motion.div>
    </div>
  );
}