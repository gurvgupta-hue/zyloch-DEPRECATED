"use client";

import React, { useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import LightningBoltIcon from "@/public/assets/icons/scan/installation/lightning-bolt.svg";
import GithubMinimalIcon from "@/public/assets/icons/scan/installation/github-minimal.svg";
import ArrowRightIcon from "@/public/assets/icons/scan/installation/arrow-right.svg";

export default function InstallationCard() {
  const [activeStep, setActiveStep] = useState(1);
  const githubAppUrl =
    process.env.NEXT_PUBLIC_GITHUB_APP_URL || "https://github.com/apps/zyloch-security";

  const steps = [
    {
      number: "01",
      title: "Install the GitHub App",
      description: "Authorize Zyloch on your GitHub account or org",
    },
    {
      number: "02",
      title: "Select repositories",
      description: "Choose all repos or pick specific ones to monitor",
    },
    {
      number: "03",
      title: "Connect your workspace",
      description: "Sign in to begin continuous coverage",
    },
  ];

  const permissions = [
    "Read · Contents",
    "Read · Metadata",
    "Read · Pull requests",
  ];

  return (
    <div className="w-full h-full flex flex-col justify-between rounded-[32px] border border-[var(--border)] bg-[var(--surface)] p-6 sm:p-7 xl:p-8 shadow-xs relative transition-colors duration-200">
      <div className="flex flex-col">
        {/* Top Badges Row */}
        <div className="flex items-center justify-between gap-2 flex-wrap mb-1">
          <span className="text-[12px] font-semibold text-[var(--muted)] uppercase tracking-wider">
            Installation
          </span>

          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[var(--badge-yellow-bg)] text-[var(--badge-yellow-text)] border border-[var(--badge-yellow-border)]">
              <LightningBoltIcon className="w-3.5 h-3.5 fill-[var(--badge-yellow-text)] text-[var(--badge-yellow-text)]" />
              Setup &lt; 2 min
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold bg-[var(--elevated-surface)] text-[var(--text-secondary)] border border-[var(--border)]">
              <GithubMinimalIcon className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
              GitHub App
            </span>
          </div>
        </div>

        {/* Heading */}
        <h2 className="pt-3 text-2xl sm:text-3xl lg:text-[34px] xl:text-[36px] font-bold text-[var(--text)] tracking-tight leading-[1.15]">
          Connect via GitHub
        </h2>

        {/* Subtitle */}
        <p className="pt-2 text-xs sm:text-sm lg:text-[14px] text-[var(--text-secondary)] leading-relaxed">
          Install the Zyloch GitHub App to begin monitoring your repositories in minutes.
        </p>

        {/* 3 Step Numbered List */}
        <div className="pt-4 space-y-2.5">
          {steps.map((step, idx) => {
            const isSelected = activeStep === idx + 1;
            return (
              <motion.div
                key={step.number}
                whileHover={{ scale: 1.006 }}
                onClick={() => setActiveStep(idx + 1)}
                className={`flex items-start gap-3.5 p-3.5 sm:p-4 rounded-[16px] border cursor-pointer transition-all duration-200 ${
                  isSelected
                    ? "border-[var(--color-primary)] bg-[var(--badge-cyan-bg)] shadow-2xs"
                    : "border-[var(--border-subtle)] bg-[var(--elevated-surface)] hover:border-[var(--border)]"
                }`}
              >
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 text-[12px] font-semibold transition-colors ${
                    isSelected
                      ? "bg-[var(--color-primary)] text-white"
                      : "bg-[var(--border)] text-[var(--muted)]"
                  }`}
                >
                  {step.number}
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="text-xs sm:text-[14px] font-semibold text-[var(--text)]">
                    {step.title}
                  </h3>
                  <p className="text-[11px] sm:text-[12px] text-[var(--muted)] pt-0.5 leading-relaxed">
                    {step.description}
                  </p>
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Read-Only Permission Badges */}
        <div className="pt-3.5 flex flex-wrap items-center gap-2">
          {permissions.map((perm) => (
            <span
              key={perm}
              className="inline-flex items-center px-3 py-1 rounded-full text-[11px] font-medium text-[var(--text-secondary)] border border-[var(--border)] bg-[var(--elevated-surface)]"
            >
              {perm}
            </span>
          ))}
        </div>
      </div>

      {/* Action Buttons Section */}
      <div className="pt-4 shrink-0 space-y-3">
        {/* Figma Button Frame Container */}
        <div className="p-3.5 rounded-[16px] border border-[var(--border-subtle)] bg-[var(--elevated-surface)]">
          {/* Primary CTA Button: Install GitHub App */}
          <Link
            href={githubAppUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="group relative flex w-full h-[52px] items-center justify-center gap-2.5 rounded-[12px] bg-[var(--color-primary)] hover:bg-[var(--color-primary-600)] active:opacity-90 px-5 font-semibold text-white shadow-md transition-all duration-200 hover:shadow-lg active:scale-[0.99] !no-underline"
          >
            <GithubMinimalIcon className="w-5 h-5 text-white shrink-0 group-hover:scale-105 transition-transform" />
            <span className="text-[14px] font-semibold text-white tracking-wide">
              Install GitHub App
            </span>
          </Link>
        </div>

        {/* Secondary CTA Button: Go to dashboard */}
        <Link
          href="/dashboard"
          className="group flex w-full h-[50px] items-center justify-center gap-2 rounded-[12px] border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--elevated-surface)] px-5 text-[14px] font-medium text-[var(--text-secondary)] transition-all duration-200 shadow-2xs hover:border-[var(--border-hover)] !no-underline"
        >
          <span className="font-medium text-[var(--text-secondary)]">
            Go to dashboard
          </span>
          <ArrowRightIcon className="w-4 h-4 text-[var(--muted)] group-hover:translate-x-0.5 transition-transform" />
        </Link>

        {/* Status Hint */}
        <p className="text-center text-[12px] font-normal text-[var(--muted)] pt-0.5">
          Your dashboard unlocks once the app is connected.
        </p>
      </div>
    </div>
  );
}
