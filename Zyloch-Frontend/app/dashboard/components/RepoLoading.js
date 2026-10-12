"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Loader2, Circle, Clock, FolderGit2, Info } from "lucide-react";
import { estimateSyncWindow, syncEtaLabel, formatDuration } from "@/lib/syncEstimate";

/**
 * What the dashboard shows while an installation is being populated.
 *
 * The first sync of a large organisation runs for hours — GitHub is walked
 * repository by repository for branches, commits and languages, under a rate
 * limit. A bare "Please wait…" spinner for that long reads as a hung page, so
 * this screen states the expected window up front, narrows it to a live estimate
 * once there is real progress to extrapolate from, and says plainly that the
 * work continues after the tab is closed.
 *
 * `variant="inline"` is the small form used inside a populated page (a section
 * reloading); `variant="spinner"` is the bare loader shown while the dashboard
 * works out which state it is in; the full form is the whole-screen sync state.
 */

/** The phases the summary job moves through, keyed to its own progress scale. */
const PHASES = [
  { upTo: 40, label: "Discovering repositories" },
  { upTo: 70, label: "Reading languages and branches" },
  { upTo: 95, label: "Building your summary" },
  { upTo: 100, label: "Finishing up" },
];

function Spinner({ className = "w-16 h-16" }) {
  return (
    <div className="relative flex items-center justify-center">
      <div className="absolute w-24 h-24 rounded-full bg-[var(--color-primary)] opacity-10 blur-2xl" />
      <Loader2 className={`relative z-10 ${className} text-[var(--color-primary)] animate-spin`} />
    </div>
  );
}

/** A finished step: the tick is drawn rather than popped in. */
function StepCheck() {
  return (
    <svg viewBox="0 0 24 24" className="w-4 h-4 shrink-0" aria-hidden="true">
      <circle cx="12" cy="12" r="10" fill="none" stroke="var(--success)" strokeWidth="2" />
      <path
        d="M7.5 12.5l3 3 6-6.5"
        fill="none"
        stroke="var(--success)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="animate-check-draw"
      />
    </svg>
  );
}

function Stat({ label, value }) {
  return (
    <div
      className="flex-1 min-w-[150px] rounded-[var(--radius-lg)] px-4 py-3"
      style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
    >
      <p
        className="text-[11px] uppercase tracking-wide font-medium"
        style={{ color: "var(--muted)" }}
      >
        {label}
      </p>
      <p className="text-lg font-semibold mt-1 leading-tight" style={{ color: "var(--text)" }}>
        {value}
      </p>
    </div>
  );
}

export default function RepoLoading({
  message = "Please wait while we update your data...",
  variant = "full",
  status = "in_progress",
  progress = 0,
  repoTarget = 0,
  repoProcessed = 0,
  startedAt = null,
  accountLogin = null,
}) {
  // Elapsed time and the live estimate both move on their own; a slow tick keeps
  // them honest without re-rendering the page every second.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 15000);
    return () => clearInterval(id);
  }, []);

  const pct = Math.min(Math.max(Number(progress) || 0, 0), 100);
  const sizeBand = useMemo(() => estimateSyncWindow(repoTarget), [repoTarget]);
  const eta = useMemo(
    () => syncEtaLabel({ repoCount: repoTarget, progress: pct, startedAt, now }),
    [repoTarget, pct, startedAt, now]
  );
  const elapsed = startedAt ? formatDuration(now - new Date(startedAt).getTime()) : null;
  const currentPhase = PHASES.find((phase) => pct < phase.upTo) || PHASES[PHASES.length - 1];

  // Just the round loader: the page is still asking the server whether a sync is
  // running, so it must not claim one is.
  if (variant === "spinner") {
    return (
      <div
        role="status"
        aria-label={message}
        className="flex items-center justify-center min-h-[60vh] w-full"
      >
        <Spinner />
      </div>
    );
  }

  if (variant === "inline") {
    return (
      <div className="flex items-center gap-3 py-8 justify-center">
        <Loader2 className="w-5 h-5 animate-spin text-[var(--color-primary)]" />
        <span className="text-sm" style={{ color: "var(--muted)" }}>
          {message}
        </span>
      </div>
    );
  }

  return (
    <div className="w-full min-h-screen px-[var(--space-4)] py-[var(--space-10)] md:px-[var(--space-8)]">
      <div className="mx-auto w-full max-w-2xl flex flex-col items-center animate-fade-up">
        <Spinner />

        <h1
          className="text-2xl md:text-3xl font-semibold mt-6 tracking-tight text-center"
          style={{ color: "var(--text)" }}
        >
          {status === "pending" ? "Your sync is queued" : "Building your dashboard"}
        </h1>

        <p className="text-sm mt-2 text-center max-w-xl leading-relaxed" style={{ color: "var(--muted)" }}>
          {accountLogin ? (
            <>
              We are reading <span className="font-medium" style={{ color: "var(--text)" }}>{accountLogin}</span>
              {repoTarget ? ` ${repoTarget.toLocaleString()} repositories` : ""}. {message}
            </>
          ) : (
            message
          )}
        </p>

        {/* Progress */}
        <div className="w-full mt-8">
          <div className="flex items-center justify-between text-xs mb-2">
            <span className="font-medium" style={{ color: "var(--text-secondary)" }}>
              {currentPhase.label}
            </span>
            <span style={{ color: pct > 0 ? "var(--color-primary)" : "var(--muted)" }}>
              {pct > 0 ? `${pct}%` : "starting…"}
            </span>
          </div>

          <div
            className="h-1.5 w-full rounded-full overflow-hidden"
            style={{ background: "var(--elevated-surface)", border: "1px solid var(--border)" }}
          >
            {/* Before the first real value the bar is a small pulsing sliver, not a
                15% placeholder: the placeholder shrank back to the left the moment
                the job reported 1–2%, which read as the sync restarting. */}
            <div
              className={`h-full rounded-full transition-[width] duration-700 ease-out ${pct > 0 ? "" : "animate-pulse"}`}
              style={{
                width: `${Math.max(pct, 2)}%`,
                background: "var(--color-primary)",
              }}
            />
          </div>

          <div className="flex items-center gap-2 mt-3 text-sm" style={{ color: "var(--text-secondary)" }}>
            <Clock className="w-4 h-4 shrink-0" style={{ color: "var(--color-primary)" }} />
            <span>{eta}</span>
          </div>
        </div>

        {/* Numbers */}
        <div className="flex flex-wrap gap-3 mt-6 w-full">
          {repoTarget > 0 && <Stat label="Repositories" value={repoTarget.toLocaleString()} />}
          {repoProcessed > 0 && (
            <Stat label="Processed" value={`${repoProcessed.toLocaleString()} of ${repoTarget.toLocaleString()}`} />
          )}
          {elapsed && <Stat label="Elapsed" value={elapsed} />}
          <Stat label="Typical for this size" value={sizeBand.label} />
        </div>

        {/* Phases */}
        <ol className="w-full mt-6 space-y-2.5">
          {PHASES.map((phase) => {
            const done = pct >= phase.upTo;
            const active = phase.label === currentPhase.label;
            return (
              <li key={phase.label} className="flex items-center gap-2.5 text-sm">
                {done ? (
                  <StepCheck />
                ) : (
                  <Circle
                    className={`w-4 h-4 shrink-0 ${active ? "animate-pulse" : ""}`}
                    style={{ color: active ? "var(--color-primary)" : "var(--text-disabled)" }}
                  />
                )}
                <span
                  style={{
                    color: done ? "var(--success)" : active ? "var(--text)" : "var(--muted)",
                    fontWeight: active ? 500 : 400,
                  }}
                >
                  {phase.label}
                </span>
              </li>
            );
          })}
        </ol>

        {/* The part that stops people from staring at the page */}
        <div
          className="flex items-start gap-3 mt-8 w-full rounded-[var(--radius-lg)] px-4 py-3"
          style={{ background: "var(--elevated-surface)", border: "1px solid var(--border)" }}
        >
          <Info className="w-4 h-4 mt-0.5 shrink-0" style={{ color: "var(--color-primary)" }} />
          <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            This runs in the background. You can close this page and come back later, the sync keeps
            going, and the dashboard fills in as it completes.{" "}
            <span style={{ color: "var(--muted)" }}>
              Large organisations can take up to 24 hours on the first sync; later refreshes only pick
              up what changed.
            </span>
          </p>
        </div>
      </div>
    </div>
  );
}
