"use client";

import React from "react";
import { FaGithub } from "react-icons/fa";
import { RefreshCw } from "lucide-react";

/**
 * Shown between the GitHub App install redirect and the moment the installation
 * is recorded on our side. Without it the dashboard said "Connect Your GitHub
 * Account" and the account list was empty — right after the customer had just
 * done exactly that — which reads as a failed install.
 *
 * `timedOut` swaps the animation for a plain explanation and a manual re-check,
 * so the page never spins indefinitely.
 */

const CARD = {
  background: "var(--surface)",
  border: "1px solid var(--border)",
  boxShadow: "var(--shadow-1)",
};

function ConnectingMark({ animated = true }) {
  return (
    <div className="relative flex items-center justify-center w-20 h-20" aria-hidden="true">
      {animated &&
        [0, 400, 800].map((delay) => (
          <span
            key={delay}
            className="absolute inset-0 rounded-full animate-ring-pulse"
            style={{
              border: "2px solid var(--color-primary)",
              animationDelay: `${delay}ms`,
            }}
          />
        ))}
      <span
        className="relative flex items-center justify-center w-16 h-16 rounded-full"
        style={{
          background: "var(--surface)",
          boxShadow: "0 0 0 1px rgba(var(--color-primary-rgb), 0.25)",
        }}
      >
        <FaGithub size={32} style={{ color: "var(--text)" }} />
      </span>
    </div>
  );
}

export default function InstallationConnecting({ timedOut = false, onRetry }) {
  return (
    <div
      role="status"
      aria-label={timedOut ? "Installation is taking longer than usual" : "Connecting to your GitHub account"}
      className="flex items-start justify-center w-full min-h-[70vh] px-[var(--space-4)] py-[var(--space-10)]"
    >
      <div
        className="w-full max-w-md rounded-[var(--radius-xl)] px-8 py-10 text-center animate-fade-up"
        style={CARD}
      >
        <div className="flex justify-center">
          <ConnectingMark animated={!timedOut} />
        </div>

        <h1 className="text-lg font-semibold mt-6 tracking-tight" style={{ color: "var(--text)" }}>
          {timedOut ? "This is taking longer than usual" : "Connecting to your GitHub account"}
          {!timedOut && (
            <span aria-hidden="true" className="inline-flex ml-0.5">
              {[0, 150, 300].map((delay) => (
                <span key={delay} className="animate-bounce" style={{ animationDelay: `${delay}ms` }}>
                  .
                </span>
              ))}
            </span>
          )}
        </h1>

        <p className="text-sm mt-2 leading-relaxed" style={{ color: "var(--muted)" }}>
          {timedOut
            ? "GitHub hasn't finished handing over your installation yet. It will complete in the background — check again in a minute."
            : "GitHub is finishing the installation. This can take a minute or two, you'll be able to pick the account as soon as it's ready."}
        </p>

        {timedOut ? (
          <button
            type="button"
            onClick={onRetry}
            className="mt-6 inline-flex items-center gap-2 px-4 py-2 rounded-[var(--radius-md)] text-sm font-medium transition-colors"
            style={{ backgroundColor: "var(--color-primary)", color: "var(--text-on-primary)" }}
            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = "var(--color-primary-600)")}
            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "var(--color-primary)")}
          >
            <RefreshCw className="w-4 h-4" />
            Check again
          </button>
        ) : (
          <div
            className="mt-8 h-1 w-full rounded-full overflow-hidden"
            style={{ background: "var(--elevated-surface)" }}
          >
            <div
              className="h-full w-2/5 rounded-full animate-bar-sweep"
              style={{
                background:
                  "linear-gradient(90deg, transparent, var(--color-primary), transparent)",
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
