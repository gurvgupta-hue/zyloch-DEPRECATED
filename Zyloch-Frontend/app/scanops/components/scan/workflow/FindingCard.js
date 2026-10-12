"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FileText, ChevronDown, ChevronUp } from "lucide-react";
import PolicyItem from "./PolicyItem";

const FindingCard = ({ finding }) => {
  const [open, setOpen] = useState(false);

  // File name logic
  const parts = finding.file_name.split("/");
  const fileName = parts.slice(-4).join("/");

  const totalIssues = finding.violated_policies.length;

  // Calculate severity counts
  const severityCounts = (finding.violated_policies || []).reduce((acc, policy) => {
    const sev = String(policy?.severity || "").trim().toLowerCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  // Severity configuration using root CSS variables
  const severityConfig = {
    critical: {
      color: 'var(--critical)',
      bgColor: 'var(--critical)20', // Using opacity through rgba in inline styles
      label: 'Critical'
    },
    high: {
      color: 'var(--high)',
      bgColor: 'var(--high)20',
      label: 'High'
    },
    medium: {
      color: 'var(--medium)',
      bgColor: 'var(--medium)20',
      label: 'Medium'
    },
    low: {
      color: 'var(--low)',
      bgColor: 'var(--low)20',
      label: 'Low'
    }
  };

  const severityOrder = ['critical', 'high', 'medium', 'low'];

  // Helper function to get rgba version of CSS variable
  const getRgbaColor = (colorVar, opacity) => {
    // This is a workaround - in a real app you might want to parse the RGB values
    // For now, we'll use the CSS color-mix function where supported
    return `color-mix(in srgb, ${colorVar} ${opacity * 100}%, transparent)`;
  };

  return (
    <div
      className="border rounded-xl"
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: "16px",
      }}
    >

      {/* HEADER */}
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 hover:bg-surface/50 transition-all duration-200 rounded-xl focus-ring"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3 text-left">
          <div className="p-2 bg-primary/10 rounded-lg">
            <FileText className="w-5 h-5 text-primary" />
          </div>

          <div>
            {/* MAIN TITLE — sliced filename */}
            <h4 className="font-semibold text-text font-ui">{fileName}</h4>

            {/* Severity badges in closed state */}
            {!open && (
              <div className="flex items-center gap-2 mt-1">
                {severityOrder.map(severity => {
                  const count = severityCounts[severity];
                  if (!count) return null;

                  const config = severityConfig[severity];

                  return (
                    <div
                      key={severity}
                      className="badge"
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '0 var(--space-2)',
                        minWidth: '50px',
                        height: '20px',
                        backgroundColor: `color-mix(in srgb, ${config.color} 10%, transparent)`,
                        borderRadius: 'var(--radius-full)',
                        border: `1px solid color-mix(in srgb, ${config.color} 30%, transparent)`,
                      }}
                    >
                      <span style={{
                        fontSize: 'var(--font-size-xs)',
                        fontWeight: 'var(--weight-medium)',
                        color: config.color,
                        lineHeight: '20px',
                        textTransform: 'uppercase'
                      }}>
                        {config.label}
                      </span>
                      <span style={{
                        fontSize: 'var(--font-size-xs)',
                        fontWeight: 'var(--weight-semibold)',
                        color: config.color,
                        lineHeight: '20px',
                        marginLeft: 'var(--space-1)'
                      }}>
                        {count}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="px-3 py-1 bg-warning/10 text-warning text-sm font-medium rounded-full border border-warning/20">
            {totalIssues} issue{totalIssues !== 1 ? "s" : ""}
          </span>

          {open ? (
            <ChevronUp className="w-5 h-5 text-muted transition-transform duration-200" />
          ) : (
            <ChevronDown className="w-5 h-5 text-muted transition-transform duration-200" />
          )}
        </div>
      </button>

      {/* DROPDOWN CONTENT */}
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="content"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            <div className="p-5 border-t border-border space-y-4 bg-surface">
              {finding.violated_policies.map((policy, idx) => (
                <PolicyItem key={idx} policy={policy} />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

    </div>
  );
};

export default FindingCard;