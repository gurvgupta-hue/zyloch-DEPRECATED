import React, { useEffect, useState } from "react";
import { X, AlertCircle, Copy, Check, Eye, EyeOff } from "lucide-react";

const FindingDetailsSidebar = ({ finding, isOpen, onClose }) => {
  const [copiedValue, setCopiedValue] = useState(false);
  const [copiedPath, setCopiedPath] = useState(false);
  const [showFullValue, setShowFullValue] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(false);

  useEffect(() => {
    const root = document.documentElement;

    const syncTheme = () => {
      setIsDarkMode(root.getAttribute("data-theme") === "dark");
    };

    syncTheme();

    const observer = new MutationObserver(syncTheme);
    observer.observe(root, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });

    return () => observer.disconnect();
  }, []);

  if (!finding) return null;

  const getSeverityConfig = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return {
          icon: <AlertCircle className="w-3 h-3" />,
          label: "Critical",
          bg: "rgba(var(--danger-rgb), 0.16)",
          text: "var(--danger)",
        };
      case "high":
        return {
          icon: <AlertCircle className="w-3 h-3" />,
          label: "High",
          bg: "rgba(var(--warning-rgb), 0.16)",
          text: "var(--warning)",
        };
      case "medium":
        return {
          icon: <AlertCircle className="w-3 h-3" />,
          label: "Medium",
          bg: "rgba(var(--color-primary-rgb), 0.16)",
          text: "var(--color-primary)",
        };
      default:
        return {
          icon: <AlertCircle className="w-3 h-3" />,
          label: "Low",
          bg: "rgba(var(--info-rgb), 0.16)",
          text: "var(--info)",
        };
    }
  };

  const severityConfig = getSeverityConfig(finding.severity);
  const title = finding.pattern_type || finding.policy_name || finding.description || "Finding Details";
  const hasMetaInfo = Boolean(finding.category || finding.severity);
  const hasDetailSections = Boolean(
    finding.description || finding.file_name || finding.redacted_value || finding.remediation
  );

  const handleCopyValue = () => {
    if (!finding.redacted_value) return;
    navigator.clipboard.writeText(finding.redacted_value);
    setCopiedValue(true);
    setTimeout(() => setCopiedValue(false), 2000);
  };

  const handleCopyPath = () => {
    if (!finding.file_name) return;
    navigator.clipboard.writeText(finding.file_name);
    setCopiedPath(true);
    setTimeout(() => setCopiedPath(false), 2000);
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className={`fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-300 z-[90] ${
          isOpen ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
        style={{
          backgroundColor: isDarkMode ? "rgba(0, 0, 0, 0.65)" : "rgba(0, 0, 0, 0.45)",
          backdropFilter: isDarkMode ? "blur(12px)" : "blur(4px)",
          WebkitBackdropFilter: isDarkMode ? "blur(12px)" : "blur(4px)",
        }}
        onClick={onClose}
      />

      {/* Sidebar */}
      <div
        className={`fixed top-0 right-0 z-[100] h-screen w-[520px] overflow-y-auto transform transition-transform duration-300 ease-in-out ${
          isOpen ? "translate-x-0" : "translate-x-full"
        }`}
        style={{
          background: "var(--surface)",
          borderLeft: "1px solid var(--border)",
          boxShadow: isDarkMode ? "-8px 0 40px rgba(0,0,0,0.35)" : "-6px 0 24px rgba(15,23,42,0.12)",
        }}
      >
        {/* Header */}
        <div
          className="sticky top-0 z-10 flex items-center justify-between px-5 py-3"
          style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}
        >
          <span
            className="inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-bold tracking-wider"
            style={{
              backgroundColor: severityConfig.bg,
              color: severityConfig.text,
              border: "1px solid var(--border)",
            }}
          >
            {severityConfig.icon}
            {severityConfig.label}
          </span>

          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded p-1.5 transition-colors"
            style={{ color: "var(--muted)" }}
            onMouseEnter={(e) => (e.currentTarget.style.color = "var(--text)")}
            onMouseLeave={(e) => (e.currentTarget.style.color = "var(--muted)")}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="space-y-6 px-6 py-5 min-h-[calc(100vh-56px)]" style={{ background: "var(--surface)" }}>

          {/* Title */}
          <h2 className="text-xl font-semibold leading-tight" style={{ color: "var(--text)" }}>
            {title}
          </h2>

          {/* Metadata Row */}
          {hasMetaInfo && (
            <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
              {finding.category && (
                <span>
                  <span style={{ color: "var(--muted)" }}>Category: </span>
                  <span className="font-semibold" style={{ color: "var(--text)" }}>{finding.category}</span>
                </span>
              )}
              {finding.severity && (
                <span>
                  <span style={{ color: "var(--muted)" }}>Severity: </span>
                  <span className="font-semibold" style={{ color: severityConfig.text }}>{severityConfig.label}</span>
                </span>
              )}
            </div>
          )}

          {(hasMetaInfo || hasDetailSections) && <div style={{ borderTop: "1px solid var(--border)" }} />}

          {!hasDetailSections && (
            <div
              className="flex min-h-[calc(100vh-220px)] items-center justify-center text-sm leading-relaxed"
              style={{
                background: "var(--surface)",
                color: "var(--muted)",
              }}
            >
              No additional details available for this finding.
            </div>
          )}

          {/* Description */}
          {finding.description && (
            <div>
              <p className="mb-3 text-xs font-semibold tracking-widest" style={{ color: "var(--muted)" }}>
                Description
              </p>
              <p className="text-sm leading-relaxed" style={{ color: "var(--text)" }}>
                {finding.description}
              </p>
            </div>
          )}

          {/* File */}
          {finding.file_name && (
            <div>
              <p className="mb-3 text-xs font-semibold tracking-widest" style={{ color: "var(--muted)" }}>
                File
              </p>
              <div className="flex items-center justify-between gap-2">
                <code
                  className="block text-xs font-mono px-3 py-2 rounded flex-1 break-words"
                  style={{
                    backgroundColor: "var(--elevated-surface)",
                    color: "var(--badge-cyan-text)",
                    border: "1px solid var(--border)",
                  }}
                >
                  {finding.file_name}
                </code>
                <button
                  onClick={handleCopyPath}
                  className="rounded p-2 transition-colors"
                  style={{ color: "var(--muted)" }}
                  title="Copy file path"
                >
                  {copiedPath ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              {finding.line_no && finding.line_no !== "N/A" && (
                <p className="text-xs mt-2" style={{ color: "var(--muted)" }}>
                  Line {finding.line_no}
                </p>
              )}
            </div>
          )}

          {/* Detected Value */}
          {finding.redacted_value && (
            <div>
              <div className="mb-3 flex items-center justify-between">
                <p className="text-xs font-semibold tracking-widest" style={{ color: "var(--muted)" }}>
                  Detected Value
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setShowFullValue(!showFullValue)}
                    className="rounded p-1 transition-colors"
                    style={{ color: "var(--muted)" }}
                    title={showFullValue ? "Hide value" : "Show value"}
                  >
                    {showFullValue ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                  <button
                    onClick={handleCopyValue}
                    className="rounded p-1 transition-colors"
                    style={{ color: "var(--muted)" }}
                    title="Copy value"
                  >
                    {copiedValue ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
              <div
                className="overflow-hidden rounded-lg p-4"
                style={{ background: "var(--elevated-surface)", border: "1px solid var(--border)" }}
              >
                <code
                  className="text-xs leading-relaxed break-all"
                  style={{
                    color: showFullValue ? "var(--badge-cyan-text)" : "var(--muted)",
                    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                  }}
                >
                  {showFullValue ? String(finding.redacted_value) : "•".repeat(Math.min(String(finding.redacted_value || "").length, 40))}
                </code>
              </div>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div>
              <p className="mb-3 text-xs font-semibold tracking-widest" style={{ color: "var(--muted)" }}>
                Remediation
              </p>
              <div
                className="rounded-lg px-4 py-3 text-sm leading-relaxed"
                style={{
                  background: "var(--badge-cyan-bg)",
                  borderLeft: "3px solid var(--badge-cyan-text)",
                  color: "var(--text)",
                }}
              >
                {finding.remediation}
              </div>
            </div>
          )}

        </div>
      </div>
    </>
  );
};

export default FindingDetailsSidebar;

