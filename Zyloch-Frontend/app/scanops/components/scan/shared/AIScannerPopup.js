"use client";

import { useState, useEffect, useRef } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { useScanStore } from "@/store/useScanStore";

const AI_SERVICE_URL = process.env.NEXT_PUBLIC_AI_SERVICE_URL || "http://100.69.3.18:8005";

// Animated confidence arc
function ConfidenceArc({ confidence, isAI }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const timer = setTimeout(() => setAnimated(confidence), 300);
    return () => clearTimeout(timer);
  }, [confidence]);

  const humanColor = "#22d3a5";
  const aiColor = "#f97316";
  const color = isAI ? aiColor : humanColor;
  const pct = Math.round(animated * 100);
  const circumference = 2 * Math.PI * 52;
  const strokeDash = (animated * circumference).toFixed(2);

  return (
    <div style={{ position: "relative", width: 130, height: 130, margin: "0 auto" }}>
      <svg width="130" height="130" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r="52" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
        <circle
          cx="70" cy="70" r="52"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${strokeDash} ${circumference}`}
          strokeDashoffset="0"
          transform="rotate(-90 70 70)"
          style={{
            transition: "stroke-dasharray 1.2s cubic-bezier(0.34,1.56,0.64,1)",
            filter: `drop-shadow(0 0 8px ${color}88)`,
          }}
        />
        <circle cx="70" cy="70" r="42" fill="rgba(15,15,25,0.95)" />
      </svg>
      <div style={{
        position: "absolute", top: "50%", left: "50%",
        transform: "translate(-50%,-50%)", textAlign: "center",
      }}>
        <div style={{ fontSize: 26, fontWeight: 800, color, fontFamily: "'DM Mono', monospace", lineHeight: 1 }}>
          {pct}<span style={{ fontSize: 13, opacity: 0.7 }}>%</span>
        </div>
        <div style={{ fontSize: 9, color: "rgba(255,255,255,0.4)", letterSpacing: 2, textTransform: "uppercase", marginTop: 2 }}>
          confidence
        </div>
      </div>
    </div>
  );
}

// Verdict badge
function VerdictBadge({ isAI }) {
  const humanGrad = "linear-gradient(135deg, #064e3b 0%, #065f46 100%)";
  const aiGrad = "linear-gradient(135deg, #7c2d12 0%, #9a3412 100%)";
  const humanBorder = "#22d3a5";
  const aiBorder = "#f97316";
  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: 8,
      background: isAI ? aiGrad : humanGrad,
      border: `1px solid ${isAI ? aiBorder : humanBorder}44`,
      borderRadius: 8, padding: "6px 14px",
      boxShadow: `0 0 20px ${isAI ? aiBorder : humanBorder}22`,
    }}>
      <div style={{
        width: 7, height: 7, borderRadius: "50%",
        background: isAI ? aiBorder : humanBorder,
        boxShadow: `0 0 6px ${isAI ? aiBorder : humanBorder}`,
      }} />
      <span style={{
        fontSize: 11, fontWeight: 700, letterSpacing: 2,
        textTransform: "uppercase", color: isAI ? aiBorder : humanBorder,
        fontFamily: "'DM Mono', monospace",
      }}>
        {isAI ? "AI Generated" : "Human Written"}
      </span>
    </div>
  );
}

// Metric pill
function MetricPill({ label, value, accent }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.04)",
      border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: 8, padding: "9px 12px",
      display: "flex", flexDirection: "column", gap: 3,
    }}>
      <span style={{ fontSize: 9, color: "rgba(255,255,255,0.35)", letterSpacing: 2, textTransform: "uppercase" }}>{label}</span>
      <span style={{ fontSize: 14, fontWeight: 700, color: accent || "rgba(255,255,255,0.9)", fontFamily: "'DM Mono', monospace" }}>{value}</span>
    </div>
  );
}

// Split bar
function SplitBar({ humanPct, aiPct }) {
  const [anim, setAnim] = useState(false);
  useEffect(() => { setTimeout(() => setAnim(true), 500); }, []);
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
        <span style={{ fontSize: 10, color: "#22d3a5", letterSpacing: 1, textTransform: "uppercase" }}>Human {humanPct}%</span>
        <span style={{ fontSize: 10, color: "#f97316", letterSpacing: 1, textTransform: "uppercase" }}>AI {aiPct}%</span>
      </div>
      <div style={{ height: 5, borderRadius: 99, background: "rgba(255,255,255,0.06)", overflow: "hidden", display: "flex" }}>
        <div style={{
          height: "100%", borderRadius: "99px 0 0 99px",
          background: "linear-gradient(90deg, #22d3a5, #059669)",
          width: anim ? `${humanPct}%` : "0%",
          transition: "width 1.4s cubic-bezier(0.34,1.2,0.64,1)",
          boxShadow: "2px 0 8px #22d3a566",
        }} />
        <div style={{
          height: "100%", borderRadius: "0 99px 99px 0",
          background: "linear-gradient(90deg, #ea580c, #f97316)",
          width: anim ? `${aiPct}%` : "0%",
          transition: "width 1.4s cubic-bezier(0.34,1.2,0.64,1) 0.1s",
          boxShadow: "-2px 0 8px #f9731666",
        }} />
      </div>
    </div>
  );
}

// Scan pulse animation
function ScanPulse() {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14, padding: "24px 0" }}>
      <div style={{ position: "relative", width: 64, height: 64 }}>
        {[0, 1, 2].map((i) => (
          <div key={i} style={{
            position: "absolute", inset: 0, borderRadius: "50%",
            border: "2px solid var(--color-primary, #06b6d4)",
            animation: `aiScanPing 1.8s ${i * 0.4}s ease-out infinite`,
            opacity: 0,
          }} />
        ))}
        <div style={{
          position: "absolute", inset: "16px",
          background: "linear-gradient(135deg, var(--color-primary, #06b6d4), var(--color-secondary, #8b5cf6))",
          borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
          boxShadow: "0 0 20px rgba(6,182,212,0.4)",
        }}>
          <svg width="16" height="16" fill="none" viewBox="0 0 24 24">
            <path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18"
              stroke="white" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </div>
      </div>
      <div style={{ textAlign: "center" }}>
        <div style={{ color: "rgba(255,255,255,0.85)", fontWeight: 600, fontSize: 13, marginBottom: 3 }}>Analyzing code patterns…</div>
        <div style={{ color: "rgba(255,255,255,0.35)", fontSize: 11, fontFamily: "'DM Mono', monospace" }}>Running AI detection model</div>
      </div>
      <div style={{ display: "flex", gap: 4 }}>
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} style={{
            width: 3, height: 14, borderRadius: 99,
            background: "var(--color-primary, #06b6d4)",
            animation: `aiScanBounce 1s ${i * 0.12}s ease-in-out infinite alternate`,
            opacity: 0.7,
          }} />
        ))}
      </div>
      <style>{`
        @keyframes aiScanPing { 0% { transform: scale(0.9); opacity: 0.6; } 100% { transform: scale(2.2); opacity: 0; } }
        @keyframes aiScanBounce { from { transform: scaleY(0.5); opacity: 0.4; } to { transform: scaleY(1.4); opacity: 1; } }
      `}</style>
    </div>
  );
}

/**
 * @param {string[]} files - List of scanned file paths for this page's findings
 */
export default function AIScannerPopup({ files = [] }) {
  const { latestScan } = useScanStore();
  const [open, setOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [dropOpen, setDropOpen] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const activeScanId = useRef(null);
  const [mounted, setMounted] = useState(false);
  const dropRef = useRef(null);
  const pollRef = useRef(null);

  const fileList = files.length > 0 ? files : [];

  useEffect(() => {
    if (fileList.length > 0 && !selectedFile) {
      setSelectedFile(fileList[0]);
    }
  }, [fileList]);

  useEffect(() => {
    if (open) setTimeout(() => setMounted(true), 50);
    else setMounted(false);
  }, [open]);

  useEffect(() => {
    const handler = (e) => {
      if (dropRef.current && !dropRef.current.contains(e.target)) setDropOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const handleOpen = () => {
    setResult(null);
    setScanError(null);
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setMounted(false);
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const handleScan = async () => {
    setScanning(true);
    setResult(null);
    setScanError(null);
    activeScanId.current = null;

    const scanMeta = latestScan?.scan_metadata || {};
    const body = {
      repo_url: scanMeta.repository_url,
      org_name: scanMeta.organization,
      repo_name: scanMeta.repository,
      branch: scanMeta.branch || "main",
      file: selectedFile || "all",
      installation_id: latestScan?.installation_id,
    };

    try {
      const res = await fetch(`${AI_SERVICE_URL}/scan/ai`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const initiated = await res.json();
      const ourScanId = initiated?.scan_id;
      activeScanId.current = ourScanId;

      // Poll /scans/ai/latest until we get OUR completed result
      let attempts = 0;
      const MAX_ATTEMPTS = 60; // 3 min max

      pollRef.current = setInterval(async () => {
        attempts++;
        try {
          const pollRes = await fetch(`${AI_SERVICE_URL}/scans/ai/latest`);
          if (!pollRes.ok) return;
          const data = await pollRes.json();

          // Accept only the result matching our scan_id
          if (
            data?.status === "completed" &&
            ourScanId &&
            data?.scan_id === ourScanId
          ) {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setScanning(false);
            setResult(data);
            return;
          }
        } catch (_) {
          // silently continue polling
        }

        if (attempts >= MAX_ATTEMPTS) {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setScanning(false);
          setScanError("Scan timed out. Please try again.");
        }
      }, 3000);
    } catch (err) {
      setScanning(false);
      setScanError(err.message || "Failed to initiate scan.");
    }
  };

  const finding = result?.per_scanner_results?.ai_check?.findings?.[0];
  const isAI = finding?.is_ai === 1;
  const confidence = finding?.confidence ?? 0;
  const humanPct = isAI ? Math.round((1 - confidence) * 100) : Math.round(confidence * 100);
  const aiPct = 100 - humanPct;
  const linesScanned = finding ? finding.end_line - finding.start_line + 1 : 0;
  const ts = result?.per_scanner_results?.ai_check?.metadata?.timestamp;
  const timeStr = ts ? new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";

  const pieData = finding
    ? [
      { name: "Human", value: humanPct, color: "#22d3a5" },
      { name: "AI", value: aiPct, color: "#f97316" },
    ]
    : [];

  const hasResult = !!(result && !scanning);

  const fileName = (path) => path?.split("/").pop() || path;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap');
        .ai-scanner-trigger:hover { transform: translateY(-2px); box-shadow: 0 8px 28px rgba(6,182,212,0.35), 0 0 0 1px rgba(6,182,212,0.3) !important; }
        .ai-scanner-trigger:active { transform: translateY(0); }
        .ai-scan-run-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 8px 24px rgba(6,182,212,0.4) !important; }
        .ai-scan-run-btn:active:not(:disabled) { transform: translateY(0); }
        .ai-scan-file-opt:hover { background: rgba(var(--color-primary-rgb),0.12) !important; color: var(--color-primary, #06b6d4) !important; }
        .ai-scan-close-btn:hover { background: rgba(255,255,255,0.1) !important; }
        @keyframes aiScanSpin { to { transform: rotate(360deg); } }
      `}</style>

      {/* Floating trigger button */}
      <button
        className="ai-scanner-trigger"
        onClick={handleOpen}
        style={{
          position: "fixed",
          bottom: 28,
          right: 28,
          zIndex: 30,
          display: "flex",
          alignItems: "center",
          gap: 8,
          background: "linear-gradient(135deg, rgba(var(--color-primary-rgb),0.15) 0%, rgba(var(--color-secondary-rgb),0.15) 100%)",
          border: "1px solid rgba(var(--color-primary-rgb),0.35)",
          color: "var(--color-primary, #06b6d4)",
          padding: "10px 18px",
          borderRadius: 10,
          cursor: "pointer",
          fontSize: 13,
          fontWeight: 600,
          letterSpacing: 0.2,
          backdropFilter: "blur(12px)",
          WebkitBackdropFilter: "blur(12px)",
          boxShadow: "0 4px 20px rgba(var(--color-primary-rgb),0.2), 0 0 0 1px rgba(var(--color-primary-rgb),0.15), inset 0 1px 0 rgba(var(--surface-rgb),0.08)",
          transition: "all 0.22s cubic-bezier(0.34,1.2,0.64,1)",
          fontFamily: "var(--font-ui, inherit)",
        }}
      >
        <svg width="15" height="15" fill="none" viewBox="0 0 24 24" style={{ opacity: 0.9 }}>
          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"
            stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        AI Code Scanner
        <div style={{
          width: 6, height: 6, borderRadius: "50%",
          background: "var(--color-primary, #06b6d4)",
          boxShadow: "0 0 6px var(--color-primary, #06b6d4)",
          animation: "aiScanSpin 3s linear infinite",
          animationName: "none",
          opacity: 0.9,
        }} />
      </button>

      {/* Backdrop */}
      {open && (
        <div
          onClick={handleClose}
          style={{
            position: "fixed", inset: 0,
            background: "rgba(0,0,0,0.6)",
            backdropFilter: "blur(4px)",
            WebkitBackdropFilter: "blur(4px)",
            zIndex: 40,
            opacity: mounted ? 1 : 0,
            transition: "opacity 0.25s ease",
          }}
        />
      )}

      {/* Popup */}
      {open && (
        <div
          style={{
            position: "fixed",
            top: "50%",
            left: "50%",
            transform: mounted
              ? "translate(-50%,-50%) scale(1)"
              : "translate(-50%,-50%) scale(0.96)",
            opacity: mounted ? 1 : 0,
            transition: "all 0.3s cubic-bezier(0.34,1.2,0.64,1)",
            zIndex: 50,
            width: hasResult ? "min(480px, 94vw)" : "min(500px, 94vw)",
            maxHeight: "90vh",
            overflowY: "auto",
            background: "#FFFFFF0D",
            borderRadius: 12,
            border: hasResult
              ? "1px solid rgba(255,255,255,0.1)"
              : "1px solid #1E2533",
            borderTop: hasResult ? undefined : "1px solid #1E2533",
            boxShadow: hasResult
              ? "0px 0px 40px 0px #4A9EFF14, 0px 20px 60px rgba(0,0,0,0.5)"
              : "0px 0px 40px 0px #4A9EFF14, 0px 20px 60px rgba(0,0,0,0.5)",
            backdropFilter: "blur(20px)",
            WebkitBackdropFilter: "blur(20px)",
            fontFamily: "var(--font-ui, 'Inter', sans-serif)",
          }}
        >
          {/* Header */}
          <div style={{
            padding: "18px 20px 14px",
            borderBottom: "1px solid rgba(255,255,255,0.06)",
            display: "flex", alignItems: "flex-start", justifyContent: "space-between",
            background: "rgba(6,182,212,0.04)",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{
                width: 34, height: 34, borderRadius: 9,
                background: "linear-gradient(135deg, var(--color-primary, #06b6d4) 0%, var(--color-secondary, #8b5cf6) 100%)",
                display: "flex", alignItems: "center", justifyContent: "center",
                boxShadow: "0 4px 12px rgba(6,182,212,0.35)",
              }}>
                <svg width="16" height="16" fill="none" viewBox="0 0 24 24">
                  <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"
                    stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: "rgba(255,255,255,0.92)", letterSpacing: -0.2 }}>
                  AI Code Scanner
                </div>
                <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)", marginTop: 1, fontFamily: "'DM Mono', monospace" }}>
                  {result ? `${result.repo_org} / ${result.repo_name}` : "Detect AI vs Human code"}
                </div>
              </div>
            </div>
            <button
              className="ai-scan-close-btn"
              onClick={handleClose}
              style={{
                width: 28, height: 28, borderRadius: 7, border: "none",
                background: "rgba(var(--surface-rgb),0.05)", color: "rgba(var(--text-rgb),0.5)",
                cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
                transition: "all 0.15s", fontSize: 15,
              }}
            >
              ✕
            </button>
          </div>

          {/* Body */}
          <div style={{ padding: "18px 20px 20px" }}>

            {/* File selector */}
            {fileList.length > 0 && (
              <div style={{ marginBottom: 14 }}>
                <label style={{
                  fontSize: 10, color: "rgba(255,255,255,0.4)", letterSpacing: 1.5,
                  textTransform: "uppercase", display: "block", marginBottom: 7,
                }}>
                  Target File
                </label>
                <div ref={dropRef} style={{ position: "relative" }}>
                  <button
                    onClick={() => setDropOpen((v) => !v)}
                    style={{
                      width: "100%", padding: "9px 12px",
                      background: "rgba(255,255,255,0.04)",
                      border: `1px solid ${dropOpen ? "rgba(6,182,212,0.5)" : "rgba(255,255,255,0.1)"}`,
                      borderRadius: 8, color: "rgba(255,255,255,0.85)",
                      cursor: "pointer", display: "flex", alignItems: "center",
                      justifyContent: "space-between",
                      fontSize: 12, fontFamily: "'DM Mono', monospace", transition: "border-color 0.2s",
                      boxShadow: dropOpen ? "0 0 0 3px rgba(6,182,212,0.1)" : "none",
                    }}
                  >
                    <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
                      <span style={{ fontSize: 13 }}>📄</span>
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 340 }}>
                        {fileName(selectedFile)}
                      </span>
                    </span>
                    <svg width="12" height="12" fill="none" viewBox="0 0 24 24"
                      style={{ flexShrink: 0, transform: dropOpen ? "rotate(180deg)" : "rotate(0)", transition: "transform 0.2s" }}>
                      <path d="M6 9l6 6 6-6" stroke="rgba(255,255,255,0.4)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </button>
                  {dropOpen && (
                    <div style={{
                      position: "absolute", top: "calc(100% + 5px)", left: 0, right: 0,
                      background: "#0e1420", border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: 8, overflow: "hidden", zIndex: 100,
                      boxShadow: "0 16px 40px rgba(0,0,0,0.6)",
                      maxHeight: 200, overflowY: "auto",
                    }}>
                      {fileList.map((f) => (
                        <button
                          key={f}
                          className="ai-scan-file-opt"
                          onClick={() => { setSelectedFile(f); setDropOpen(false); setResult(null); setScanError(null); }}
                          style={{
                            width: "100%", padding: "8px 12px",
                            background: f === selectedFile ? "rgba(6,182,212,0.1)" : "transparent",
                            border: "none",
                            color: f === selectedFile ? "var(--color-primary, #06b6d4)" : "rgba(255,255,255,0.55)",
                            cursor: "pointer", textAlign: "left", fontSize: 11,
                            fontFamily: "'DM Mono', monospace", transition: "all 0.1s",
                            borderBottom: "1px solid rgba(255,255,255,0.04)",
                            display: "flex", alignItems: "center", gap: 7,
                          }}
                        >
                          {f === selectedFile && (
                            <span style={{ color: "var(--color-primary, #06b6d4)", fontSize: 10 }}>▸</span>
                          )}
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{fileName(f)}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Scan button */}
            <button
              className="ai-scan-run-btn"
              onClick={handleScan}
              disabled={scanning}
              style={{
                width: "100%", padding: "11px",
                background: scanning
                  ? "rgba(6,182,212,0.15)"
                  : "linear-gradient(135deg, var(--color-primary, #06b6d4) 0%, var(--color-secondary, #8b5cf6) 100%)",
                border: scanning ? "1px solid rgba(6,182,212,0.25)" : "none",
                borderRadius: 8, color: "white",
                fontSize: 13, fontWeight: 600, cursor: scanning ? "not-allowed" : "pointer",
                letterSpacing: 0.3, transition: "all 0.2s",
                boxShadow: scanning ? "none" : "0 4px 16px rgba(6,182,212,0.3)",
                display: "flex", alignItems: "center", justifyContent: "center", gap: 7,
                fontFamily: "inherit",
              }}
            >
              {scanning ? (
                <>
                  <div style={{
                    width: 13, height: 13, borderRadius: "50%",
                    border: "2px solid rgba(255,255,255,0.3)", borderTopColor: "white",
                    animation: "aiScanSpin 0.8s linear infinite",
                  }} />
                  Scanning…
                </>
              ) : (
                <>
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24">
                    <path d="M21 21l-6-6m2-5a7 7 0 1 1-14 0 7 7 0 0 1 14 0z"
                      stroke="white" strokeWidth="2.5" strokeLinecap="round" />
                  </svg>
                  Run Scan
                </>
              )}
            </button>

            {/* Loading */}
            {scanning && <ScanPulse />}

            {/* Error */}
            {scanError && !scanning && (
              <div style={{
                marginTop: 14, padding: "10px 14px",
                background: "rgba(239,68,68,0.08)",
                border: "1px solid rgba(239,68,68,0.2)",
                borderRadius: 8,
                display: "flex", alignItems: "flex-start", gap: 8,
              }}>
                <span style={{ color: "#ef4444", fontSize: 14, lineHeight: 1 }}>⚠</span>
                <span style={{ fontSize: 12, color: "rgba(255,255,255,0.6)", lineHeight: 1.5 }}>{scanError}</span>
              </div>
            )}

            {/* Results */}
            {hasResult && (
              <div style={{ marginTop: 18 }}>
                {/* Divider */}
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16 }}>
                  <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.07)" }} />
                  <span style={{ fontSize: 9, color: "rgba(255,255,255,0.25)", letterSpacing: 2, textTransform: "uppercase" }}>
                    Scan Results
                  </span>
                  <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.07)" }} />
                </div>

                {finding ? (
                  <>
                    {/* Verdict + arc */}
                    <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 18 }}>
                      <ConfidenceArc confidence={confidence} isAI={isAI} />
                      <div style={{ flex: 1 }}>
                        <VerdictBadge isAI={isAI} />
                        <div style={{ marginTop: 10 }}>
                          <SplitBar humanPct={humanPct} aiPct={aiPct} />
                        </div>
                        <div style={{ marginTop: 8, fontSize: 11, color: "rgba(255,255,255,0.35)", lineHeight: 1.6 }}>
                          {finding.description} with{" "}
                          <span style={{ color: isAI ? "#f97316" : "#22d3a5", fontWeight: 600 }}>
                            {(confidence * 100).toFixed(1)}%
                          </span>{" "}
                          confidence across{" "}
                          <span style={{ color: "rgba(255,255,255,0.6)" }}>{linesScanned} lines</span>
                        </div>
                      </div>
                    </div>

                    {/* Pie chart */}
                    <div style={{
                      background: "rgba(255,255,255,0.025)",
                      border: "1px solid rgba(255,255,255,0.07)",
                      borderRadius: 10, padding: "14px", marginBottom: 12,
                    }}>
                      <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 10 }}>
                        Code Origin Distribution
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                        <ResponsiveContainer width={90} height={90}>
                          <PieChart>
                            <Pie data={pieData} cx={40} cy={40} innerRadius={24} outerRadius={40}
                              dataKey="value" paddingAngle={3} startAngle={90} endAngle={-270}>
                              {pieData.map((entry, i) => (
                                <Cell key={i} fill={entry.color} stroke="transparent"
                                  style={{ filter: `drop-shadow(0 0 4px ${entry.color}66)` }} />
                              ))}
                            </Pie>
                            <Tooltip
                              formatter={(v) => `${v}%`}
                              contentStyle={{ background: "#1a1a2e", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, color: "#fff", fontSize: 11 }}
                            />
                          </PieChart>
                        </ResponsiveContainer>
                        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 7 }}>
                          {pieData.map((d) => (
                            <div key={d.name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <div style={{ width: 9, height: 9, borderRadius: 3, background: d.color, boxShadow: `0 0 5px ${d.color}88` }} />
                                <span style={{ fontSize: 12, color: "rgba(255,255,255,0.6)" }}>{d.name}</span>
                              </div>
                              <span style={{ fontSize: 13, fontWeight: 700, color: d.color, fontFamily: "'DM Mono', monospace" }}>
                                {d.value}%
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Metric pills */}
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 7, marginBottom: 12 }}>
                      <MetricPill label="Lines" value={`${finding.start_line}–${finding.end_line}`} />
                      <MetricPill label="Severity" value={finding.severity} accent="var(--color-primary, #06b6d4)" />
                      <MetricPill label="Scan time" value={timeStr} />
                    </div>

                    {/* Policy */}
                    <div style={{
                      background: "rgba(6,182,212,0.06)",
                      border: "1px solid rgba(6,182,212,0.15)",
                      borderRadius: 9, padding: "9px 12px",
                      display: "flex", alignItems: "center", justifyContent: "space-between",
                      marginBottom: 0,
                    }}>
                      <div>
                        <div style={{ fontSize: 9, color: "rgba(255,255,255,0.3)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 3 }}>
                          Policy
                        </div>
                        <div style={{ fontSize: 12, color: "var(--color-primary, #06b6d4)", fontWeight: 600 }}>
                          {finding.policy}
                        </div>
                      </div>
                      <div style={{ textAlign: "right" }}>
                        <div style={{ fontSize: 9, color: "rgba(255,255,255,0.3)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 3 }}>
                          Status
                        </div>
                        <div style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#22d3a5", boxShadow: "0 0 6px #22d3a5" }} />
                          <span style={{ fontSize: 12, color: "#22d3a5", fontWeight: 600, textTransform: "capitalize" }}>
                            {result.status}
                          </span>
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  /* No findings — file scanned but no AI patterns detected */
                  <div style={{
                    display: "flex", flexDirection: "column", alignItems: "center", gap: 10,
                    padding: "20px 16px",
                    background: "rgba(34,211,165,0.05)",
                    border: "1px solid rgba(34,211,165,0.15)",
                    borderRadius: 10,
                  }}>
                    <div style={{
                      width: 40, height: 40, borderRadius: "50%",
                      background: "rgba(34,211,165,0.12)",
                      display: "flex", alignItems: "center", justifyContent: "center",
                    }}>
                      <svg width="18" height="18" fill="none" viewBox="0 0 24 24">
                        <path d="M20 6L9 17l-5-5" stroke="#22d3a5" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    </div>
                    <div style={{ textAlign: "center" }}>
                      <div style={{ fontSize: 13, fontWeight: 700, color: "#22d3a5", marginBottom: 4 }}>
                        No AI Patterns Detected
                      </div>
                      <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", lineHeight: 1.5 }}>
                        The selected file does not appear to contain AI-generated code.
                      </div>
                    </div>
                    <div style={{ display: "inline-flex", alignItems: "center", gap: 5, marginTop: 2 }}>
                      <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#22d3a5", boxShadow: "0 0 6px #22d3a5" }} />
                      <span style={{ fontSize: 11, color: "#22d3a5", fontWeight: 600, textTransform: "capitalize" }}>
                        {result.status}
                      </span>
                    </div>
                  </div>
                )}

                {/* Scan ID */}
                <div style={{
                  marginTop: 9, padding: "7px 10px",
                  background: "rgba(255,255,255,0.02)", borderRadius: 6,
                  border: "1px solid rgba(255,255,255,0.05)",
                }}>
                  <span style={{ fontSize: 9, color: "rgba(255,255,255,0.2)", letterSpacing: 1.5, textTransform: "uppercase" }}>
                    Scan ID{"  "}
                  </span>
                  <span style={{ fontSize: 10, color: "rgba(255,255,255,0.35)", fontFamily: "'DM Mono', monospace" }}>
                    {result.scan_id}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
