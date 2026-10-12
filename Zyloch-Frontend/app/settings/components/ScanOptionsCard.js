"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  CheckCircle,
  XCircle,
  Save,
  RefreshCw,
  Lock,
} from "lucide-react";
import { getScannerIconComponent } from "@/app/scanops/components/scan/shared/scannerIcons";
import { updatePolicyConfigurations } from "@/lib/api/organization";
import { useTenant } from "@/context/TenantContext";

// Maps each scan-options category → the individual GHAPP scanner keys
// whose policy-configurations should be enabled/disabled together.
const SCAN_ID_TO_SCANNER_KEYS = {
  iac: ['docker', 'kubernetes', 'terraform_aws', 'terraform_azure', 'terraform_gcp', 'bicep', 'ansible', 'cloudformation'],
  workflow: ['workflow'],
  'secret-scanner': ['secret_scanner'],
  sbom: ['sbom'],
  'ai-vs-human': ['ai_vs_human'],
  'skill-scanner': ['skill-scanner'],
};

// Same grouping, but spelled with the canonical scanner keys that license
// entitlements (`entitlements.scanners`) use — kept separate from the map
// above because `useTenant().hasScanner` does a raw key match with no alias
// normalization, unlike the backend write path. Mirrors
// SCAN_ID_TO_LICENSE_SCANNER_KEYS in Zyloch-Backend/controllers/organization.js.
const SCAN_ID_TO_LICENSE_SCANNER_KEYS = {
  workflow: ['workflow'],
  iac: ['docker', 'kubernetes', 'terraform_aws', 'terraform_azure', 'terraform_gcp', 'bicep', 'ansible', 'cloudformation'],
  sbom: ['sbom'],
  'secret-scanner': ['secret_scanner'],
  'ai-vs-human': ['ai_vs_human'],
  // Paid-tier scanners. An unmapped id is treated as "not gated", which showed a
  // Free tenant a toggle for a scan the backend refuses to run.
  'skill-scanner': ['skill-scanner'],
  'cis-agent': ['cis-agent'],
};

export const ScanOptionsCard = ({ isAdmin, orgName }) => {
  const { hasScanner } = useTenant();

  const isScanLicensed = (scanId) => {
    const keys = SCAN_ID_TO_LICENSE_SCANNER_KEYS[scanId];
    return !keys || keys.length === 0 || keys.some((key) => hasScanner(key));
  };

  const [scanConfigurations, setScanConfigurations] = useState({
    workflow: true,
    iac: true,
    sbom: true,
    "secret-scanner": true,
    "ai-vs-human": true,
    "skill-scanner": true,
  });

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState({ text: "", type: "" });

  // Sync enabled/disabled state to the policy-configurations API so that
  // the overview page immediately reflects the scan-options toggle.
  const syncPolicyConfig = async (scanId, enabled) => {
    const scannerKeys = SCAN_ID_TO_SCANNER_KEYS[scanId];
    if (!scannerKeys) return;
    const scanners = {};
    for (const key of scannerKeys) {
      scanners[key] = { enabled };
    }
    // Tenant-scoped backend rather than a direct browser call to the scanner
    // service, which carried no tenant context or credentials (MT-08).
    try {
      await updatePolicyConfigurations(scanners, false);
    } catch (e) {
      console.error('Failed to sync policy-configurations:', e);
    }
  };

  useEffect(() => {
    fetchScanConfigurations();
  }, []);

  const fetchScanConfigurations = async () => {
    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization/scans`,
        {
          credentials: "include",
        },
      );

      if (response.ok) {
        const data = await response.json();
        if (data.scanConfigurations) {
          setScanConfigurations({
            workflow: data.scanConfigurations.workflow ?? true,
            iac: data.scanConfigurations.iac ?? true,
            sbom: data.scanConfigurations.sbom ?? true,
            "secret-scanner": data.scanConfigurations["secret-scanner"] ?? true,
            "ai-vs-human": data.scanConfigurations["ai-vs-human"] ?? true,
            "skill-scanner": data.scanConfigurations["skill-scanner"] ?? true,
          });
        }
      } else {
        const errorData = await response.json();
        setMessage({
          text: errorData.message || "Failed to load scan configurations",
          type: "error",
        });
      }
    } catch (error) {
      setMessage({
        text: "Failed to load scan configurations",
        type: "error",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = async (scanId) => {
    if (!isScanLicensed(scanId)) {
      setMessage({
        text: "This scan isn't included in your plan. Upgrade your license to access it.",
        type: "error",
      });
      setTimeout(() => setMessage({ text: "", type: "" }), 3000);
      return;
    }

    if (!isAdmin) {
      setMessage({
        text: "Only administrators can modify scan configurations",
        type: "error",
      });
      setTimeout(() => setMessage({ text: "", type: "" }), 3000);
      return;
    }

    const newValue = !scanConfigurations[scanId];

    // Optimistic update
    setScanConfigurations((prev) => ({
      ...prev,
      [scanId]: newValue,
    }));

    const updatedConfig = { ...scanConfigurations, [scanId]: newValue };

    // Prepare backend config (maintain backward compatibility)
    const backendConfig = {
      workflow: updatedConfig.workflow,
      iac: updatedConfig.iac,
      sbom: updatedConfig.sbom,
      "secret-scanner": updatedConfig["secret-scanner"],
      "ai-vs-human": updatedConfig["ai-vs-human"],
      "skill-scanner": updatedConfig["skill-scanner"],
    };

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization/scans`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ scanConfigurations: backendConfig }),
        },
      );

      const data = await response.json();

      if (response.ok) {
        setMessage({
          text: `${scanId.replace(/-/g, " ")} scan ${newValue ? "enabled" : "disabled"} successfully!`,
          type: "success",
        });
        setTimeout(() => setMessage({ text: "", type: "" }), 2000);
        // Mirror the toggle into the per-scanner policy-configurations so the
        // overview page honours the setting without requiring a new scan.
        syncPolicyConfig(scanId, newValue);
      } else {
        // Revert on error
        setScanConfigurations((prev) => ({
          ...prev,
          [scanId]: !newValue,
        }));
        setMessage({
          text: data.message || "Failed to save configuration",
          type: "error",
        });
      }
    } catch (error) {
      // Revert on error
      setScanConfigurations((prev) => ({
        ...prev,
        [scanId]: !newValue,
      }));
      setMessage({
        text: "Network error. Please try again.",
        type: "error",
      });
    }
  };

  const handleSave = async () => {
    if (!isAdmin) return;

    setSaving(true);
    setMessage({ text: "", type: "" });

    const backendConfig = {
      workflow: scanConfigurations.workflow,
      iac: scanConfigurations.iac,
      sbom: scanConfigurations.sbom,
      "secret-scanner": scanConfigurations["secret-scanner"],
      "ai-vs-human": scanConfigurations["ai-vs-human"],
      "skill-scanner": scanConfigurations["skill-scanner"],
    };

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization/scans`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ scanConfigurations: backendConfig }),
        },
      );

      const data = await response.json();

      if (response.ok) {
        setMessage({
          text: "Scan configurations saved successfully!",
          type: "success",
        });
        await fetchScanConfigurations();
        setTimeout(() => setMessage({ text: "", type: "" }), 3000);
      } else {
        setMessage({
          text: data.message || "Failed to save configurations",
          type: "error",
        });
      }
    } catch (error) {
      setMessage({
        text: "Failed to save scan configurations",
        type: "error",
      });
    } finally {
      setSaving(false);
    }
  };

  const scanItems = [
    {
      label: "Workflow Scanner",
      id: "workflow",
      icon: getScannerIconComponent("workflow"),
      description: "Analyze CI/CD workflows for security issues",
    },
    {
      label: "IaC Scanner",
      id: "iac",
      icon: getScannerIconComponent("iac"),
      description: "Scan Infrastructure as Code configurations for security vulnerabilities",
      category: "iac"
    },
    {
      label: "SBOM Generator",
      id: "sbom",
      icon: getScannerIconComponent("sbom"),
      description: "Generate Software Bill of Materials for dependencies",
    },
    {
      label: "Secret Scanner",
      id: "secret-scanner",
      icon: getScannerIconComponent("secret-scanner"),
      description: "Detect exposed secrets, API keys, and credentials",
    },
    {
      label: "AI vs Human",
      id: "ai-vs-human",
      icon: getScannerIconComponent("ai-vs-human"),
      description: "Compare AI-generated vs human-written code for anomalies",
    },
    {
      label: "AI Security Scanner",
      id: "skill-scanner",
      icon: getScannerIconComponent("skill-scanner"),
      description: "Detect unsafe instructions, exfiltration, impersonation, and supply-chain risks in agent skills",
    },
  ];


  if (loading) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex items-center justify-center min-h-[400px]"
      >
        <div className="text-center">
          <RefreshCw
            className="animate-spin text-[var(--color-primary)] mx-auto mb-4"
            size={32}
          />
          <p className="text-[var(--muted)]">Loading scan configurations...</p>
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      style={{ color: "var(--text)" }}
    >
      <div className="flex flex-col flex-1">
        <div className="flex-1 overflow-y-auto">
          <div>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-6 md:gap-8 px-2 md:px-4 py-4 md:py-[17px]">
              {scanItems.map(({ label, id, icon: Icon, description }, index) => {
                const enabled = scanConfigurations[id];
                const licensed = isScanLicensed(id);
                const canToggle = isAdmin && licensed;
                const lockReason = !licensed
                  ? "Upgrade your license to access this scan"
                  : !isAdmin
                    ? "Only administrators can modify scan configurations"
                    : undefined;

                return (
                  <motion.div
                    key={id}
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.04 }}
                    title={!licensed ? lockReason : undefined}
                    className={`relative rounded-xl border border-[var(--border)] bg-[var(--surface)] h-[253px] flex flex-col shadow-md ${!licensed ? "opacity-70" : ""
                      }`}
                  >
                    {!licensed && (
                      <div className="absolute top-3 right-3 h-6 w-6 rounded-full bg-[var(--elevated-surface)] border border-[var(--border)] flex items-center justify-center text-[var(--muted)]">
                        <Lock className="h-3 w-3" />
                      </div>
                    )}
                    <div className="px-4 pt-6 md:px-6 flex-1 flex flex-col justify-between">
                      <div className="flex items-center justify-between gap-4 mb-6">
                        <div className="h-9 w-9 rounded-lg bg-[var(--badge-cyan-bg)] flex items-center justify-center text-[var(--color-primary)]">
                          <Icon className="h-5 w-5" />
                        </div>
                        <button
                          type="button"
                          onClick={() => handleToggle(id)}
                          disabled={!canToggle}
                          aria-pressed={enabled}
                          aria-label={`Toggle ${label}`}
                          title={lockReason}
                          className={`relative h-7 w-[64px] rounded-full transition-all duration-300 border overflow-hidden ${canToggle ? "cursor-pointer" : "cursor-not-allowed opacity-60"
                            }`}
                          style={{
                            borderColor: "var(--border)",
                            backgroundColor: enabled
                              ? "var(--color-primary)"
                              : "var(--elevated-surface)",
                          }}
                        >
                          <span
                            className={`absolute top-[3px] h-5 w-5 rounded-full transition-all duration-300 shadow-[0_1px_6px_rgba(0,0,0,0.25)] ${enabled ? "left-[38px]" : "left-1"
                              }`}
                            style={{
                              backgroundColor: "var(--surface)",
                              border: "1px solid var(--border)",
                            }}
                          />
                        </button>
                      </div>

                      <div className="space-y-3 pb-6">
                        <h3 className="text-sm md:text-base font-medium leading-[140%] text-[var(--text)]">
                          {label}
                        </h3>
                        <p className="text-xs md:text-sm leading-[140%] text-[var(--muted)] min-h-[34px]">
                          {description}
                        </p>
                      </div>
                    </div>

                    <div className="border-t border-dashed border-[var(--border)] px-4 md:px-6 py-4 flex items-center justify-between gap-4 h-[62px]">
                      <div
                        className={`inline-flex items-center gap-2 rounded-lg px-3 py-1.5 border text-xs ${!licensed
                          ? "bg-[var(--elevated-surface)] border-[var(--border)] text-[var(--muted)]"
                          : enabled
                            ? "bg-[var(--badge-green-bg)] border-[var(--badge-green-border)] text-[var(--badge-green-text)]"
                            : "bg-[var(--badge-cyan-bg)] border-[var(--badge-cyan-border)] text-[var(--muted)]"
                          }`}
                      >
                        {!licensed ? (
                          <Lock className="h-3 w-3" />
                        ) : (
                          <span
                            className={`h-1 w-1 rounded-full ${enabled ? "bg-[var(--success)]" : "bg-[var(--muted)]"
                              }`}
                          />
                        )}
                        {!licensed ? "Upgrade required" : enabled ? "Enabled" : "Disabled"}
                      </div>
                      <p className="text-xs md:text-[12px] leading-[140%] text-[var(--muted)]">
                        Last Scanned: Just now
                      </p>
                    </div>
                  </motion.div>
                );
              })}
            </div>

            {message.text && (
              <div
                className={`mx-6 mt-1 rounded-lg border px-4 py-3 text-sm flex items-center gap-2 ${message.type === "success"
                  ? "bg-[rgba(var(--success-rgb),0.1)] border-[rgba(var(--success-rgb),0.3)] text-[var(--success)]"
                  : "bg-[rgba(var(--danger-rgb),0.1)] border-[rgba(var(--danger-rgb),0.3)] text-[var(--danger)]"
                  }`}
              >
                {message.type === "success" ? (
                  <CheckCircle className="h-4 w-4" />
                ) : (
                  <XCircle className="h-4 w-4" />
                )}
                <span>{message.text}</span>
              </div>
            )}
          </div>
        </div>

        {/* Sticky Footer */}
        <div className="border-t border-dashed border-[var(--border)] rounded-b-2xl h-auto md:h-[89px] bg-transparent z-30 sticky bottom-0 left-0 w-full backdrop-blur-md">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 px-4 md:px-8 py-6">
            <div>
              <p className="text-xs text-[var(--text)]">
                Scans Enabled:{" "}
                {Object.values(scanConfigurations).filter(Boolean).length}/
                {Object.keys(scanConfigurations).length}
              </p>
              <div className="mt-2 flex items-center gap-2 text-xs text-[var(--text)]">
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--success)]" />
                Auto-save on each toggle
              </div>
            </div>

            <div
              type="button"
              onClick={handleSave}
              disabled={!isAdmin || saving}
              className={`h-11 px-7 rounded-lg text-base font-semibold flex items-center gap-2 transition-colors shadow-lg border-2 ${!isAdmin || saving
                ? "bg-[var(--color-primary)] border-[var(--border)] cursor-not-allowed"
                : "bg-[var(--color-primary)] text-[var(--text-on-primary)] border-[var(--color-primary)] hover:opacity-90"
                }`}
              style={{ minWidth: 160 }}
            >
              <Save className="h-5 w-5" />
              {saving ? "Saving..." : "Save Configuration"}
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
};