"use client";

import React, { useState } from "react";
import {
  Save,
  Trash2,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { useTheme } from "@/context/ThemeContext";

// Since you have SVGR configured, these are React components
import GoogleIcon from "@/public/assets/icons/google.svg";
import MicrosoftIcon from "@/public/assets/icons/microsoft.svg";

export const OAuthConfigUI = ({
  // State
  loading,
  saving,
  togglingGoogle,
  togglingMicrosoft,
  isAdmin,

  // Data
  organization,
  googleConfig,
  microsoftConfig,

  // Handlers
  onGoogleToggle,
  onGoogleSave,
  onGoogleDelete,
  onGoogleConfigChange,

  onMicrosoftToggle,
  onMicrosoftSave,
  onMicrosoftDelete,
  onMicrosoftConfigChange,
}) => {
  const { theme } = useTheme();
  const isLight = theme === "light";
  const [showGoogleSecret, setShowGoogleSecret] = useState(false);
  const [showMicrosoftSecret, setShowMicrosoftSecret] = useState(false);
  const [isGoogleExpanded, setIsGoogleExpanded] = useState(false);
  const [isMicrosoftExpanded, setIsMicrosoftExpanded] = useState(false);

  if (loading) {
    return (
      <div
        className="bg-surface rounded-xl p-6"
        style={{
          background: "var(--surface)",
          border: isLight ? "1px solid var(--border)" : "none",
          borderRadius: "var(--radius-xl)",
          boxShadow: "var(--shadow-1)",
        }}
      >
        <p style={{ color: "var(--muted)" }}>Loading OAuth configurations...</p>
      </div>
    );
  }

  if (!isAdmin) {
    return (
      <div
        className="bg-surface rounded-xl p-6"
        style={{
          background: "var(--surface)",
          border: isLight ? "1px solid var(--border)" : "none",
          borderRadius: "var(--radius-xl)",
          boxShadow: "var(--shadow-1)",
        }}
      >
        <p style={{ color: "var(--muted)" }}>
          Only organization administrators can manage OAuth configurations.
        </p>
      </div>
    );
  }

  const GoogleSection = () => (
    <div
      className="w-full rounded-xl overflow-hidden"
      style={{
        background: "var(--surface)",
        border: isLight ? "1px solid var(--border)" : "none",
        borderRadius: "var(--radius-xl)",
        boxShadow: "var(--shadow-1)",
        transition: "all var(--transition-normal) var(--ease-smooth)",
        "--hover-shadow": "var(--shadow-2)",
      }}
      onMouseOver={(e) => {
        e.currentTarget.style.boxShadow = "var(--hover-shadow)";
      }}
      onMouseOut={(e) => {
        e.currentTarget.style.boxShadow = "var(--shadow-1)";
      }}
    >
      {/* Google Header - Blue Background */}
      <div
        className="p-4 sm:p-6"
        style={{
          background:
            "linear-gradient(135deg, var(--color-primary), color-mix(in srgb, var(--color-primary) 80%, var(--info)))",
          color: "var(--text-on-primary)",
          cursor: "pointer",
          userSelect: "none",
        }}
        onClick={() => setIsGoogleExpanded(!isGoogleExpanded)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
              style={{
                background: "var(--surface)",
              }}
            >
              <GoogleIcon
                className="w-6 h-6"
                style={{ color: "var(--color-primary)" }}
              />
            </div>
            <div className="min-w-0">
              <h3
                className="text-base font-semibold sm:text-lg"
                style={{ color: "var(--text-on-primary)" }}
              >
                Google OAuth
              </h3>
              <p className="mt-1 text-xs opacity-90">
                {googleConfig.enabled ? "Enabled for sign-in" : "Disabled"}
              </p>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2 sm:gap-3">
            <span className="hidden text-xs opacity-90 sm:inline sm:text-sm">
              {togglingGoogle ? "Updating..." : ""}
            </span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onGoogleToggle(!googleConfig.enabled);
              }}
              disabled={togglingGoogle}
              className="relative inline-flex h-6 w-11 items-center rounded-full transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              style={{
                background: googleConfig.enabled
                  ? "var(--surface)"
                  : "color-mix(in srgb, var(--text-on-primary) 30%, transparent)",
                border: "2px solid",
                borderColor: googleConfig.enabled
                  ? "var(--surface)"
                  : "color-mix(in srgb, var(--text-on-primary) 50%, transparent)",
                transition: "all var(--transition-normal) var(--ease-smooth)",
              }}
            >
              <span
                className="inline-block h-4 w-4 rounded-full transition-all duration-300"
                style={{
                  background: googleConfig.enabled
                    ? "var(--color-primary)"
                    : "color-mix(in srgb, var(--text-on-primary) 80%, transparent)",
                  transform: googleConfig.enabled
                    ? "translateX(1.5rem)"
                    : "translateX(0.25rem)",
                  boxShadow: "var(--shadow-1)",
                }}
              />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setIsGoogleExpanded(!isGoogleExpanded);
              }}
              className="p-1 rounded-lg transition-all duration-300"
              style={{ color: "var(--text-on-primary)" }}
              onMouseOver={(e) => {
                e.currentTarget.style.background =
                  "color-mix(in srgb, var(--text-on-primary) 20%, transparent)";
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.background = "transparent";
              }}
            >
              {isGoogleExpanded ? (
                <ChevronUp
                  size={20}
                  style={{ color: "var(--text-on-primary)" }}
                />
              ) : (
                <ChevronDown
                  size={20}
                  style={{ color: "var(--text-on-primary)" }}
                />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Collapsible Content */}
      {isGoogleExpanded && (
        <div className="space-y-6 p-4 sm:p-6">
          <div className="space-y-4">
            <div className="space-y-2">
              <label
                className="block text-sm font-medium"
                style={{ color: "var(--muted)" }}
              >
                Client ID
              </label>
              <input
                type="text"
                value={googleConfig.clientId}
                onChange={(e) =>
                  onGoogleConfigChange("clientId", e.target.value)
                }
                placeholder="Enter Google Client ID"
                className="w-full px-4 py-3 rounded-xl text-sm"
                style={{
                  background: "var(--elevated-surface)",
                  border: "1px solid var(--border)",
                  color: "var(--text)",
                  transition: "all var(--transition-normal) var(--ease-smooth)",
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = "var(--color-primary)";
                  e.target.style.boxShadow =
                    "0 0 0 3px color-mix(in srgb, var(--color-primary) 20%, transparent)";
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = "var(--border)";
                  e.target.style.boxShadow = "none";
                }}
                disabled={!googleConfig.enabled}
              />
            </div>

            <div className="space-y-2">
              <label
                className="text-sm font-medium flex items-center justify-between"
                style={{ color: "var(--muted)" }}
              >
                <span>Client Secret</span>
                {organization?.oauthConfigurations?.google?.hasClientSecret && (
                  <span
                    className="text-xs px-2 py-1 rounded-md"
                    style={{
                      background:
                        "color-mix(in srgb, var(--success) 10%, transparent)",
                      color: "var(--success)",
                    }}
                  >
                    ✓ Configured
                  </span>
                )}
              </label>
              <div className="relative">
                <input
                  type={
                    showGoogleSecret &&
                      googleConfig.clientSecret !== "••••••••••••••••"
                      ? "text"
                      : "password"
                  }
                  value={googleConfig.clientSecret}
                  onChange={(e) => {
                    onGoogleConfigChange("clientSecret", e.target.value);
                    if (
                      e.target.value !== "••••••••••••••••" &&
                      e.target.value !== ""
                    ) {
                      setShowGoogleSecret(false);
                    }
                  }}
                  placeholder="Enter Google Client Secret"
                  className="w-full px-4 py-3 pr-12 rounded-xl text-sm"
                  style={{
                    background: "var(--elevated-surface)",
                    border: "1px solid var(--border)",
                    color: "var(--text)",
                    transition:
                      "all var(--transition-normal) var(--ease-smooth)",
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = "var(--color-primary)";
                    e.target.style.boxShadow =
                      "0 0 0 3px color-mix(in srgb, var(--color-primary) 20%, transparent)";
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = "var(--border)";
                    e.target.style.boxShadow = "none";
                  }}
                  disabled={!googleConfig.enabled}
                />
                {googleConfig.clientSecret &&
                  googleConfig.clientSecret !== "••••••••••••••••" && (
                    <button
                      type="button"
                      onClick={() => setShowGoogleSecret(!showGoogleSecret)}
                      disabled={!googleConfig.enabled}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 p-1 rounded-lg transition-all duration-300"
                      style={{
                        color: "var(--muted)",
                        background: "transparent",
                        "--hover-bg":
                          "color-mix(in srgb, var(--surface) 80%, transparent)",
                      }}
                      onMouseOver={(e) => {
                        e.currentTarget.style.background = "var(--hover-bg)";
                        e.currentTarget.style.color = "var(--text)";
                      }}
                      onMouseOut={(e) => {
                        e.currentTarget.style.background = "transparent";
                        e.currentTarget.style.color = "var(--muted)";
                      }}
                    >
                      {showGoogleSecret ? (
                        <EyeOff size={18} />
                      ) : (
                        <Eye size={18} />
                      )}
                    </button>
                  )}
              </div>
              {organization?.oauthConfigurations?.google?.hasClientSecret && (
                <p className="text-xs mt-2" style={{ color: "var(--muted)" }}>
                  {googleConfig.clientSecret === "••••••••••••••••"
                    ? "Secret is configured. Enter new secret to update or leave blank to keep existing."
                    : "Leave blank to keep existing secret"}
                </p>
              )}
            </div>

            <div className="space-y-2">
              <label
                className="block text-sm font-medium"
                style={{ color: "var(--muted)" }}
              >
                Redirect URI
              </label>
              <input
                type="text"
                value={googleConfig.redirectUri}
                onChange={(e) =>
                  onGoogleConfigChange("redirectUri", e.target.value)
                }
                placeholder="https://yourapp.com/auth/google/callback"
                className="w-full px-4 py-3 rounded-xl text-sm"
                style={{
                  background: "var(--elevated-surface)",
                  border: "1px solid var(--border)",
                  color: "var(--text)",
                  transition: "all var(--transition-normal) var(--ease-smooth)",
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = "var(--color-primary)";
                  e.target.style.boxShadow =
                    "0 0 0 3px color-mix(in srgb, var(--color-primary) 20%, transparent)";
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = "var(--border)";
                  e.target.style.boxShadow = "none";
                }}
                disabled={!googleConfig.enabled}
              />
            </div>
          </div>

          <div className="flex flex-col gap-3 pt-2 sm:flex-row">
            <button
              onClick={onGoogleSave}
              disabled={saving || !googleConfig.enabled}
              className="flex items-center gap-2 px-5 py-3 rounded-xl text-sm font-semibold transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex-1 justify-center"
              style={{
                background:
                  "linear-gradient(to right, var(--color-primary), color-mix(in srgb, var(--color-primary) 90%, transparent))",
                color: "var(--text-on-primary)",
                boxShadow: "var(--shadow-1)",
                transform: "scale(1)",
                transition: "all var(--transition-normal) var(--ease-smooth)",
                "--hover-shadow": "var(--shadow-2)",
                "--active-scale": "scale(0.98)",
              }}
              onMouseOver={(e) => {
                if (!saving && googleConfig.enabled) {
                  e.currentTarget.style.boxShadow = "var(--hover-shadow)";
                }
              }}
              onMouseOut={(e) => {
                if (!saving && googleConfig.enabled) {
                  e.currentTarget.style.boxShadow = "var(--shadow-1)";
                }
              }}
              onMouseDown={(e) => {
                if (!saving && googleConfig.enabled) {
                  e.currentTarget.style.transform = "var(--active-scale)";
                }
              }}
              onMouseUp={(e) => {
                if (!saving && googleConfig.enabled) {
                  e.currentTarget.style.transform = "scale(1)";
                }
              }}
            >
              <Save size={16} />
              {saving ? "Saving..." : "Save Configuration"}
            </button>

            {organization?.oauthConfigurations?.google?.enabled && (
              <button
                onClick={onGoogleDelete}
                disabled={saving}
                className="flex items-center justify-center gap-2 px-5 py-3 rounded-xl text-sm font-semibold transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed sm:justify-start"
                style={{
                  background: "var(--surface)",
                  color: "var(--danger)",
                  boxShadow: "var(--shadow-1)",
                  border: "1px solid var(--border)",
                  transform: "scale(1)",
                  transition: "all var(--transition-normal) var(--ease-smooth)",
                  "--hover-bg":
                    "color-mix(in srgb, var(--surface) 80%, transparent)",
                  "--hover-shadow": "var(--shadow-2)",
                  "--hover-border": "1px solid var(--danger)",
                  "--active-scale": "scale(0.98)",
                }}
                onMouseOver={(e) => {
                  if (!saving) {
                    e.currentTarget.style.background = "var(--hover-bg)";
                    e.currentTarget.style.boxShadow = "var(--hover-shadow)";
                    e.currentTarget.style.borderColor = "var(--hover-border)";
                  }
                }}
                onMouseOut={(e) => {
                  if (!saving) {
                    e.currentTarget.style.background = "var(--surface)";
                    e.currentTarget.style.boxShadow = "var(--shadow-1)";
                    e.currentTarget.style.borderColor = "var(--border)";
                  }
                }}
                onMouseDown={(e) => {
                  if (!saving) {
                    e.currentTarget.style.transform = "var(--active-scale)";
                  }
                }}
                onMouseUp={(e) => {
                  if (!saving) {
                    e.currentTarget.style.transform = "scale(1)";
                  }
                }}
              >
                <Trash2 size={16} />
                Delete
              </button>
            )}
          </div>

          {organization?.oauthConfigurations?.google?.configuredAt && (
            <p
              className="text-xs pt-2 border-t"
              style={{
                color: "var(--muted)",
                borderColor: "var(--border)",
              }}
            >
              Last configured:{" "}
              {new Date(
                organization.oauthConfigurations.google.configuredAt,
              ).toLocaleString()}
            </p>
          )}
        </div>
      )}
    </div>
  );

  const MicrosoftSection = () => (
    <div
      className="w-full rounded-xl overflow-hidden"
      style={{
        background: "var(--surface)",
        border: isLight ? "1px solid var(--border)" : "none",
        borderRadius: "var(--radius-xl)",
        boxShadow: "var(--shadow-1)",
        transition: "all var(--transition-normal) var(--ease-smooth)",
        "--hover-shadow": "var(--shadow-2)",
      }}
      onMouseOver={(e) => {
        e.currentTarget.style.boxShadow = "var(--hover-shadow)";
      }}
      onMouseOut={(e) => {
        e.currentTarget.style.boxShadow = "var(--shadow-1)";
      }}
    >
      {/* Microsoft Header - Grey Background */}
      <div
        className="p-4 sm:p-6"
        style={{
          background:
            "linear-gradient(135deg, var(--muted), color-mix(in srgb, var(--muted) 80%, var(--surface)))",
          color: "var(--text)",
          cursor: "pointer",
          userSelect: "none",
        }}
        onClick={() => setIsMicrosoftExpanded(!isMicrosoftExpanded)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
              style={{
                background: "var(--surface)",
              }}
            >
              <MicrosoftIcon
                className="w-6 h-6"
                style={{ color: "var(--text)" }}
              />
            </div>
            <div className="min-w-0">
              <h3
                className="text-base font-semibold sm:text-lg"
                style={{ color: "var(--text)" }}
              >
                Microsoft OAuth
              </h3>
              <p
                className="text-xs mt-1 opacity-90"
                style={{ color: "var(--text)" }}
              >
                {microsoftConfig.enabled ? "Enabled for sign-in" : "Disabled"}
              </p>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2 sm:gap-3">
            <span
              className="hidden text-xs opacity-90 sm:inline sm:text-sm"
              style={{ color: "var(--text)" }}
            >
              {togglingMicrosoft ? "Updating..." : ""}
            </span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onMicrosoftToggle(!microsoftConfig.enabled);
              }}
              disabled={togglingMicrosoft}
              className="relative inline-flex h-6 w-11 items-center rounded-full transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              style={{
                background: microsoftConfig.enabled
                  ? "var(--color-primary)"
                  : "color-mix(in srgb, var(--text) 12%, transparent)",
                border: "2px solid",
                borderColor: microsoftConfig.enabled
                  ? "var(--color-primary)"
                  : "color-mix(in srgb, var(--text) 20%, transparent)",
                transition: "all var(--transition-normal) var(--ease-smooth)",
              }}
            >
              <span
                className="inline-block h-4 w-4 rounded-full transition-all duration-300"
                style={{
                  background: microsoftConfig.enabled
                    ? "var(--text-on-primary)"
                    : "color-mix(in srgb, var(--surface) 85%, transparent)",
                  transform: microsoftConfig.enabled
                    ? "translateX(1.5rem)"
                    : "translateX(0.25rem)",
                  boxShadow: "var(--shadow-1)",
                }}
              />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setIsMicrosoftExpanded(!isMicrosoftExpanded);
              }}
              className="p-1 rounded-lg transition-all duration-300"
              style={{ color: "var(--text)" }}
              onMouseOver={(e) => {
                e.currentTarget.style.background =
                  "color-mix(in srgb, var(--text) 10%, transparent)";
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.background = "transparent";
              }}
            >
              {isMicrosoftExpanded ? (
                <ChevronUp size={20} />
              ) : (
                <ChevronDown size={20} />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Collapsible Content */}
      {isMicrosoftExpanded && (
        <div className="space-y-6 p-4 sm:p-6">
          <div className="space-y-4">
            <div className="space-y-2">
              <label
                className="block text-sm font-medium"
                style={{ color: "var(--muted)" }}
              >
                Client ID
              </label>
              <input
                type="text"
                value={microsoftConfig.clientId}
                onChange={(e) =>
                  onMicrosoftConfigChange("clientId", e.target.value)
                }
                placeholder="Enter Microsoft Client ID"
                className="w-full px-4 py-3 rounded-xl text-sm"
                style={{
                  background: "var(--elevated-surface)",
                  border: "1px solid var(--border)",
                  color: "var(--text)",
                  transition: "all var(--transition-normal) var(--ease-smooth)",
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = "var(--color-primary)";
                  e.target.style.boxShadow =
                    "0 0 0 3px color-mix(in srgb, var(--color-primary) 20%, transparent)";
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = "var(--border)";
                  e.target.style.boxShadow = "none";
                }}
                disabled={!microsoftConfig.enabled}
              />
            </div>

            <div className="space-y-2">
              <label
                className="text-sm font-medium flex items-center justify-between"
                style={{ color: "var(--muted)" }}
              >
                <span>Client Secret</span>
                {organization?.oauthConfigurations?.microsoft
                  ?.hasClientSecret && (
                    <span
                      className="text-xs px-2 py-1 rounded-md"
                      style={{
                        background:
                          "color-mix(in srgb, var(--success) 10%, transparent)",
                        color: "var(--success)",
                      }}
                    >
                      ✓ Configured
                    </span>
                  )}
              </label>
              <div className="relative">
                <input
                  type={
                    showMicrosoftSecret &&
                      microsoftConfig.clientSecret !== "••••••••••••••••"
                      ? "text"
                      : "password"
                  }
                  value={microsoftConfig.clientSecret}
                  onChange={(e) => {
                    onMicrosoftConfigChange("clientSecret", e.target.value);
                    if (
                      e.target.value !== "••••••••••••••••" &&
                      e.target.value !== ""
                    ) {
                      setShowMicrosoftSecret(false);
                    }
                  }}
                  placeholder="Enter Microsoft Client Secret"
                  className="w-full px-4 py-3 pr-12 rounded-xl text-sm"
                  style={{
                    background: "var(--elevated-surface)",
                    border: "1px solid var(--border)",
                    color: "var(--text)",
                    transition:
                      "all var(--transition-normal) var(--ease-smooth)",
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = "var(--color-primary)";
                    e.target.style.boxShadow =
                      "0 0 0 3px color-mix(in srgb, var(--color-primary) 20%, transparent)";
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = "var(--border)";
                    e.target.style.boxShadow = "none";
                  }}
                  disabled={!microsoftConfig.enabled}
                />
                {microsoftConfig.clientSecret &&
                  microsoftConfig.clientSecret !== "••••••••••••••••" && (
                    <button
                      type="button"
                      onClick={() =>
                        setShowMicrosoftSecret(!showMicrosoftSecret)
                      }
                      disabled={!microsoftConfig.enabled}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 p-1 rounded-lg transition-all duration-300"
                      style={{
                        color: "var(--muted)",
                        background: "transparent",
                        "--hover-bg":
                          "color-mix(in srgb, var(--surface) 80%, transparent)",
                      }}
                      onMouseOver={(e) => {
                        e.currentTarget.style.background = "var(--hover-bg)";
                        e.currentTarget.style.color = "var(--text)";
                      }}
                      onMouseOut={(e) => {
                        e.currentTarget.style.background = "transparent";
                        e.currentTarget.style.color = "var(--muted)";
                      }}
                    >
                      {showMicrosoftSecret ? (
                        <EyeOff size={18} />
                      ) : (
                        <Eye size={18} />
                      )}
                    </button>
                  )}
              </div>
              {organization?.oauthConfigurations?.microsoft
                ?.hasClientSecret && (
                  <p className="text-xs mt-2" style={{ color: "var(--muted)" }}>
                    {microsoftConfig.clientSecret === "••••••••••••••••"
                      ? "Secret is configured. Enter new secret to update or leave blank to keep existing."
                      : "Leave blank to keep existing secret"}
                  </p>
                )}
            </div>

            <div className="space-y-2">
              <label
                className="block text-sm font-medium"
                style={{ color: "var(--muted)" }}
              >
                Redirect URI
              </label>
              <input
                type="text"
                value={microsoftConfig.redirectUri}
                onChange={(e) =>
                  onMicrosoftConfigChange("redirectUri", e.target.value)
                }
                placeholder="https://yourapp.com/auth/microsoft/callback"
                className="w-full px-4 py-3 rounded-xl text-sm"
                style={{
                  background: "var(--elevated-surface)",
                  border: "1px solid var(--border)",
                  color: "var(--text)",
                  transition: "all var(--transition-normal) var(--ease-smooth)",
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = "var(--color-primary)";
                  e.target.style.boxShadow =
                    "0 0 0 3px color-mix(in srgb, var(--color-primary) 20%, transparent)";
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = "var(--border)";
                  e.target.style.boxShadow = "none";
                }}
                disabled={!microsoftConfig.enabled}
              />
            </div>
          </div>

          <div className="flex flex-col gap-3 pt-2 sm:flex-row">
            <button
              onClick={onMicrosoftSave}
              disabled={saving || !microsoftConfig.enabled}
              className="flex items-center gap-2 px-5 py-3 rounded-xl text-sm font-semibold transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex-1 justify-center"
              style={{
                background:
                  "linear-gradient(to right, var(--color-primary), color-mix(in srgb, var(--color-primary) 90%, transparent))",
                color: "var(--text-on-primary)",
                boxShadow: "var(--shadow-1)",
                transform: "scale(1)",
                transition: "all var(--transition-normal) var(--ease-smooth)",
                "--hover-shadow": "var(--shadow-2)",
                "--active-scale": "scale(0.98)",
              }}
              onMouseOver={(e) => {
                if (!saving && microsoftConfig.enabled) {
                  e.currentTarget.style.boxShadow = "var(--hover-shadow)";
                }
              }}
              onMouseOut={(e) => {
                if (!saving && microsoftConfig.enabled) {
                  e.currentTarget.style.boxShadow = "var(--shadow-1)";
                }
              }}
              onMouseDown={(e) => {
                if (!saving && microsoftConfig.enabled) {
                  e.currentTarget.style.transform = "var(--active-scale)";
                }
              }}
              onMouseUp={(e) => {
                if (!saving && microsoftConfig.enabled) {
                  e.currentTarget.style.transform = "scale(1)";
                }
              }}
            >
              <Save size={16} />
              {saving ? "Saving..." : "Save Configuration"}
            </button>

            {organization?.oauthConfigurations?.microsoft?.enabled && (
              <button
                onClick={onMicrosoftDelete}
                disabled={saving}
                className="flex items-center justify-center gap-2 px-5 py-3 rounded-xl text-sm font-semibold transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed sm:justify-start"
                style={{
                  background: "var(--surface)",
                  color: "var(--danger)",
                  boxShadow: "var(--shadow-1)",
                  border: "1px solid var(--border)",
                  transform: "scale(1)",
                  transition: "all var(--transition-normal) var(--ease-smooth)",
                  "--hover-bg":
                    "color-mix(in srgb, var(--surface) 80%, transparent)",
                  "--hover-shadow": "var(--shadow-2)",
                  "--hover-border": "1px solid var(--danger)",
                  "--active-scale": "scale(0.98)",
                }}
                onMouseOver={(e) => {
                  if (!saving) {
                    e.currentTarget.style.background = "var(--hover-bg)";
                    e.currentTarget.style.boxShadow = "var(--hover-shadow)";
                    e.currentTarget.style.borderColor = "var(--hover-border)";
                  }
                }}
                onMouseOut={(e) => {
                  if (!saving) {
                    e.currentTarget.style.background = "var(--surface)";
                    e.currentTarget.style.boxShadow = "var(--shadow-1)";
                    e.currentTarget.style.borderColor = "var(--border)";
                  }
                }}
                onMouseDown={(e) => {
                  if (!saving) {
                    e.currentTarget.style.transform = "var(--active-scale)";
                  }
                }}
                onMouseUp={(e) => {
                  if (!saving) {
                    e.currentTarget.style.transform = "scale(1)";
                  }
                }}
              >
                <Trash2 size={16} />
                Delete
              </button>
            )}
          </div>

          {organization?.oauthConfigurations?.microsoft?.configuredAt && (
            <p
              className="text-xs pt-2 border-t"
              style={{
                color: "var(--muted)",
                borderColor: "var(--border)",
              }}
            >
              Last configured:{" "}
              {new Date(
                organization.oauthConfigurations.microsoft.configuredAt,
              ).toLocaleString()}
            </p>
          )}
        </div>
      )}
    </div>
  );

  return (
    <div className="space-y-6 fade-in">
      <div className="flex flex-col gap-4 xl:flex-row xl:gap-6">
        <GoogleSection />
        <MicrosoftSection />
      </div>
    </div>
  );
};
