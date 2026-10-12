"use client";

import React, { useState, useEffect } from "react";
import { OAuthConfigUI } from "./OAuthConfigUI";
import { Copy, Check, Link2 } from "lucide-react";
import { useTheme } from "@/context/ThemeContext";

export const OAuthConfigCard = () => {
  const { theme } = useTheme();
  const isLight = theme === "light";
  const [organization, setOrganization] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [togglingGoogle, setTogglingGoogle] = useState(false);
  const [togglingMicrosoft, setTogglingMicrosoft] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);

  const [googleConfig, setGoogleConfig] = useState({
    enabled: false,
    clientId: "",
    clientSecret: "",
    redirectUri: "",
  });

  const [microsoftConfig, setMicrosoftConfig] = useState({
    enabled: false,
    clientId: "",
    clientSecret: "",
    redirectUri: "",
  });

  useEffect(() => {
    fetchOrganization();
  }, []);

  const fetchOrganization = async () => {
    try {
      setLoading(true);
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization`,
        {
          credentials: "include",
        },
      );

      if (response.ok) {
        const data = await response.json();
        setOrganization(data.organization);

        if (data.organization.oauthConfigurations.google) {
          setGoogleConfig({
            enabled: data.organization.oauthConfigurations.google.enabled,
            clientId:
              data.organization.oauthConfigurations.google.clientId || "",
            clientSecret: data.organization.oauthConfigurations.google
              .hasClientSecret
              ? "••••••••••••••••"
              : "",
            redirectUri:
              data.organization.oauthConfigurations.google.redirectUri || "",
          });
        }

        if (data.organization.oauthConfigurations.microsoft) {
          setMicrosoftConfig({
            enabled: data.organization.oauthConfigurations.microsoft.enabled,
            clientId:
              data.organization.oauthConfigurations.microsoft.clientId || "",
            clientSecret: data.organization.oauthConfigurations.microsoft
              .hasClientSecret
              ? "••••••••••••••••"
              : "",
            redirectUri:
              data.organization.oauthConfigurations.microsoft.redirectUri || "",
          });
        }
      }
    } catch (error) {
      console.error("Error fetching organization:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleToggle = async (enabled) => {
    try {
      setTogglingGoogle(true);
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization/oauth/google`,
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify({
            ...googleConfig,
            clientSecret:
              googleConfig.clientSecret === "••••••••••••••••"
                ? ""
                : googleConfig.clientSecret,
            enabled,
          }),
        },
      );

      if (response.ok) {
        setGoogleConfig({ ...googleConfig, enabled });
        await fetchOrganization();
      } else {
        const error = await response.json();
        alert(error.message || "Failed to update Google OAuth status");
      }
    } catch (error) {
      console.error("Error toggling Google OAuth:", error);
      alert("Failed to update Google OAuth status");
    } finally {
      setTogglingGoogle(false);
    }
  };

  const handleGoogleSave = async () => {
    try {
      setSaving(true);
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization/oauth/google`,
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify({
            ...googleConfig,
            clientSecret:
              googleConfig.clientSecret === "••••••••••••••••"
                ? ""
                : googleConfig.clientSecret,
          }),
        },
      );

      if (response.ok) {
        alert("Google OAuth configuration saved successfully!");
        await fetchOrganization();
      } else {
        const error = await response.json();
        alert(error.message || "Failed to save Google OAuth configuration");
      }
    } catch (error) {
      console.error("Error saving Google OAuth:", error);
      alert("Failed to save Google OAuth configuration");
    } finally {
      setSaving(false);
    }
  };

  const handleMicrosoftToggle = async (enabled) => {
    try {
      setTogglingMicrosoft(true);
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization/oauth/microsoft`,
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify({
            ...microsoftConfig,
            clientSecret:
              microsoftConfig.clientSecret === "••••••••••••••••"
                ? ""
                : microsoftConfig.clientSecret,
            enabled,
          }),
        },
      );

      if (response.ok) {
        setMicrosoftConfig({ ...microsoftConfig, enabled });
        await fetchOrganization();
      } else {
        const error = await response.json();
        alert(error.message || "Failed to update Microsoft OAuth status");
      }
    } catch (error) {
      console.error("Error toggling Microsoft OAuth:", error);
      alert("Failed to update Microsoft OAuth status");
    } finally {
      setTogglingMicrosoft(false);
    }
  };

  const handleMicrosoftSave = async () => {
    try {
      setSaving(true);
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization/oauth/microsoft`,
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify({
            ...microsoftConfig,
            clientSecret:
              microsoftConfig.clientSecret === "••••••••••••••••"
                ? ""
                : microsoftConfig.clientSecret,
          }),
        },
      );

      if (response.ok) {
        alert("Microsoft OAuth configuration saved successfully!");
        await fetchOrganization();
      } else {
        const error = await response.json();
        alert(error.message || "Failed to save Microsoft OAuth configuration");
      }
    } catch (error) {
      console.error("Error saving Microsoft OAuth:", error);
      alert("Failed to save Microsoft OAuth configuration");
    } finally {
      setSaving(false);
    }
  };

  const handleGoogleDelete = async () => {
    if (
      !confirm("Are you sure you want to delete Google OAuth configuration?")
    ) {
      return;
    }

    try {
      setSaving(true);
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization/oauth/google`,
        {
          method: "DELETE",
          credentials: "include",
        },
      );

      if (response.ok) {
        alert("Google OAuth configuration deleted successfully!");
        setGoogleConfig({
          enabled: false,
          clientId: "",
          clientSecret: "",
          redirectUri: "",
        });
        await fetchOrganization();
      } else {
        const error = await response.json();
        alert(error.message || "Failed to delete Google OAuth configuration");
      }
    } catch (error) {
      console.error("Error deleting Google OAuth:", error);
      alert("Failed to delete Google OAuth configuration");
    } finally {
      setSaving(false);
    }
  };

  const handleMicrosoftDelete = async () => {
    if (
      !confirm("Are you sure you want to delete Microsoft OAuth configuration?")
    ) {
      return;
    }

    try {
      setSaving(true);
      const response = await fetch(
                `${process.env.NEXT_PUBLIC_API_URL}/api/organization/oauth/microsoft`,
        {
          method: "DELETE",
          credentials: "include",
        },
      );

      if (response.ok) {
        alert("Microsoft OAuth configuration deleted successfully!");
        setMicrosoftConfig({
          enabled: false,
          clientId: "",
          clientSecret: "",
          redirectUri: "",
        });
        await fetchOrganization();
      } else {
        const error = await response.json();
        alert(
          error.message || "Failed to delete Microsoft OAuth configuration",
        );
      }
    } catch (error) {
      console.error("Error deleting Microsoft OAuth:", error);
      alert("Failed to delete Microsoft OAuth configuration");
    } finally {
      setSaving(false);
    }
  };

  const handleGoogleConfigChange = (field, value) => {
    setGoogleConfig({ ...googleConfig, [field]: value });
  };

  const handleMicrosoftConfigChange = (field, value) => {
    setMicrosoftConfig({ ...microsoftConfig, [field]: value });
  };

  const copyLoginLinkToClipboard = async () => {
    if (!organization?._id) return;

const loginLink = `${process.env.NEXT_PUBLIC_FRONTEND_URL}/login?orgid=${organization._id}`;

    try {
      await navigator.clipboard.writeText(loginLink);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    } catch (error) {
      console.error("Failed to copy login link:", error);
    }
  };

  const isAdmin = organization?.userRole === "admin";

  // The link only ever gets a recipient to the Google/Microsoft SSO buttons
  // on the login page — both stay disabled there until at least one provider
  // is enabled.
  const hasOAuthEnabled = !!(googleConfig.enabled || microsoftConfig.enabled);

  return (
    <>
      <OAuthConfigUI
        // State
        loading={loading}
        saving={saving}
        togglingGoogle={togglingGoogle}
        togglingMicrosoft={togglingMicrosoft}
        isAdmin={isAdmin}
        // Data
        organization={organization}
        googleConfig={googleConfig}
        microsoftConfig={microsoftConfig}
        // Handlers
        onGoogleToggle={handleGoogleToggle}
        onGoogleSave={handleGoogleSave}
        onGoogleDelete={handleGoogleDelete}
        onGoogleConfigChange={handleGoogleConfigChange}
        onMicrosoftToggle={handleMicrosoftToggle}
        onMicrosoftSave={handleMicrosoftSave}
        onMicrosoftDelete={handleMicrosoftDelete}
        onMicrosoftConfigChange={handleMicrosoftConfigChange}
      />

      {/* Shareable Login Link Section — hidden until Google or Microsoft OAuth
          is actually enabled; see hasOAuthEnabled above. */}
      {organization && !hasOAuthEnabled && (
        <div
          className="mt-6 p-4 rounded-xl"
          style={{
            background: "var(--surface)",
            border: isLight ? "1px solid var(--border)" : "none",
            borderRadius: "var(--radius-xl)",
          }}
        >
          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
              style={{
                background:
                  "linear-gradient(135deg, color-mix(in srgb, var(--color-accent) 10%, transparent), color-mix(in srgb, var(--color-primary) 10%, transparent))",
              }}
            >
              <Link2 size={20} style={{ color: "var(--muted)" }} />
            </div>
            <div>
              <h3 className="text-sm font-medium" style={{ color: "var(--text)" }}>
                Shareable sign-in link
              </h3>
              <p className="text-sm" style={{ color: "var(--muted)" }}>
                {isAdmin
                  ? "Enable Google or Microsoft OAuth above to get a link you can share with your team to sign them in."
                  : "Ask an administrator to enable Google or Microsoft OAuth to get a shareable sign-in link."}
              </p>
            </div>
          </div>
        </div>
      )}

      {organization && hasOAuthEnabled && (
        <div
          className="mt-6"
          style={{
            background: "var(--surface)",
            border: isLight ? "1px solid var(--border)" : "none",
            borderRadius: "var(--radius-xl)",
            boxShadow: "var(--shadow-1)",
            transition: "all var(--transition-normal) var(--ease-smooth)",
          }}
        >
          <div className="p-6">
            {/* Header */}
            <div className="flex items-center gap-3 mb-4">
              <div
                className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                style={{
                  background:
                    "linear-gradient(135deg, color-mix(in srgb, var(--color-accent) 10%, transparent), color-mix(in srgb, var(--color-primary) 10%, transparent))",
                }}
              >
                <Link2 size={20} style={{ color: "var(--color-accent)" }} />
              </div>
              <div>
                <h3
                  className="text-lg font-medium"
                  style={{ color: "var(--text)" }}
                >
                  Shareable Sign-in Link
                </h3>
                <p className="text-sm" style={{ color: "var(--muted)" }}>
                  Share this link with your team members
                </p>
              </div>
            </div>

            {/* Login Link and Copy Button */}
            <div className="space-y-3">
              <div
                className="flex items-center gap-3 p-4 rounded-xl"
                style={{
                  background: "var(--elevated-surface)",
                  border: isLight ? "1px solid var(--border)" : "none",
                  borderRadius: "var(--radius-xl)",
                }}
              >
                <div className="flex-1 min-w-0">
                  <code
                    className="text-sm font-mono break-all block"
                    style={{ color: "var(--text)" }}
                  >
                    {`${process.env.NEXT_PUBLIC_FRONTEND_URL}/login?orgid=${organization._id}`}
                  </code>
                </div>
                <button
                  onClick={copyLoginLinkToClipboard}
                  className="p-2 rounded-lg shrink-0 transition-all duration-300"
                  style={{
                    background: "var(--surface)",
                    transform: "scale(1)",
                    transition:
                      "all var(--transition-normal) var(--ease-smooth)",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background =
                      "color-mix(in srgb, var(--surface) 80%, transparent)";
                    e.currentTarget.style.boxShadow = "var(--shadow-1)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "var(--surface)";
                    e.currentTarget.style.boxShadow = "none";
                  }}
                  onMouseDown={(e) => {
                    e.currentTarget.style.transform = "scale(0.95)";
                  }}
                  onMouseUp={(e) => {
                    e.currentTarget.style.transform = "scale(1)";
                  }}
                  title="Copy sign-in link"
                  disabled={copiedLink}
                >
                  {copiedLink ? (
                    <Check size={18} style={{ color: "var(--success)" }} />
                  ) : (
                    <Copy size={18} style={{ color: "var(--muted)" }} />
                  )}
                </button>
              </div>

              {/* Description */}
              <div
                className="p-3 rounded-lg"
                style={{
                  background: "color-mix(in srgb, var(--info) 5%, transparent)",
                  border: isLight ? "1px solid var(--border)" : "none",
                }}
              >
                <p className="text-sm" style={{ color: "var(--muted)" }}>
                  Share this link with your team members to allow them to sign in
                  using Google or Microsoft OAuth with your organization&apos;s
                  credentials.
                </p>
                {!isAdmin && (
                  <p className="text-xs mt-2" style={{ color: "var(--muted)" }}>
                    <strong>Note:</strong> Only administrators can configure
                    OAuth settings.
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
