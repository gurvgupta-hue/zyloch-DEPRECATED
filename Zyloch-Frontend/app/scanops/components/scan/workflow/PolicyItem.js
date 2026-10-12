"use client";

import Link from "next/link";
import { ExternalLink } from "lucide-react";

const PolicyItem = ({ policy }) => {
  const severityConfig = {
    critical: { color: "var(--danger)", bg: "var(--danger)15" },
    high: { color: "var(--warning)", bg: "var(--warning)15" },
    medium: { color: "var(--info)", bg: "var(--info)15" },
    low: { color: "var(--success)", bg: "var(--success)15" },
  };

  const config = severityConfig[policy.severity] || severityConfig.low;

  const extractRemediationFromDescription = (description) => {
    const urlRegex = /(https?:\/\/[^\s|]+)/g;
    const match = description?.match(urlRegex);
    return match ? match[0] : null;
  };

  const cleanDescription = (description) => {
    if (!description) return "";
    return description.split("| Remediation:")[0]?.trim() || description;
  };

  const getRemediationUrl = () => {
    if (policy.remediation && policy.remediation !== "N/A") {
      return policy.remediation;
    }
    return extractRemediationFromDescription(policy.description);
  };

  const remediationUrl = getRemediationUrl();
  const isExternalUrl = remediationUrl?.startsWith("http");
  const description = cleanDescription(policy.description);

  return (
    <div
      className="fade-in"
      style={{
        padding: "var(--space-5)",
        borderRadius: "12px",
        background: "var(--elevated-surface)",
        border: "1px solid var(--border)",
        boxShadow: "var(--shadow-1)",
      }}
    >
      {/* HEADER */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: "var(--space-4)",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)" }}>
          {/* Severity + Policy Code */}
          <div style={{ display: "flex", gap: "var(--space-3)", flexWrap: "wrap", alignItems: "center" }}>
            <span
              style={{
                backgroundColor: config.color,
                color: "white",
                padding: "2px 10px",
                borderRadius: "var(--radius-full)",
                fontSize: "var(--font-size-xs)",
                fontWeight: "var(--weight-semibold)",
                textTransform: "capitalize",
              }}
            >
              {policy.severity}
            </span>

            <span
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--font-size-sm)",
                fontWeight: "var(--weight-semibold)",
                color: "var(--text)",
              }}
            >
              {policy.policy_code}
            </span>

            {policy.policy_name && (
              <span
                style={{
                  fontSize: "var(--font-size-sm)",
                  color: "var(--muted)",
                  fontWeight: "var(--weight-medium)",
                }}
              >
                {policy.policy_name}
              </span>
            )}
          </div>
        </div>

        {/* Line Number */}
        {policy.Line_No && policy.Line_No !== "-" && (
          <span
            style={{
              backgroundColor: "var(--elevated-surface)",
              padding: "2px 8px",
              borderRadius: "var(--radius-md)",
              fontSize: "var(--font-size-xs)",
              color: "var(--muted)",
            }}
          >
            Line {policy.Line_No}
          </span>
        )}
      </div>

      {/* DESCRIPTION */}
      {description && (
        <p
          style={{
            fontSize: "var(--font-size-sm)",
            color: "var(--text)",
            marginBottom: "var(--space-4)",
            lineHeight: "var(--line-normal)",
          }}
        >
          {description}
        </p>
      )}

      {/* MATCHES */}
      {policy.Matches && policy.Matches !== "-" && (
        <div
          style={{
            backgroundColor: "var(--elevated-surface)",
            padding: "var(--space-4)",
            borderRadius: "var(--radius-md)",
            marginBottom: "var(--space-4)",
            overflowX: "auto",
          }}
        >
          <code
            style={{
              fontSize: "var(--font-size-xs)",
              color: "var(--text)",
              fontFamily: "var(--font-mono)",
            }}
          >
            {policy.Matches}
          </code>
        </div>
      )}

      {/* REMEDIATION LINK */}
      {remediationUrl && (
        isExternalUrl ? (
          <a
            href={remediationUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              fontSize: "var(--font-size-sm)",
              color: "var(--color-primary)",
              fontWeight: "var(--weight-medium)",
            }}
          >
            View Remediation Guide <ExternalLink size={14} />
          </a>
        ) : (
          <Link
            href={remediationUrl}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              fontSize: "var(--font-size-sm)",
              color: "var(--color-primary)",
              fontWeight: "var(--weight-medium)",
            }}
          >
            View Remediation Guide <ExternalLink size={14} />
          </Link>
        )
      )}
    </div>
  );
};

export default PolicyItem;