"use client";

import React, { useState } from "react";
import { ExternalLink, AlertCircle } from "lucide-react";
import CodeSnippetPopup from "./CodeSnippetPopup";

const PolicyItem = ({ policy }) => {
  // Hooks must be called unconditionally at the top level
  const [showCodePopup, setShowCodePopup] = useState(false);
  const [popupError, setPopupError] = useState(null);
  
  // Early return after hooks
  if (!policy) return null;
  
  const severity = policy?.severity || "medium";
  const policyName = policy?.policy_name || policy?.policy_code || "ML-HighEntropy";
  const description = policy?.description || "Suspicious high-entropy string detected";
  const lineNo = policy?.line_no || policy?.Line_No || null;
  const matches = policy?.matches || policy?.Matches || null;
  const codeSnippet = policy?.code_snippet || policy?.snippet || null;
  const remediation = policy?.remediation || null;
  
  const displayName = policyName.replace("ML-", "").replace(/_/g, ' ');

  const severityConfig = {
    critical: { color: "var(--danger)", bg: "var(--danger)15" },
    high: { color: "var(--danger)", bg: "var(--danger)15" },
    medium: { color: "var(--warning)", bg: "var(--warning)15" },
    low: { color: "var(--info)", bg: "var(--info)15" },
    default: { color: "var(--info)", bg: "var(--info)15" },
  };

  const config = severityConfig[severity?.toLowerCase()] || severityConfig.default;

  const handleLineClick = (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    // Reset error state
    setPopupError(null);
    
    // Check if we have enough data to show a useful popup
    const hasValidLineNo = lineNo && lineNo !== "-" && lineNo !== "N/A";
    const hasValidMatches = matches && matches !== "-" && matches !== "N/A";
    const hasValidSnippet = codeSnippet && codeSnippet.length > 0;
    
    if (hasValidSnippet || (hasValidLineNo && hasValidMatches)) {
      setShowCodePopup(true);
    } else {
      // Show error message if no useful data is available
      setPopupError("Code snippet context is not available. Showing error line only.");
      setShowCodePopup(true);
    }
  };

  // Helper function to validate if line number is clickable
  const isLineClickable = () => {
    if (!lineNo || lineNo === "-" || lineNo === "N/A") return false;
    
    const hasValidMatches = matches && matches !== "-" && matches !== "N/A";
    const hasValidSnippet = codeSnippet && codeSnippet.length > 0;
    
    return hasValidSnippet || hasValidMatches;
  };

  const getButtonTitle = () => {
    if (!isLineClickable()) {
      return "No code context available";
    }
    return "Click to view code snippet";
  };

  return (
    <>
      <div
        className="p-4 rounded-lg border-l-4"
        style={{
          borderLeftColor: config.color,
          backgroundColor: config.bg,
        }}
      >
        <div className="flex items-start justify-between mb-2">
          <div className="flex items-center gap-3 flex-wrap">
            <span
              className="px-2 py-1 rounded-full text-xs font-medium capitalize"
              style={{ backgroundColor: config.color, color: "white" }}
            >
              {severity}
            </span>

            <span className="font-mono text-sm font-semibold text-text">
              {policyName}
            </span>

            <span className="text-sm text-text font-medium">
              {displayName}
            </span>
          </div>

          {lineNo && lineNo !== "-" && lineNo !== "N/A" && (
            <button
              onClick={handleLineClick}
              disabled={!isLineClickable()}
              className={`text-sm bg-surface px-2 py-1 rounded border transition-colors ${
                isLineClickable() 
                  ? "text-primary hover:text-primary-600 hover:border-primary/50 cursor-pointer"
                  : "text-muted cursor-not-allowed opacity-60"
              }`}
              title={getButtonTitle()}
            >
              Line {lineNo}
              {!isLineClickable() && (
                <AlertCircle className="w-3 h-3 inline ml-1" />
              )}
            </button>
          )}
        </div>

        <p className="text-text text-sm mb-3">{description}</p>

        {matches && matches !== "-" && matches !== "N/A" && (
          <div className="mt-3">
            <p className="text-xs font-medium text-muted mb-1">Detected Pattern:</p>
            <div className="bg-surface p-3 rounded border font-mono text-xs">
              <code className="text-text break-all">{matches}</code>
            </div>
          </div>
        )}

        {remediation && remediation !== "N/A" && remediation !== "-" && (
          <div className="mt-3">
            <a
              href={remediation}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm text-primary hover:text-primary-600 font-medium"
            >
              View Remediation Guide
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}
      </div>

      {/* CODE SNIPPET POPUP */}
      {showCodePopup && (
        <CodeSnippetPopup
          lineNo={lineNo}
          codeSnippet={codeSnippet}
          matches={matches}
          errorMessage={popupError}
          onClose={() => {
            setShowCodePopup(false);
            setPopupError(null);
          }}
        />
      )}
    </>
  );
};

export default PolicyItem;