"use client";

import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X } from "lucide-react";

const CodeSnippetPopup = ({ lineNo, codeSnippet, matches, onClose }) => {
  const errorLineNo = lineNo && lineNo !== "-" ? parseInt(lineNo, 10) : null;

  useEffect(() => {
    const handleEscape = (e) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [onClose]);

  let parsedLines = [];
  let hasFullContext = false;

  if (codeSnippet && Array.isArray(codeSnippet) && codeSnippet.length > 0) {
    hasFullContext = true;
    parsedLines = codeSnippet.map((line) => {
      const match = line.match(/^line_no:(\d+)\s+(.*)$/);
      if (match) {
        return {
          lineNumber: parseInt(match[1], 10),
          content: match[2],
        };
      }

      return {
        lineNumber: null,
        content: line,
      };
    });
  } else if (errorLineNo && matches && matches !== "-") {
    const lineContent = matches.split("//")[0].trim();
    parsedLines = [
      {
        lineNumber: errorLineNo,
        content: lineContent,
      },
    ];
    hasFullContext = false;
  } else {
    // No data available
    return null;
  }

  // Handle backdrop click
  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm"
        onClick={handleBackdropClick}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="bg-surface rounded-2xl shadow-2xl border border-border max-w-4xl w-full max-h-[90vh] flex flex-col"
          onClick={(e) => e.stopPropagation()}
        >
          {/* HEADER */}
          <div className="flex items-center justify-between p-6 border-b border-border">
            <h3 className="text-xl font-bold text-text">Code Details</h3>
            <button
              onClick={onClose}
              className="p-2 hover:bg-elevated-surface rounded-lg transition-colors"
              aria-label="Close popup"
            >
              <X className="w-5 h-5 text-muted" />
            </button>
          </div>

          {/* CONTENT */}
          <div className="flex-1 overflow-auto p-6 space-y-6">
            {/* LINE NUMBER FIELD */}
            <div>
              <label className="block text-sm font-medium text-text mb-2">
                Line Number
              </label>
              <input
                type="text"
                value={lineNo || ""}
                readOnly
                className="w-full px-4 py-2 bg-elevated-surface border border-border rounded-lg text-text font-mono focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>

            {/* CODE SNIPPET SECTION */}
            <div>
              <label className="block text-sm font-medium text-text mb-2">
                Code Snippet
              </label>
              <p className="text-xs text-muted mb-3">
                Context around line {lineNo}
              </p>
              {!hasFullContext && (
                <p className="text-xs text-warning mb-3">
                  Full code context not available. Showing error line only.
                </p>
              )}
              <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
                <pre className="p-4 font-mono text-sm leading-relaxed m-0 bg-gray-900">
                  {parsedLines.map((line, index) => {
                    const isErrorLine = errorLineNo && line.lineNumber === errorLineNo;
                    return (
                      <div
                        key={index}
                        className={`flex items-start gap-4 px-3 py-1 ${
                          isErrorLine
                            ? "bg-red-900/40 border-l-4 border-red-600"
                            : "hover:bg-gray-800/50"
                        }`}
                      >
                        {/* LINE NUMBER */}
                        <span
                          className={`text-right min-w-[60px] text-xs select-none ${
                            isErrorLine ? "text-red-400 font-bold" : "text-gray-500"
                          }`}
                        >
                          {line.lineNumber || "?"}
                        </span>

                        {/* ERROR MARKER */}
                        <span
                          className={`min-w-[40px] text-xs font-bold ${
                            isErrorLine ? "text-red-500" : "text-transparent"
                          }`}
                        >
                          {isErrorLine ? ">>>" : ""}
                        </span>

                        {/* CODE CONTENT */}
                        <span
                          className={`flex-1 ${
                            isErrorLine ? "text-red-300 font-semibold" : "text-gray-100"
                          }`}
                        >
                          {line.content || " "}
                        </span>
                      </div>
                    );
                  })}
                </pre>
              </div>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default CodeSnippetPopup;

