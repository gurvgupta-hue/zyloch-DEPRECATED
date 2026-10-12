// components/common/Modal.js
"use client";
import React, { useEffect } from "react";

export default function Modal({
  isOpen,
  onClose,
  title,
  children,
  size = "md",
  className = "",
  ...props
}) {
  useEffect(() => {
    const handleEscape = (e) => {
      if (e.key === "Escape") onClose();
    };

    if (isOpen) {
      document.addEventListener("keydown", handleEscape);
      const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
      document.body.style.setProperty(
        "--scrollbar-compensation",
        `${Math.max(scrollbarWidth, 0)}px`
      );
      document.body.classList.add("scroll-locked");
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
      document.body.classList.remove("scroll-locked");
      document.body.style.removeProperty("--scrollbar-compensation");
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const sizes = {
    sm: "max-w-md",
    md: "max-w-lg",
    lg: "max-w-2xl",
    xl: "max-w-4xl",
  };

  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget) onClose();
  };

  return (
    <div className="fixed inset-0 z-modal" onClick={handleBackdropClick}>
      {/* Backdrop */}
      <div
        className="fixed inset-0 animate-fadeIn"
        style={{
          background: "rgba(var(--bg-rgb), 0.6)",
        }}
      />

      <div className="flex min-h-full items-center justify-center p-4">
        <div
          className={`
            relative
            bg-surface
            rounded-xl
            shadow-3
            w-full
            ${sizes[size] ?? sizes.md}
            animate-scale-in
            ${className}
          `}
          {...props}
        >
          {title && (
            <div className="flex items-center justify-between p-6 pb-0">
              <h2
                className="text-xl"
                style={{
                  color: "var(--text)",
                  fontWeight: "700",
                }}
              >
                {title}
              </h2>

              <button
                onClick={onClose}
                className="
                  text-muted
                  hover:text-text
                  p-1
                  rounded-full
                  hover:bg-elevated
                  transition-fast
                "
              >
                <svg
                  className="w-5 h-5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>
          )}

          <div className="p-6">{children}</div>
        </div>
      </div>
    </div>
  );
}
