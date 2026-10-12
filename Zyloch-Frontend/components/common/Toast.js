"use client";
import React, { useEffect } from "react";

export default function Toast({
  message,
  type = "info",
  duration = 3000,
  onClose,
  className = "",
  ...props
}) {
  useEffect(() => {
    if (duration) {
      const timer = setTimeout(onClose, duration);
      return () => clearTimeout(timer);
    }
  }, [duration, onClose]);

  const types = {
    info: "bg-info text-on-info",
    success: "bg-success text-on-success",
    warning: "bg-warning text-on-warning",
    danger: "bg-danger text-on-danger",
  };

  return (
    <div
      className={`fixed top-4 right-4 z-toast rounded-lg shadow-2 animate-slideIn ${types[type]} ${className}`}
      style={{
        padding: "var(--space-3) var(--space-4)",
        animationDuration: "300ms", // smooth animation transition for showing
      }}
      {...props}
    >
      <div className="flex items-center">
        <span className="mr-3">{message}</span>
        <button
          onClick={onClose}
          className="ml-auto opacity-70 hover:opacity-100"
          style={{
            padding: "var(--space-1)",
            transition: "opacity 200ms ease",
          }}
        >
          <svg
            className="w-4 h-4"
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
    </div>
  );
}
