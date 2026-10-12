// components/common/Tabs.js
"use client";
import React, { useState } from "react";

export default function Tabs({
  tabs,
  defaultTab,
  onChange,
  className = "",
  ...props
}) {
  const [activeTab, setActiveTab] = useState(defaultTab || tabs[0]?.id);

  const handleTabClick = (tabId) => {
    setActiveTab(tabId);
    onChange?.(tabId);
  };

  return (
    <div className={className} {...props}>
      <div className="flex border-b border-border">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => handleTabClick(tab.id)}
            className={`
              relative
              font-medium
              transition-fast
              ${
                activeTab === tab.id
                  ? "text-primary"
                  : "text-muted hover:text-text"
              }
            `}
            style={{
              padding: "var(--space-3) var(--space-4)",
            }}
          >
            {tab.label}

            {activeTab === tab.id && (
              <div
                className="absolute left-0 right-0 bg-primary"
                style={{
                  bottom: 0,
                  height: "var(--border-thick)",
                }}
              />
            )}
          </button>
        ))}
      </div>

      <div
        style={{
          padding: "var(--space-4) 0",
        }}
      >
        {tabs.find((tab) => tab.id === activeTab)?.content}
      </div>
    </div>
  );
}
