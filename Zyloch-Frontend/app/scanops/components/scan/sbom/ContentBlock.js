import React from "react";

const ContentBlock = React.memo(({ title, description, children, className = "" }) => (
  <div
    className={`flex flex-col w-full border border-[var(--border)] bg-[var(--surface)] shadow-[var(--shadow-soft)] transition-all duration-300 ${className}`}
    style={{ borderRadius: "var(--radius-lg)" }}
  >
    <div className="px-[var(--space-6)] py-[var(--space-4)]">
      {title && (
        <div className="text-[var(--text)] text-lg font-semibold leading-snug">{title}</div>
      )}
      {description && (
        <div className="mt-1 text-[var(--muted)] text-xs leading-snug">{description}</div>
      )}
    </div>
    <div className="px-[var(--space-6)] pb-[var(--space-6)] pt-0 flex-1 overflow-visible">{children}</div>
  </div>
));

export default ContentBlock;
