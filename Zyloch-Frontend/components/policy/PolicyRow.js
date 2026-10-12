import React, { useState, useRef, useEffect } from 'react';

const SEVERITY_OPTIONS = ['Critical', 'High', 'Medium', 'Low'];

const PolicyRow = ({ policyId, title, description, severity, enabled, onToggle, onSeverityChange, disabled = false }) => {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    if (!dropdownOpen) return;
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [dropdownOpen]);

  // mapping for severity
  const severityStyles = {
    Critical: { bg: 'rgba(251, 44, 54, 0.15)', border: 'rgba(251, 44, 54, 0.3)', text: '#FF6467', icon: '#FF6467' },
    High: { bg: 'rgba(255, 105, 0, 0.15)', border: 'rgba(255, 105, 0, 0.3)', text: '#FF8904', icon: '#FF8904' },
    Medium: { bg: 'rgba(255, 193, 7, 0.15)', border: 'rgba(255, 193, 7, 0.3)', text: '#FFC107', icon: '#FFC107' },
    Low: { bg: 'rgba(142, 81, 255, 0.15)', border: 'rgba(142, 81, 255, 0.3)', text: '#A684FF', icon: '#A684FF' },
  };

  const currentSeverity = severityStyles[severity] || severityStyles.Medium;

  return (
    <div className="flex flex-col items-start p-0 w-full border-b border-[var(--border)]">
      <div className="flex flex-row items-center py-3 px-6 gap-4 w-full hover:bg-[var(--elevated-surface)] transition-colors">
        {/* Small Toggle */}
        <div
          onClick={() => !disabled && onToggle()}
          title={disabled ? 'Only GitHub administrators can modify policies' : undefined}
          className={`relative w-8 h-[18px] rounded-full shadow-inner transition-colors duration-200 ${disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'} ${enabled ? 'bg-[#00D3F3]' : 'bg-[#2A2D36]'}`}
          style={{ flexShrink: 0 }}
        >
          <div
            className={`absolute top-[2px] w-[14px] h-[14px] bg-white rounded-full transition-all duration-200 ${enabled ? 'left-[16px]' : 'left-[2px]'}`}
            style={{ boxShadow: '0px 1px 3px rgba(0, 0, 0, 0.1), 0px 1px 2px -1px rgba(0, 0, 0, 0.1)' }}
          />
        </div>

        {/* Text and Policy ID */}
        <div className="flex flex-col items-start p-0 flex-1 min-w-0">
          {/* Row 1: Policy ID (+ "Read more" badge for enabled) */}
          <div className="flex flex-row items-center gap-4 w-full">
            {policyId && (
              <div
                style={{
                  fontFamily: 'Inter, sans-serif',
                  fontWeight: 500,
                  fontSize: 14,
                  lineHeight: '17px',
                  color: enabled ? '#00D3F3' : 'rgba(0, 211, 243, 0.5)',
                  flexShrink: 0,
                  transition: 'color 200ms ease',
                }}
              >
                {policyId}
              </div>
            )}
            {enabled && policyId && (
              <a
                href={`http://100.85.190.49:3004/${policyId.toLowerCase()}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex flex-row items-center rounded-[11px] bg-[var(--elevated-surface)] border border-[var(--border)] transition-colors cursor-pointer hover:opacity-80"
                style={{
                  padding: '2px 8px',
                  textDecoration: 'none',
                }}
              >
                <span
                  className="font-normal text-[11px] leading-[15px] text-[var(--muted)]"
                  style={{ fontFamily: 'Inter, sans-serif' }}
                >
                  Read more
                </span>
              </a>
            )}
          </div>

          {/* Row 2: description */}
          <div
            className="mt-0.5 text-[var(--muted)]"
            style={{
              fontFamily: 'Inter, sans-serif',
              fontWeight: 400,
              fontSize: 12,
              lineHeight: '16px',
              width: '100%',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {description || title}
          </div>
        </div>

        {/* Severity Badge / Custom Dropdown */}
        <div className="relative flex items-center ml-2 shrink-0" ref={dropdownRef}>
          <div
            className={`flex flex-row items-center px-3 py-1.5 gap-1.5 h-[30px] rounded-[5px] border whitespace-nowrap select-none ${disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'}`}
            style={{ backgroundColor: currentSeverity.bg, borderColor: currentSeverity.border }}
            onClick={() => !disabled && setDropdownOpen((o) => !o)}
            title={disabled ? 'Only GitHub administrators can modify policies' : undefined}
          >
            <div className="text-[12px] leading-4" style={{ color: currentSeverity.text }}>
              {severity}
            </div>
            <div className="w-3 h-3 flex items-center justify-center">
              <svg width="8" height="5" viewBox="0 0 8 5" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M1 1L4 4L7 1" stroke={currentSeverity.icon} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
          </div>

          {dropdownOpen && (
            <div
              className="absolute right-0 top-full mt-1 z-50 rounded-lg overflow-hidden"
              style={{
                background: 'var(--elevated-surface)',
                border: '1px solid var(--border)',
                boxShadow: '0px 8px 24px rgba(0,0,0,0.25)',
                minWidth: 110,
              }}
            >
              {SEVERITY_OPTIONS.map((opt) => {
                const s = severityStyles[opt];
                const isSelected = opt === severity;
                return (
                  <div
                    key={opt}
                    className="flex items-center gap-2 px-3 cursor-pointer transition-colors"
                    style={{
                      height: 34,
                      background: isSelected ? s?.bg : 'transparent',
                    }}
                    onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = 'var(--bg-hover)'; }}
                    onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = 'transparent'; }}
                    onClick={() => {
                      if (onSeverityChange) onSeverityChange(opt);
                      setDropdownOpen(false);
                    }}
                  >
                    <span style={{ color: s?.text || 'var(--text)', fontSize: 12, fontFamily: 'Inter, sans-serif', fontWeight: isSelected ? 600 : 400 }}>
                      {opt}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PolicyRow;

