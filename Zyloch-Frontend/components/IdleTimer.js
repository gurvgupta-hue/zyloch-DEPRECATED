"use client";
import { useEffect, useState, useRef } from "react";
import { IDLE_TIMEOUT } from "@/hooks/useAutoLogout";

// Heroicons outline clock (SVG)
function ClockIcon({ className = "w-5 h-5" }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.5" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 7.5v4.25l2.25 2.25" />
    </svg>
  );
}

export default function IdleTimer({ storageKey = "zyloch-last-activity" }) {
  const [remaining, setRemaining] = useState(IDLE_TIMEOUT);
  const [isVisible, setIsVisible] = useState(true);
  const [position, setPosition] = useState({ x: null, y: null });
  const [isDragging, setIsDragging] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  const dragRef = useRef(null);
  const dragStart = useRef({ x: 0, y: 0 });

  useEffect(() => {
    let interval = null;
    function update() {
      const last = localStorage.getItem(storageKey);
      if (last) {
        const elapsed = Date.now() - parseInt(last, 10);
        setRemaining(Math.max(IDLE_TIMEOUT - elapsed, 0));
      } else {
        setRemaining(IDLE_TIMEOUT);
      }
    }
    update();
    interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [storageKey]);

  // Set initial position to right side center
  useEffect(() => {
    if (typeof window !== 'undefined' && position.x === null && position.y === null) {
      const windowHeight = window.innerHeight;
      const timerHeight = 60; // Approximate height of the compact timer
      setPosition({
        x: 20,
        y: (windowHeight / 2) - (timerHeight / 2)
      });
    }
  }, [position.x, position.y]);

  // Drag functionality - vertical only
  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!isDragging || !dragRef.current) return;
      
      const rect = dragRef.current.getBoundingClientRect();
      let newY = e.clientY - dragStart.current.y;
      
      // Keep within viewport boundaries
      newY = Math.max(10, Math.min(window.innerHeight - rect.height - 10, newY));
      
      setPosition({
        x: position.x,
        y: newY
      });
    };
    
    const handleMouseUp = () => {
      setIsDragging(false);
    };
    
    if (isDragging) {
      window.addEventListener("mousemove", handleMouseMove);
      window.addEventListener("mouseup", handleMouseUp);
    }
    
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isDragging, position.x]);

  const handleMouseDown = (e) => {
    e.preventDefault();
    const rect = dragRef.current.getBoundingClientRect();
    dragStart.current = {
      y: e.clientY - rect.top
    };
    setIsDragging(true);
  };

  const formatTime = () => {
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  };

  const isWarning = remaining < 2 * 60 * 1000;
  const isCritical = remaining < 60 * 1000;

  if (!isVisible) return null;

  // Color logic using root variables
  let borderColor = 'var(--border)';
  let bgColor = 'var(--surface)';
  let textColor = 'var(--text)';
  let iconColor = 'var(--muted)';
  let timeColor = 'var(--text)';
  let pulse = false;
  if (isCritical) {
    borderColor = 'var(--critical)';
    bgColor = 'var(--badge-red-bg)';
    textColor = 'var(--critical)';
    iconColor = 'var(--critical)';
    timeColor = 'var(--critical)';
    pulse = true;
  } else if (isWarning) {
    borderColor = 'var(--warning)';
    bgColor = 'var(--badge-yellow-bg)';
    textColor = 'var(--warning)';
    iconColor = 'var(--warning)';
    timeColor = 'var(--warning)';
  }

  const style = {
    position: 'fixed',
    right: position.x !== null ? `${position.x}px` : '20px',
    top: position.y !== null ? `${position.y}px` : '50%',
    transform: position.y === null ? 'translateY(-50%)' : 'none',
    zIndex: 9999,
    cursor: isDragging ? 'grabbing' : 'grab',
    width: '4rem',
    borderRadius: 'var(--radius-md)',
    boxShadow: isHovered ? 'var(--shadow-2)' : 'var(--shadow-1)',
    border: `1.5px solid ${borderColor}`,
    background: bgColor,
    backdropFilter: 'var(--backdrop-blur)',
    transition: 'all 0.2s',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    padding: '0.5rem 0.75rem',
    gap: '0.375rem',
    position: 'fixed',
  };

  return (
    <div
      ref={dragRef}
      style={style}
      onMouseDown={handleMouseDown}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <ClockIcon className="w-4 h-4" />
      <span
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '0.75rem',
          fontWeight: 700,
          color: timeColor,
          letterSpacing: '0.01em',
          ...(pulse ? { animation: 'lp-blink 1s infinite' } : {}),
        }}
      >
        {formatTime()}
      </span>
      {/* Close button - appears on hover */}
      {isHovered && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            setIsVisible(false);
          }}
          style={{
            position: 'absolute',
            top: '-0.25rem',
            right: '-0.25rem',
            width: '1rem',
            height: '1rem',
            borderRadius: '50%',
            background: 'var(--border)',
            color: 'var(--text)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: 'none',
            transition: 'background 0.2s',
          }}
          aria-label="Hide timer"
        >
          <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
      {/* Drag indicator dots - visible on hover */}
      {isHovered && (
        <div style={{
          position: 'absolute',
          left: '-0.25rem',
          top: '50%',
          transform: 'translateY(-50%)',
          display: 'flex',
          flexDirection: 'column',
          gap: '2px',
        }}>
          <div style={{ width: '0.25rem', height: '0.25rem', borderRadius: '50%', background: 'var(--muted)' }} />
          <div style={{ width: '0.25rem', height: '0.25rem', borderRadius: '50%', background: 'var(--muted)' }} />
          <div style={{ width: '0.25rem', height: '0.25rem', borderRadius: '50%', background: 'var(--muted)' }} />
        </div>
      )}
    </div>
  );
}