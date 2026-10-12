// components/common/Dropdown.js
"use client"
import React, { useState, useRef, useEffect } from 'react';

export default function Dropdown({ 
  trigger, 
  children, 
  placement = 'bottom-left',
  className = '',
  ...props 
}) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  const placements = {
    'bottom-left': 'top-full left-0 mt-2',
    'bottom-right': 'top-full right-0 mt-2',
    'top-left': 'bottom-full left-0 mb-2',
    'top-right': 'bottom-full right-0 mb-2',
  };

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className={`relative inline-block ${className}`} ref={dropdownRef} {...props}>
      <div onClick={() => setIsOpen(!isOpen)}>{trigger}</div>
      {isOpen && (
        <div className={`absolute z-dropdown min-w-[200px] bg-surface border border-border rounded-lg shadow-2 ${placements[placement]} animate-fadeIn`}>
          {children}
        </div>
      )}
    </div>
  );
}

export function DropdownItem({ children, onClick, className = '', ...props }) {
  return (
    <button
      className={`w-full px-4 py-2.5 text-left hover:bg-elevated transition-fast first:rounded-t-lg last:rounded-b-lg ${className}`}
      onClick={onClick}
      {...props}
    >
      {children}
    </button>
  );
}