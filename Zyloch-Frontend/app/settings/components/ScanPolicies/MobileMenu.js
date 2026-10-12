// ScanPolicies/MobileMenu.jsx
import React from 'react';
import { ChevronRight } from 'lucide-react';

export const MobileMenu = ({ isOpen, onClose, scanCategories, onSelectCategory }) => {
  if (!isOpen) return null;

  return (
    <div className="sm:hidden bg-[var(--elevated-surface)]">
      <div className="p-4 border-b border-[var(--border)]">
        <h3 className="text-sm font-semibold text-[var(--muted)] mb-3 px-2 uppercase tracking-wider">
          Scan Options
        </h3>

        <div className="space-y-2">
          {scanCategories.map((category) => (
            <button
              key={category.id}
              onClick={() => onSelectCategory(category.id)}
              className="flex items-center justify-between w-full p-3 rounded-xl transition-all duration-200 hover:bg-[var(--surface)] text-[var(--text)] border border-transparent"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[var(--elevated-surface)]">
                  {category.icon}
                </div>
                <div className="text-left">
                  <div className="font-medium text-sm">{category.name}</div>
                  <div className="text-xs text-[var(--muted)]">{category.description}</div>
                </div>
              </div>
              <ChevronRight size={16} />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};