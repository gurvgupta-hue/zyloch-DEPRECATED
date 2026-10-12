// components/dashboard/FilterBar.jsx
import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Filter, ChevronDown, X, FileCode2, FileText, Terminal } from 'lucide-react';
import { SiDocker, SiKubernetes, SiTerraform } from 'react-icons/si';
import { getTypeTextColor } from './utils/styles';
import {
  getSeverityBadgeStyle as getSharedSeverityBadgeStyle,
  getSeverityIcon as getSharedSeverityIcon,
  SEVERITY_FIGMA_COLORS,
} from '../shared/severityVisuals';

import ScannerIconTile from '../overview/scores/ScannerIconTile';

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'];
const TYPE_OPTIONS = [
  { id: 'docker', label: 'Docker' },
  { id: 'kubernetes', label: 'Kubernetes' },
  { id: 'terraform', label: 'Terraform' },
  { id: 'bicep', label: 'Bicep' },
  { id: 'arm', label: 'ARM Template' },
  { id: 'ansible', label: 'Ansible' },
  { id: 'cloudformation', label: 'CloudFormation' },
];

const getSeverityIcon = (severity) => {
  return getSharedSeverityIcon(severity);
};

const getSeverityBadgeStyle = (severity) => {
  return getSharedSeverityBadgeStyle(severity);
};

const FilterBar = ({
  selectedSeverities,
  selectedTypes,
  toggleSeverity,
  toggleType,
  selectAllSeverities,
  clearAllSeverities,
  selectAllTypes,
  clearAllTypes,
  selectedProviders,
  providerOptions,
  toggleProvider,
  selectAllProviders,
  clearAllProviders,
  totalIssues, // Add this prop
}) => {
  const [typeDropdownOpen, setTypeDropdownOpen] = useState(false);
  const [severityDropdownOpen, setSeverityDropdownOpen] = useState(false);
  const [providerDropdownOpen, setProviderDropdownOpen] = useState(false);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        !event.target.closest('.type-dropdown') &&
        !event.target.closest('.severity-dropdown') &&
        !event.target.closest('.provider-dropdown')
      ) {
        setTypeDropdownOpen(false);
        setSeverityDropdownOpen(false);
        setProviderDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const hasPartialSeveritySelection = selectedSeverities.length > 0 && selectedSeverities.length < SEVERITY_OPTIONS.length;
  const hasAllSeveritiesSelected = selectedSeverities.length === SEVERITY_OPTIONS.length;
  const hasPartialTypeSelection = selectedTypes.length > 0 && selectedTypes.length < TYPE_OPTIONS.length;
  const hasAllTypesSelected = selectedTypes.length === TYPE_OPTIONS.length;
  const hasProviderFilter = providerOptions.some((provider) => provider !== 'none');
  const hasPartialProviderSelection =
    hasProviderFilter && selectedProviders.length > 0 && selectedProviders.length < providerOptions.length;
  const hasAllProvidersSelected =
    !hasProviderFilter || selectedProviders.length === providerOptions.length;
  const hasActiveFilters = !hasAllSeveritiesSelected || !hasAllTypesSelected || !hasAllProvidersSelected;
  const filterButtonClass =
    'inline-flex items-center gap-2 rounded-lg border border-default bg-surface px-3.5 py-1.5 text-xs font-normal text-muted hover:border-hover hover:text-text transition-colors shadow-sm';
  const activeFilterButtonClass = 'border-primary/40 bg-primary/10 text-primary font-medium';
  const inactiveFilterButtonClass = 'border-default bg-surface text-muted hover:border-hover hover:text-text';
  const dropdownClass =
    'absolute left-0 top-full mt-1.5 w-52 overflow-hidden rounded-xl border border-default bg-surface shadow-lg z-50 py-1';

  return (
    <div className="flex flex-wrap items-center gap-3">
      <span className="text-xs font-medium uppercase tracking-wider text-muted mr-1">
        FILTERS
      </span>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative severity-dropdown">
          <button
            onClick={() => {
              setSeverityDropdownOpen(!severityDropdownOpen);
              setTypeDropdownOpen(false);
              setProviderDropdownOpen(false);
            }}
            className={`${filterButtonClass} ${hasPartialSeveritySelection
              ? activeFilterButtonClass
              : inactiveFilterButtonClass
              }`}
          >
            <span>
              Severity: <strong className="font-medium text-text">{hasPartialSeveritySelection ? `(${selectedSeverities.length})` : hasAllSeveritiesSelected ? 'All' : '(0)'}</strong>
            </span>
            <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${severityDropdownOpen ? 'rotate-180' : ''}`} />
          </button>

          <AnimatePresence>
            {severityDropdownOpen && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
                className={dropdownClass}
              >
                <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                  <button
                    onClick={selectAllSeverities}
                    className="text-xs text-primary hover:underline transition-colors font-medium"
                  >
                    Select All
                  </button>
                  <button
                    onClick={clearAllSeverities}
                    className="text-xs text-muted hover:text-text transition-colors"
                  >
                    Clear
                  </button>
                </div>
                {SEVERITY_OPTIONS.map((severity) => (
                  <label key={severity} className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors">
                    <span className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: SEVERITY_FIGMA_COLORS[severity]?.dot || "#999" }} />
                      <span className="capitalize">{severity}</span>
                    </span>
                    <input
                      type="checkbox"
                      checked={selectedSeverities.includes(severity)}
                      onChange={() => toggleSeverity(severity)}
                      className="h-3.5 w-3.5 rounded border-default bg-surface text-primary focus:ring-1 focus:ring-primary/30"
                    />
                  </label>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Type Filter Dropdown */}
        <div className="relative type-dropdown">
          <button
            onClick={() => {
              setTypeDropdownOpen(!typeDropdownOpen);
              setSeverityDropdownOpen(false);
              setProviderDropdownOpen(false);
            }}
            className={`${filterButtonClass} ${hasPartialTypeSelection
              ? activeFilterButtonClass
              : inactiveFilterButtonClass
              }`}
          >
            <span>
              Type: <strong className="font-medium text-text">{hasPartialTypeSelection ? `(${selectedTypes.length})` : hasAllTypesSelected ? 'All' : '(0)'}</strong>
            </span>
            <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${typeDropdownOpen ? 'rotate-180' : ''}`} />
          </button>

          <AnimatePresence>
            {typeDropdownOpen && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
                className={dropdownClass}
              >
                <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                  <button
                    onClick={selectAllTypes}
                    className="text-xs text-primary hover:underline transition-colors font-medium"
                  >
                    Select All
                  </button>
                  <button
                    onClick={clearAllTypes}
                    className="text-xs text-muted hover:text-text transition-colors"
                  >
                    Clear
                  </button>
                </div>
                {TYPE_OPTIONS.map((type) => (
                  <label key={type.id} className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors">
                    <span className="flex items-center gap-2 truncate">
                      <ScannerIconTile scannerKey={type.id} size={13} tileSize={22} />
                      <span>{type.label}</span>
                    </span>
                    <input
                      type="checkbox"
                      checked={selectedTypes.includes(type.id)}
                      onChange={() => toggleType(type.id)}
                      className="h-3.5 w-3.5 rounded border-default bg-surface text-primary focus:ring-1 focus:ring-primary/30 shrink-0 ml-2"
                    />
                  </label>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {hasProviderFilter && (
          <div className="relative provider-dropdown">
            <button
              onClick={() => {
                setProviderDropdownOpen(!providerDropdownOpen);
                setSeverityDropdownOpen(false);
                setTypeDropdownOpen(false);
              }}
              className={`${filterButtonClass} ${hasPartialProviderSelection
                ? activeFilterButtonClass
                : inactiveFilterButtonClass
                }`}
            >
              <span>
                Provider: <strong className="font-medium text-text">{hasPartialProviderSelection ? `(${selectedProviders.length})` : hasAllProvidersSelected ? 'All' : '(0)'}</strong>
              </span>
              <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${providerDropdownOpen ? 'rotate-180' : ''}`} />
            </button>

            <AnimatePresence>
              {providerDropdownOpen && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.2 }}
                  className={dropdownClass}
                >
                  <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                    <button
                      onClick={selectAllProviders}
                      className="text-xs text-primary hover:underline transition-colors font-medium"
                    >
                      Select All
                    </button>
                    <button
                      onClick={clearAllProviders}
                      className="text-xs text-muted hover:text-text transition-colors"
                    >
                      Clear
                    </button>
                  </div>
                  {providerOptions.map((provider) => (
                    <label key={provider} className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors">
                      <span className="truncate capitalize text-text">
                        {provider === 'none' ? 'No provider' : provider}
                      </span>
                      <input
                        type="checkbox"
                        checked={selectedProviders.includes(provider)}
                        onChange={() => toggleProvider(provider)}
                        className="h-3.5 w-3.5 rounded border-default bg-surface text-primary focus:ring-1 focus:ring-primary/30 shrink-0 ml-2"
                      />
                    </label>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}

        {hasActiveFilters && (
          <button
            type="button"
            onClick={() => {
              selectAllSeverities();
              selectAllTypes();
              selectAllProviders();
            }}
            className="inline-flex items-center gap-1 rounded-lg border border-default px-2.5 py-1.5 text-xs text-muted hover:bg-elevated hover:text-text transition-colors"
          >
            <X className="h-3.5 w-3.5" />
            <span>Clear</span>
          </button>
        )}
      </div>
    </div>
  );
};

export default FilterBar;