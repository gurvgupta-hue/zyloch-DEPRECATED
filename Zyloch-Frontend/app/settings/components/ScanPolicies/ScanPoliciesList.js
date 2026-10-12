"use client";

import React, { useMemo, useState, useRef, useEffect } from 'react';
import { toast } from 'react-toastify';
import PolicyRow from '../../../../components/policy/PolicyRow';

const PolicyToast = ({ isEnable, title, description, onUndo, closeToast }) => {
  const color = isEnable ? 'var(--color-primary)' : 'var(--danger)';
  const bgColor = isEnable ? 'rgba(var(--color-primary-rgb),0.15)' : 'rgba(var(--danger-rgb),0.15)';
  const iconBorderColor = isEnable ? 'rgba(var(--color-primary-rgb),0.3)' : 'rgba(var(--danger-rgb),0.3)';

  return (
    <div
      className="box-border flex flex-row items-center px-4 py-3 gap-3 w-[322px] h-[63px] bg-[var(--elevated-surface)] rounded-lg shadow-lg"
      style={{
        border: '0.5px solid var(--border)',
      }}
    >
      <div
        style={{
          boxSizing: 'border-box',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          width: 28,
          height: 28,
          background: bgColor,
          border: `0.5px solid ${iconBorderColor}`,
          borderRadius: 28,
          flex: 'none'
        }}
      >
        {isEnable ? (
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M3.5 7.5L6 10L11 5" stroke={color} strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        ) : (
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <circle cx="7" cy="7" r="5" stroke={color} strokeWidth="1.2" />
            <path d="M4.5 4.5L9.5 9.5" stroke={color} strokeWidth="1.2" strokeLinecap="round" />
          </svg>
        )}
      </div>

      <div className="flex flex-col items-start flex-1 overflow-hidden">
        <div className="font-sans font-medium text-[13px] leading-5 text-[var(--text)] w-full overflow-hidden text-ellipsis whitespace-nowrap">
          {title}
        </div>
        <div className="font-sans font-normal text-[11px] leading-4 text-[var(--muted)] mt-[1px] w-full overflow-hidden text-ellipsis whitespace-nowrap">
          {description}
        </div>
      </div>

      <div
        onClick={onUndo}
        style={{ fontFamily: 'Inter, sans-serif', fontWeight: 500, fontSize: 13, lineHeight: '20px', color, cursor: 'pointer', flex: 'none' }}
      >
        Undo
      </div>

      <div
        onClick={closeToast}
        style={{ display: 'flex', paddingLeft: 8, cursor: 'pointer', flex: 'none', alignItems: 'center', justifyContent: 'center' }}
      >
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <path d="M3.5 3.5L10.5 10.5M3.5 10.5L10.5 3.5" stroke="var(--muted)" strokeWidth="1.2" strokeLinecap="round" />
        </svg>
      </div>
    </div>
  );
};

const ConfirmationModal = ({ isOpen, onClose, onConfirm, isEnable, title, description, confirmText }) => {
  if (!isOpen) return null;

  const btnBg = isEnable ? '!bg-[var(--color-primary)] hover:!bg-[var(--color-primary-600)]' : '!bg-[var(--danger)] hover:!bg-[var(--critical)]';

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div
        className="box-border flex flex-col items-start p-6 relative w-[400px] bg-[var(--elevated-surface)] border border-[var(--border)] rounded-[14px] shadow-[0px_20px_60px_rgba(0,0,0,0.15)] dark:shadow-[0px_20px_60px_rgba(0,0,0,0.6)]"
      >
        <div className="flex flex-row justify-between items-start w-full h-[20px]">
          <h3 className="font-sans font-semibold text-[15px] leading-5 text-[var(--text)] m-0 p-0">
            {title}
          </h3>
          <button onClick={onClose} className="p-0 m-0 w-4 h-4 flex items-center justify-center cursor-pointer opacity-70 hover:opacity-100 transition-opacity bg-transparent border-none">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M4 4L12 12M4 12L12 4" stroke="currentColor" strokeWidth="1.33" strokeLinecap="round" className="text-[var(--muted)]" />
            </svg>
          </button>
        </div>

        <div className="flex flex-col items-start pt-3 w-full">
          <p className="font-sans font-normal text-[13px] leading-[21px] text-[var(--muted)] m-0 p-0">
            {description}
          </p>
        </div>

        <div className="flex flex-row justify-end items-start pt-6 gap-2 w-full">
          <button
            onClick={onClose}
            className="box-border px-4 h-[34.5px] border border-[var(--border)] rounded-lg font-sans font-medium text-[13px] leading-5 text-[var(--muted)] hover:!bg-[var(--bg-hover)] transition-colors cursor-pointer !bg-transparent"
          >
            Cancel
          </button>
          <button
            onClick={() => { onConfirm(); onClose(); }}
            className={`px-4 h-[34.5px] rounded-lg font-sans font-medium text-[13px] leading-5 text-white transition-colors cursor-pointer border-none ${btnBg}`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
};

/* ─────────────────────────────────────────────
   Reusable bulk-toggle dropdown
   Matches the Figma spec exactly
───────────────────────────────────────────── */
const BulkToggleDropdown = ({ type, totalCount, counts, onSelect, disabled = false }) => {
  const [isOpen, setIsOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setIsOpen(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const isEnable = type === 'enable';
  const color = isEnable ? 'var(--color-primary)' : 'var(--danger)';
  const bgColor = isEnable ? 'rgba(var(--color-primary-rgb),0.1)' : 'rgba(var(--danger-rgb),0.1)';
  const label = isEnable ? 'Enable all' : 'Disable all';

  return (
    <div className="relative shrink-0" ref={ref}>
      {/* ── Trigger button ── */}
      <div
        onClick={() => !disabled && setIsOpen(!isOpen)}
        title={disabled ? 'Only GitHub administrators can modify policies' : undefined}
        className={`box-border flex flex-row items-center h-9 rounded-lg overflow-hidden transition-colors ${disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'}`}
        style={{ backgroundColor: bgColor }}
      >
        {/* Icon + label */}
        <div className="flex items-center px-3 gap-2 h-full text-sm font-medium" style={{ color }}>
          {isEnable ? (
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
              <path d="M2.5 6L5 8.5L9.5 4" stroke="currentColor" strokeWidth="1.08333" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          ) : (
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
              <circle cx="6" cy="6" r="4.5" stroke="currentColor" strokeWidth="1.08333" />
              <path d="M3 3L9 9" stroke="currentColor" strokeWidth="1.08333" strokeLinecap="round" />
            </svg>
          )}
          <span className="hidden sm:inline">{label}</span>
        </div>
        {/* Count badge */}
        <div
          className="flex justify-center items-center px-3 h-full text-sm font-medium border-l"
          style={{ color, borderColor: `${color}30` }}
        >
          {totalCount}
        </div>
        {/* Chevron */}
        <div className="flex justify-center items-center px-2 h-full" style={{ color }}>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" strokeWidth="1.08333" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
      </div>

      {/* ── Dropdown menu (240×299 per spec) ── */}
      {isOpen && (
        <div
          className="absolute right-0 top-full mt-2 z-50 flex flex-col bg-[var(--elevated-surface)] border border-[var(--border)] rounded-lg py-1 shadow-[0px_12px_40px_rgba(0,0,0,0.15)] dark:shadow-[0px_12px_40px_rgba(0,0,0,0.5)]"
          style={{ width: 240 }}
        >
          {/* Section header: "ALL SEVERITIES" */}
          <div className="px-3.5 pt-2 pb-1">
            <span className="font-sans font-medium text-[10px] tracking-[0.7px] uppercase text-[var(--muted)]">
              {isEnable ? 'Enable by severity' : 'Disable by severity'}
            </span>
          </div>

          {/* All Severities row */}
          <DropdownRow
            icon={<LayersIcon color="var(--muted)" />}
            label="All Severities"
            count={totalCount}
            countBg="var(--elevated-surface)"
            countColor="var(--muted)"
            onClick={() => { onSelect('ALL'); setIsOpen(false); }}
          />

          {/* Divider */}
          <div className="h-px bg-[var(--border)] my-1 opacity-50" />

          {/* Section header: "BY SEVERITY" */}
          <div className="px-3.5 pt-3 pb-1">
            <span className="font-sans font-medium text-[10px] tracking-[0.7px] uppercase text-[var(--muted)]">
              By severity
            </span>
          </div>

          {/* Critical */}
          <DropdownRow
            icon={<TriangleIcon color="var(--muted)" />}
            label="Critical"
            count={counts.CRITICAL || 0}
            countBg="rgba(var(--danger-rgb),0.15)"
            countColor="var(--danger)"
            onClick={() => { onSelect('CRITICAL'); setIsOpen(false); }}
          />
          {/* High */}
          <DropdownRow
            icon={<CircleInfoIcon color="var(--muted)" />}
            label="High"
            count={counts.HIGH || 0}
            countBg="rgba(var(--warning-rgb),0.15)"
            countColor="var(--warning)"
            onClick={() => { onSelect('HIGH'); setIsOpen(false); }}
          />
          {/* Medium */}
          <DropdownRow
            icon={<CircleInfoIcon color="var(--muted)" />}
            label="Medium"
            count={counts.MEDIUM || 0}
            countBg="rgba(var(--color-primary-rgb),0.15)"
            countColor="var(--color-primary)"
            onClick={() => { onSelect('MEDIUM'); setIsOpen(false); }}
          />

          {/* Divider */}
          <div className="h-px bg-[var(--border)] my-1 opacity-50" />

          {/* Low */}
          <DropdownRow
            icon={<LayersIcon color="var(--muted)" />}
            label="Low"
            count={counts.LOW || 0}
            countBg="var(--elevated-surface)"
            countColor="var(--muted)"
            onClick={() => { onSelect('LOW'); setIsOpen(false); }}
            extraStyle={{ padding: '12px 14px 8px' }}
          />
        </div>
      )}
    </div>
  );
};

/* ─── Helper row ─── */
const DropdownRow = ({ icon, label, count, countBg, countColor, onClick, extraStyle = {} }) => (
  <div
    onClick={onClick}
    className="cursor-pointer transition-colors flex flex-row items-center gap-2.5 px-3.5 hover:bg-[var(--bg-hover)]"
    style={{
      width: 239,
      height: 36.5,
      ...extraStyle,
    }}
  >
    <div className="w-3.5 h-3.5 flex items-center justify-center">
      {icon}
    </div>
    <div className="flex-1 font-sans font-medium text-[13px] leading-5 text-[var(--text)]">
      {label}
    </div>
    <div style={{
      display: 'flex', justifyContent: 'center', alignItems: 'center',
      height: 20.5, borderRadius: 10, padding: '0 8px', minWidth: 27,
      background: countBg,
    }}>
      <span style={{ fontFamily: 'Inter, sans-serif', fontWeight: 500, fontSize: 11, lineHeight: '16px', textAlign: 'center', color: countColor }}>
        {count}
      </span>
    </div>
  </div>
);

/* ─── SVG Icons ─── */
const TriangleIcon = ({ color }) => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);
const CircleInfoIcon = ({ color }) => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" />
  </svg>
);
const LayersIcon = ({ color }) => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="12 2 2 7 12 12 22 7 12 2" />
    <polyline points="2 17 12 22 22 17" /><polyline points="2 12 12 17 22 12" />
  </svg>
);

/* ═══════════════════════════════════════════════
   Cloud-provider tabs shown for Terraform and Cloud views
═══════════════════════════════════════════════ */
const PROVIDER_TABS = [
  { id: 'all', label: 'All' },
  { id: 'aws', label: 'AWS' },
  { id: 'azure', label: 'AZURE' },
  { id: 'gcp', label: 'GCP' },
];

// Sub-categories that trigger the cloud provider tabs
const SHOW_TABS_CATEGORIES = new Set(['terraform', 'cloud', 'aws', 'azure', 'gcp', 'cloud-aws', 'cloud-azure', 'cloudformation', 'bicep']);

/* ═══════════════════════════════════════════════
   Main component
═══════════════════════════════════════════════ */
const ScanPoliciesList = ({
  selectedCategory,
  selectedSubCategory,
  scanCategories,
  policies,
  onPolicyToggle,
  onSeverityChange,
  getSeverityColor,
  getSeverityIcon,
  activeTab,
  onTabChange,
  onBulkToggle,
  onMobileMenuOpen,
  onCategoryChange,
  unsavedChangesCount = 0,
  onSavePreferences,
  onDiscardChanges,
  canEdit = true
}) => {
  const undoGenerationRef = useRef(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [enabledFilter, setEnabledFilter] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const [cloudTab, setCloudTab] = useState('all');
  const [bulkConfirmModal, setBulkConfirmModal] = useState({ isOpen: false, isEnable: true, severity: 'ALL', subCategory: null });
  const ITEMS_PER_PAGE = 15;

  // Show cloud-provider tabs when the current view is a Terraform or Cloud category
  const showCloudTabs = SHOW_TABS_CATEGORIES.has(selectedSubCategory);

  // When the selected sub-category changes, reset the cloud tab if we leave
  useEffect(() => {
    if (!SHOW_TABS_CATEGORIES.has(selectedSubCategory)) {
      setCloudTab('all');
    }
  }, [selectedSubCategory]);

  // Reset page on filter/category change
  useEffect(() => { setCurrentPage(1); }, [selectedSubCategory, searchTerm, severityFilter, enabledFilter, cloudTab]);

  const isGlobalSearch = selectedSubCategory === 'search';

  const selectedCategoryData = useMemo(() => {
    if (isGlobalSearch) {
      return { id: 'search', name: 'Global Search', subCategories: [{ id: 'search', name: 'All Policies' }] };
    }
    return scanCategories?.find(cat => cat.id === selectedCategory);
  }, [scanCategories, selectedCategory, isGlobalSearch]);

  const selectedPolicies = useMemo(() => {
    if (isGlobalSearch) {
      const allPolicies = [];
      Object.entries(policies).forEach(([subCat, catPolicies]) => {
        allPolicies.push(...catPolicies.map(p => ({ ...p, __sourceSubCategory: subCat })));
      });
      // Deduplicate by policy id (since some terraform policies might appear in multiple cloud categories, though they should have unique IDs per useScanPolicies, let's just make sure)
      const uniquePolicies = [];
      const seenIds = new Set();
      for (const p of allPolicies) {
        if (!seenIds.has(p.id)) {
          seenIds.add(p.id);
          uniquePolicies.push(p);
        }
      }
      return uniquePolicies;
    }

    // Helper to find a node by ID recursively
    const findNode = (nodes, id) => {
      if (!nodes) return null;
      for (const node of nodes) {
        if (node.id === id) return node;
        const child = findNode(node.subCategories, id);
        if (child) return child;
      }
      return null;
    };

    // If selectedCategoryData exists, find the current subCategory node
    let targetNode = null;
    if (selectedCategoryData && selectedCategoryData.id === selectedSubCategory) {
      targetNode = selectedCategoryData;
    } else if (selectedCategoryData && selectedCategoryData.subCategories) {
      targetNode = findNode(selectedCategoryData.subCategories, selectedSubCategory);
    }

    if (targetNode && targetNode.subCategories && targetNode.subCategories.length > 0) {
      // It's a parent node, aggregate leaf policies
      const getLeafPolicyIds = (node) => {
        let leafIds = [];
        if (node.subCategories && node.subCategories.length > 0) {
          for (const child of node.subCategories) {
            leafIds.push(...getLeafPolicyIds(child));
          }
        } else {
          leafIds.push(node.id);
        }
        return leafIds;
      };
      const leafIds = getLeafPolicyIds(targetNode);
      const aggPolicies = [];
      for (const leafId of leafIds) {
        if (policies[leafId]) {
          aggPolicies.push(...policies[leafId].map(p => ({ ...p, __sourceSubCategory: leafId })));
        }
      }
      // Deduplicate in case multiple leaf nodes share the same policies
      const uniqueAggPolicies = [];
      const seenAggIds = new Set();
      for (const p of aggPolicies) {
        if (!seenAggIds.has(p.id)) {
          seenAggIds.add(p.id);
          uniqueAggPolicies.push(p);
        }
      }
      return uniqueAggPolicies;
    }

    return (policies[selectedSubCategory] || []).map(p => ({ ...p, __sourceSubCategory: selectedSubCategory }));
  }, [policies, selectedSubCategory, isGlobalSearch, selectedCategoryData]);

  // For cloud-tab filtering
  const cloudFilteredBase = useMemo(() => {
    if (isGlobalSearch) return selectedPolicies;
    if (!showCloudTabs) return selectedPolicies;

    if (cloudTab === 'all') {
      return selectedPolicies;
    }

    // For Terraform: map tabs to provider policies directly
    if (selectedSubCategory === 'terraform' || selectedSubCategory === 'aws' || selectedSubCategory === 'azure' || selectedSubCategory === 'gcp') {
      return policies[cloudTab] || [];
    }

    // For Cloud: map tabs to appropriate cloud policies
    if (selectedSubCategory === 'cloud' || selectedSubCategory === 'cloud-aws' || selectedSubCategory === 'cloud-azure' || selectedSubCategory === 'cloudformation' || selectedSubCategory === 'bicep') {
      if (cloudTab === 'aws') return policies['cloudformation'] || [];
      if (cloudTab === 'azure') return policies['bicep'] || [];
      if (cloudTab === 'gcp') return [];
    }

    return selectedPolicies;
  }, [showCloudTabs, cloudTab, selectedPolicies, policies, selectedSubCategory, isGlobalSearch]);

  const filteredPolicies = useMemo(() => {
    let list = cloudFilteredBase;
    if (searchTerm) {
      const term = searchTerm.toLowerCase().trim();
      list = list.filter(p =>
        p.name?.toLowerCase().includes(term) ||
        p.description?.toLowerCase().includes(term) ||
        p.id?.toLowerCase().includes(term)
      );
    }
    if (severityFilter !== 'ALL')
      list = list.filter(p => (p.severity || '').toUpperCase() === severityFilter);
    if (enabledFilter === 'ENABLED') list = list.filter(p => p.enabled);
    if (enabledFilter === 'DISABLED') list = list.filter(p => !p.enabled);
    return list;
  }, [cloudFilteredBase, searchTerm, severityFilter, enabledFilter]);

  const getSubCategoryPath = (nodes, targetId, currentPath = []) => {
    if (!nodes) return null;
    for (const node of nodes) {
      const newPath = [...currentPath, node];
      if (node.id === targetId) return newPath;
      if (node.subCategories) {
        const found = getSubCategoryPath(node.subCategories, targetId, newPath);
        if (found) return found;
      }
    }
    return null;
  };

  const subCategoryPath = useMemo(() => {
    if (!selectedCategoryData || !selectedCategoryData.subCategories) return [];
    return getSubCategoryPath(selectedCategoryData.subCategories, selectedSubCategory) || [];
  }, [selectedCategoryData, selectedSubCategory]);

  const currentSubCategoryName = subCategoryPath.length > 0
    ? subCategoryPath[subCategoryPath.length - 1].name
    : 'Policies';

  const resolveSubCategoryForPolicy = (policyId, fallbackSubCategory, sourceSubCategory) => {
    if (sourceSubCategory) return sourceSubCategory;

    // Provider tabs under parent categories need explicit routing to leaf subcategories.
    if ((selectedSubCategory === 'terraform' || selectedSubCategory === 'aws' || selectedSubCategory === 'azure' || selectedSubCategory === 'gcp') && cloudTab !== 'all') {
      return cloudTab;
    }

    if ((selectedSubCategory === 'cloud' || selectedSubCategory === 'cloud-aws' || selectedSubCategory === 'cloud-azure' || selectedSubCategory === 'cloudformation' || selectedSubCategory === 'bicep') && cloudTab !== 'all') {
      if (cloudTab === 'aws') return 'cloudformation';
      if (cloudTab === 'azure') return 'bicep';
    }

    if (isGlobalSearch || selectedSubCategory === 'terraform' || selectedSubCategory === 'cloud' || selectedSubCategory === 'cloud-aws' || selectedSubCategory === 'cloud-azure') {
      for (const [subCat, list] of Object.entries(policies)) {
        if (list.some(p => p.id === policyId)) {
          return subCat;
        }
      }
    }

    return fallbackSubCategory;
  };

  const resolveBulkSubCategories = (fallbackSubCategory) => {
    if (selectedSubCategory === 'terraform') {
      if (cloudTab === 'aws') return ['aws'];
      if (cloudTab === 'azure') return ['azure'];
      if (cloudTab === 'gcp') return ['gcp'];
      return ['aws', 'azure', 'gcp'];
    }

    if (selectedSubCategory === 'cloud') {
      if (cloudTab === 'aws') return ['cloudformation'];
      if (cloudTab === 'azure') return ['bicep'];
      if (cloudTab === 'gcp') return [];
      return ['cloudformation', 'bicep'];
    }

    if (selectedSubCategory === 'cloud-aws') return ['cloudformation'];
    if (selectedSubCategory === 'cloud-azure') return ['bicep'];

    if ((selectedSubCategory === 'aws' || selectedSubCategory === 'azure' || selectedSubCategory === 'gcp') && cloudTab !== 'all') {
      return [cloudTab];
    }

    if ((selectedSubCategory === 'cloudformation' || selectedSubCategory === 'bicep') && cloudTab !== 'all') {
      if (cloudTab === 'aws') return ['cloudformation'];
      if (cloudTab === 'azure') return ['bicep'];
    }

    return [fallbackSubCategory];
  };

  const handleToggleWrapper = (policy, currentViewSubCategory) => {
    if (!canEdit) return;
    if (policy) {
      const actualSubCategory = resolveSubCategoryForPolicy(policy.id, currentViewSubCategory, policy.__sourceSubCategory);
      const generationAtCreation = undoGenerationRef.current;

      onPolicyToggle(policy.id, actualSubCategory);
      const isEnable = !policy.enabled;
      toast(
        ({ closeToast }) => (
          <PolicyToast
            isEnable={isEnable}
            title={currentSubCategoryName}
            description={`${isEnable ? 'Enabled' : 'Disabled'} policy: ${policy.name}`}
            onUndo={() => {
              if (generationAtCreation !== undoGenerationRef.current) {
                closeToast();
                return;
              }
              onPolicyToggle(policy.id, actualSubCategory);
              closeToast();
            }}
            closeToast={closeToast}
          />
        ),
        {
          position: "bottom-right",
          autoClose: 3000,
          hideProgressBar: true,
          closeButton: false,
          className: '!p-0 !bg-transparent !shadow-none !w-auto',
          style: { width: 'auto', padding: 0, background: 'transparent', boxShadow: 'none' }
        }
      );
    }
  };

  const handleBulkToggleWrapper = (subCategory, isEnable, severity) => {
    if (!canEdit) return;
    const subCategories = Array.isArray(subCategory) ? subCategory : [subCategory];
    const generationAtCreation = undoGenerationRef.current;
    subCategories.forEach((subCat) => {
      if (subCat) onBulkToggle(subCat, isEnable, severity);
    });
    toast(
      ({ closeToast }) => (
        <PolicyToast
          isEnable={isEnable}
          title={currentSubCategoryName}
          description={`${isEnable ? 'Enabled' : 'Disabled'} ${severity === 'ALL' ? 'all' : severity.toLowerCase()} policies`}
          onUndo={() => {
            if (generationAtCreation !== undoGenerationRef.current) {
              closeToast();
              return;
            }
            onBulkToggle(subCategory, !isEnable, severity);
            closeToast();
          }}
          closeToast={closeToast}
        />
      ),
      {
        position: "bottom-right",
        autoClose: 3000,
        hideProgressBar: true,
        closeButton: false,
        className: '!p-0 !bg-transparent !shadow-none !w-auto',
        style: { width: 'auto', padding: 0, background: 'transparent', boxShadow: 'none' }
      }
    );
  };

  const totalPages = Math.max(1, Math.ceil(filteredPolicies.length / ITEMS_PER_PAGE));
  const pagedPolicies = filteredPolicies.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE);

  // For bulk-action counts
  const bulkBase = useMemo(() => {
    if (!showCloudTabs) return selectedPolicies;

    if (cloudTab === 'all') {
      return selectedPolicies;
    }

    if (selectedSubCategory === 'terraform' || selectedSubCategory === 'aws' || selectedSubCategory === 'azure' || selectedSubCategory === 'gcp') {
      return policies[cloudTab] || [];
    }

    if (selectedSubCategory === 'cloud' || selectedSubCategory === 'cloud-aws' || selectedSubCategory === 'cloud-azure' || selectedSubCategory === 'cloudformation' || selectedSubCategory === 'bicep') {
      if (cloudTab === 'aws') return policies['cloudformation'] || [];
      if (cloudTab === 'azure') return policies['bicep'] || [];
      if (cloudTab === 'gcp') return [];
    }

    return policies[cloudTab] || [];
  }, [showCloudTabs, cloudTab, selectedPolicies, policies, selectedSubCategory]);

  // Returns total policy count for each cloud-provider tab badge
  const getBadgeCount = (tabId) => {
    if (selectedSubCategory === 'terraform' || selectedSubCategory === 'aws' || selectedSubCategory === 'azure' || selectedSubCategory === 'gcp') {
      if (tabId === 'all') return (policies['aws'] || []).length + (policies['azure'] || []).length + (policies['gcp'] || []).length;
      return (policies[tabId] || []).length;
    }
    if (selectedSubCategory === 'cloud' || selectedSubCategory === 'cloud-aws' || selectedSubCategory === 'cloud-azure' || selectedSubCategory === 'cloudformation' || selectedSubCategory === 'bicep') {
      if (tabId === 'all') return (policies['cloudformation'] || []).length + (policies['bicep'] || []).length;
      if (tabId === 'aws') return (policies['cloudformation'] || []).length;
      if (tabId === 'azure') return (policies['bicep'] || []).length;
      if (tabId === 'gcp') return 0;
    }
    return 0;
  };

  const enabledCount = bulkBase.filter(p => p.enabled).length;
  const disabledCount = bulkBase.filter(p => !p.enabled).length;

  // Counts per severity for dropdown badges
  const severityCountsAll = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    bulkBase.forEach(p => { const k = (p.severity || '').toUpperCase(); if (c[k] !== undefined) c[k]++; });
    return c;
  }, [bulkBase]);

  const enableCounts = useMemo(() => {
    // counts of disabled policies by severity (candidates for enabling)
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    bulkBase.filter(p => !p.enabled).forEach(p => { const k = (p.severity || '').toUpperCase(); if (c[k] !== undefined) c[k]++; });
    return c;
  }, [bulkBase]);

  const disableCounts = useMemo(() => {
    // counts of enabled policies by severity (candidates for disabling)
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    bulkBase.filter(p => p.enabled).forEach(p => { const k = (p.severity || '').toUpperCase(); if (c[k] !== undefined) c[k]++; });
    return c;
  }, [bulkBase]);

  // Modal derived state
  const modalPolicyCount = bulkConfirmModal.isEnable
    ? (bulkConfirmModal.severity === 'ALL' ? disabledCount : enableCounts[bulkConfirmModal.severity] || 0)
    : (bulkConfirmModal.severity === 'ALL' ? enabledCount : disableCounts[bulkConfirmModal.severity] || 0);

  const modalTitle = bulkConfirmModal.isEnable
    ? (bulkConfirmModal.severity === 'ALL' ? 'Enable all policies' : `Enable ${bulkConfirmModal.severity.toLowerCase()} policies`)
    : (bulkConfirmModal.severity === 'ALL' ? 'Disable all policies' : `Disable ${bulkConfirmModal.severity.toLowerCase()} policies`);

  const modalDescription = `This will ${bulkConfirmModal.isEnable ? 'enable' : 'disable'} ${modalPolicyCount} ${bulkConfirmModal.severity !== 'ALL' ? bulkConfirmModal.severity.toLowerCase() + ' ' : ''}policies in ${currentSubCategoryName}.`;

  const modalConfirmText = bulkConfirmModal.isEnable
    ? (bulkConfirmModal.severity === 'ALL' ? 'Enable all' : 'Enable')
    : (bulkConfirmModal.severity === 'ALL' ? 'Disable all' : 'Disable');

  const handleDiscardWrapper = () => {
    undoGenerationRef.current += 1;
    toast.dismiss();
    onDiscardChanges && onDiscardChanges();
  };

  const handleSaveWrapper = () => {
    undoGenerationRef.current += 1;
    toast.dismiss();
    onSavePreferences && onSavePreferences();
  };

  if (!selectedSubCategory) {
    return (
      <div className="flex flex-col items-center justify-center w-full h-full bg-[var(--surface)] text-center p-8">
        <div style={{
          fontFamily: 'Inter, sans-serif',
          fontWeight: 600,
          fontSize: 14,
          lineHeight: '18px',
          letterSpacing: '0.05em',
          textTransform: 'uppercase',
          color: 'var(--color-primary)',
          marginBottom: 16
        }}>
          POLICY SEARCH
        </div>
        <h2 style={{
          fontFamily: 'Inter, sans-serif',
          fontWeight: 600,
          fontSize: 28,
          lineHeight: '36px',
          color: 'var(--text)',
          margin: 0,
          marginBottom: 16
        }}>
          Find a Security Policy
        </h2>
        <p style={{
          fontFamily: 'Inter, sans-serif',
          fontWeight: 400,
          fontSize: 15,
          lineHeight: '22px',
          color: 'var(--muted)',
          maxWidth: 420,
          margin: 0,
          marginBottom: 32
        }}>
          Enter a policy ID or name to jump straight to it, or browse categories using the sidebar on the left.
        </p>
        <div
          className="box-border flex flex-row items-center gap-2 rounded-lg transition-colors focus-within:border-[var(--color-primary)]"
          style={{
            padding: '10px 16px',
            width: '100%',
            maxWidth: 500,
            background: 'var(--elevated-surface, #1A1A1A)',
            border: '1px solid var(--border)',
            borderRadius: 8,
            marginBottom: 16
          }}
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ flexShrink: 0 }}>
            <circle cx="7" cy="7" r="5" stroke="var(--muted)" strokeWidth="1.5" />
            <path d="M10.5 10.5L14 14" stroke="var(--muted)" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          <input
            type="text"
            placeholder="Search by policy ID or name, e.g. AE-SEC-ATG-002"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && searchTerm.trim()) {
                onCategoryChange?.('search', 'search');
              }
            }}
            className="flex-1 bg-transparent border-none outline-none text-[var(--text)] placeholder:text-[var(--muted)]"
            style={{ fontSize: 15, lineHeight: '22px', fontFamily: 'Inter, sans-serif' }}
          />
        </div>
        <p style={{
          fontFamily: 'Inter, sans-serif',
          fontWeight: 400,
          fontSize: 13,
          lineHeight: '18px',
          color: 'var(--muted)',
          margin: 0
        }}>
          Press <span style={{ padding: '2px 6px', background: 'var(--border)', borderRadius: 4, color: 'var(--text)', margin: '0 4px', fontSize: 12 }}>Enter</span> to search across all categories
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-start w-full h-full bg-[var(--surface)] overflow-hidden">

      <ConfirmationModal
        isOpen={bulkConfirmModal.isOpen}
        onClose={() => setBulkConfirmModal({ ...bulkConfirmModal, isOpen: false })}
        onConfirm={() => handleBulkToggleWrapper(bulkConfirmModal.subCategory, bulkConfirmModal.isEnable, bulkConfirmModal.severity)}
        isEnable={bulkConfirmModal.isEnable}
        title={modalTitle}
        description={modalDescription}
        confirmText={modalConfirmText}
      />

      {/* ── Header: breadcrumb + title (left), bulk-action buttons (right) ── */}
      <div
        className="box-border flex flex-col items-start w-full"
        style={{
          padding: '24px 24px 15px',
          gap: '16px',
          background: 'var(--surface)',
          borderBottom: '1px solid var(--border)',
          height: showCloudTabs ? '174px' : 'auto'
        }}
      >
        {/* Row 1: breadcrumb/title + bulk-toggle buttons */}
        <div className="flex flex-row justify-between items-center w-full" style={{ gap: '12px', height: '40px' }}>
          {/* Left: breadcrumb stack */}
          <div className="flex flex-col items-start gap-1 min-w-0" style={{ gap: '8px' }}>
            {/* Breadcrumb */}
            <div className="flex flex-row items-center gap-1 flex-wrap">
              <span
                className="font-light whitespace-nowrap"
                style={{ fontFamily: 'Inter, sans-serif', fontSize: 12, lineHeight: '16px', color: 'var(--muted)', letterSpacing: 0 }}
              >
                Security
              </span>
              {selectedCategoryData && (
                <>
                  <span className="font-light" style={{ fontSize: 12, lineHeight: '16px', color: 'var(--muted)' }}> › </span>
                  <button
                    className="font-light hover:text-[var(--text)] transition-colors bg-transparent border-none cursor-pointer p-0"
                    style={{ fontFamily: 'Inter, sans-serif', fontSize: 12, lineHeight: '16px', color: 'var(--muted)' }}
                    onClick={() => {
                      if (selectedCategoryData?.subCategories?.length > 0) {
                        onCategoryChange?.(selectedCategoryData.id, selectedCategoryData.subCategories[0].id);
                      }
                    }}
                  >
                    {selectedCategoryData.name}
                  </button>
                </>
              )}
              {subCategoryPath.map((sub, index) => (
                <React.Fragment key={sub.id}>
                  <span className="font-light" style={{ fontSize: 12, lineHeight: '16px', color: 'var(--muted)' }}> › </span>
                  <span className="font-light" style={{ fontFamily: 'Inter, sans-serif', fontSize: 12, lineHeight: '16px', color: 'var(--muted)' }}>{sub.name}</span>
                </React.Fragment>
              ))}
            </div>
            {/* Title */}
            <h1
              className="m-0 truncate"
              style={{
                fontFamily: 'Inter, sans-serif',
                fontWeight: 600,
                fontSize: 20,
                lineHeight: '24px',
                color: 'var(--text)',
              }}
            >
              {currentSubCategoryName}
            </h1>
          </div>

          {/* Right: bulk-toggle buttons */}
          <div className="flex flex-row items-center shrink-0" style={{ gap: '8px', height: '36px' }}>
            {/* Enable all dropdown */}
            <BulkToggleDropdown
              type="enable"
              totalCount={disabledCount}
              counts={enableCounts}
              onSelect={(sev) => setBulkConfirmModal({ isOpen: true, isEnable: true, severity: sev, subCategory: resolveBulkSubCategories(selectedSubCategory) })}
              disabled={!canEdit}
            />
            {/* Disable all dropdown */}
            <BulkToggleDropdown
              type="disable"
              totalCount={enabledCount}
              counts={disableCounts}
              onSelect={(sev) => setBulkConfirmModal({ isOpen: true, isEnable: false, severity: sev, subCategory: resolveBulkSubCategories(selectedSubCategory) })}
              disabled={!canEdit}
            />
          </div>
        </div>

        {/* Row 2: Search bar (left, wide) + Severity/Status dropdowns (right) */}
        <div className="flex flex-row items-center justify-between w-full" style={{ gap: '12px', height: '30px' }}>
          {/* Search bar — takes up most of the available width */}
          <div
            className="box-border flex flex-row items-center transition-colors focus-within:border-[var(--color-primary)]"
            style={{
              padding: '4px 12px',
              gap: '8px',
              height: 30,
              flex: '1 1 0',
              minWidth: 0,
              background: 'var(--elevated-surface)',
              border: '1px solid var(--border)',
              borderRadius: 8
            }}
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" style={{ flexShrink: 0 }}>
              <circle cx="6.5" cy="6.5" r="4" stroke="var(--muted)" strokeWidth="1.16667" />
              <path d="M9.5 9.5L12 12" stroke="var(--muted)" strokeWidth="1.16667" strokeLinecap="round" />
            </svg>
            <input
              type="text"
              placeholder={
                showCloudTabs
                  ? `Search ${cloudTab === 'all' ? currentSubCategoryName : cloudTab.toUpperCase()} policies...`
                  : `Search ${currentSubCategoryName} policies...`
              }
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="flex-1 bg-transparent border-none outline-none text-[var(--text)] placeholder-[var(--muted)] min-w-0"
              style={{ fontSize: 12, lineHeight: '15px', fontFamily: 'Inter, sans-serif', fontWeight: 400 }}
            />
          </div>

          {/* Severity + Status dropdowns — stay on the right */}
          <div className="flex flex-row shrink-0" style={{ gap: '6px' }}>
            <div className="relative">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="appearance-none cursor-pointer border hover:opacity-90 transition-opacity focus:outline-none box-border"
                style={{
                  padding: '4px 8px 4px 14px',
                  height: 30,
                  fontSize: 12,
                  lineHeight: '15px',
                  fontFamily: 'Inter, sans-serif',
                  fontWeight: 400,
                  background: 'var(--elevated-surface)',
                  border: '1px solid var(--border)',
                  color: 'var(--text)',
                  borderRadius: 8,
                  width: 109
                }}
              >
                <option value="ALL">Severity: All</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
              <div className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 flex items-center justify-center w-3 h-3">
                <svg width="6" height="3" viewBox="0 0 6 3" fill="none">
                  <path d="M0 0L3 3L6 0" stroke="var(--muted)" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
            </div>
            <div className="relative">
              <select
                value={enabledFilter}
                onChange={(e) => setEnabledFilter(e.target.value)}
                className="appearance-none cursor-pointer border hover:opacity-90 transition-opacity focus:outline-none box-border"
                style={{
                  padding: '4px 8px 4px 14px',
                  height: 30,
                  fontSize: 12,
                  lineHeight: '15px',
                  fontFamily: 'Inter, sans-serif',
                  fontWeight: 400,
                  background: 'var(--elevated-surface)',
                  border: '1px solid var(--border)',
                  color: 'var(--text)',
                  borderRadius: 8,
                  width: 99
                }}
              >
                <option value="ALL">Status: All</option>
                <option value="ENABLED">Enabled</option>
                <option value="DISABLED">Disabled</option>
              </select>
              <div className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 flex items-center justify-center w-3 h-3">
                <svg width="6" height="3" viewBox="0 0 6 3" fill="none">
                  <path d="M0 0L3 3L6 0" stroke="var(--muted)" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Row 3: Cloud provider tabs */}
        {showCloudTabs && (
          <div className="flex flex-row items-center" style={{ gap: '8px', height: '32px' }}>
            {PROVIDER_TABS.map((tab) => {
              const isActive = cloudTab === tab.id;
              const badgeCount = getBadgeCount(tab.id);

              // Only show GCP tab if there are actually policies (e.g. hide for Cloud view)
              if (tab.id === 'gcp' && getBadgeCount('gcp') === 0 && (selectedSubCategory === 'cloud' || selectedSubCategory === 'cloud-aws' || selectedSubCategory === 'cloud-azure')) {
                return null;
              }

              return (
                <button
                  key={tab.id}
                  onClick={() => setCloudTab(tab.id)}
                  className="box-border flex flex-row justify-center items-center cursor-pointer transition-all duration-150"
                  style={{
                    padding: '4px 12px',
                    gap: '8px',
                    height: 32,
                    borderRadius: 8,
                    background: isActive ? 'rgba(var(--color-primary-rgb),0.15)' : 'var(--elevated-surface)',
                    border: isActive ? '1px solid rgba(var(--color-primary-rgb),0.3)' : '1px solid var(--border)',
                    color: isActive ? 'var(--color-primary)' : 'var(--text)',
                    fontFamily: 'Inter, sans-serif',
                    fontWeight: 400,
                    fontSize: 12,
                    lineHeight: '15px',
                  }}
                >
                  <span>{tab.label}</span>
                  {badgeCount > 0 && (
                    <span
                      style={{
                        fontWeight: 400,
                        fontSize: 11,
                        color: isActive ? '#00D3F3' : 'var(--text)',
                      }}
                    >
                      {badgeCount}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Policy rows ── */}
      <div className="flex-1 w-full relative min-h-0">
        <div className="absolute inset-0 overflow-y-auto custom-scrollbar flex flex-col items-start w-full">
          {pagedPolicies.length === 0 ? (
            <div className="flex items-center justify-center w-full h-full text-[var(--muted)] text-sm">
              No policies found
            </div>
          ) : (
            pagedPolicies.map(policy => {
              const rawSev = policy.severity || 'Medium';
              let formattedSev = 'Medium';
              if (rawSev.toUpperCase() === 'CRITICAL') formattedSev = 'Critical';
              else if (rawSev.toUpperCase() === 'HIGH') formattedSev = 'High';
              else if (rawSev.toUpperCase() === 'MEDIUM') formattedSev = 'Medium';
              else if (rawSev.toUpperCase() === 'LOW') formattedSev = 'Low';

              return (
                <PolicyRow
                  key={`${policy.__sourceSubCategory || selectedSubCategory}-${policy.id}`}
                  policyId={policy.id}
                  title={policy.name}
                  description={policy.description || policy.finding}
                  severity={formattedSev}
                  enabled={policy.enabled}
                  disabled={!canEdit}
                  onToggle={() => handleToggleWrapper(policy, selectedSubCategory)}
                  onSeverityChange={(newSeverity) => {
                    if (!canEdit) return;
                    const actualSubCategory = resolveSubCategoryForPolicy(policy.id, selectedSubCategory, policy.__sourceSubCategory);
                    onSeverityChange && onSeverityChange(policy.id, actualSubCategory, newSeverity.toUpperCase());
                  }}
                />
              );
            })
          )}
        </div>
      </div>

      {/* ── Footer / Pagination ── */}
      <div className="flex flex-col w-full mt-auto shrink-0">
        {/* Unsaved Changes Banner */}
        <div
          className="flex flex-row justify-between items-center box-border px-6 py-[18px] w-full border-t bg-[var(--elevated-surface)] shadow-[0px_-4px_20px_rgba(10,191,173,0.06)] transition-colors"
          style={{
            height: '70.5px',
            borderColor: unsavedChangesCount > 0 ? 'color-mix(in srgb, var(--color-primary) 30%, transparent)' : 'var(--border)'
          }}
        >
          <div className="flex flex-row items-center gap-2.5">
            <div
              className="w-1.5 h-1.5 rounded-full opacity-90"
              style={{ background: unsavedChangesCount > 0 ? 'var(--color-primary)' : 'var(--muted)' }}
            />
            <div className="font-medium text-[13px] leading-5 text-[var(--text)] font-['Inter']">
              {unsavedChangesCount > 0
                ? `${unsavedChangesCount} unsaved change${unsavedChangesCount !== 1 ? 's' : ''}`
                : 'No unsaved changes.'}
            </div>
          </div>
          {unsavedChangesCount > 0 && (
            <div className="flex flex-row items-center gap-2">
              <button
                onClick={handleDiscardWrapper}
                disabled={!canEdit}
                title={!canEdit ? 'Only GitHub administrators can modify policies' : undefined}
                className="box-border relative flex justify-center items-center transition-colors bg-transparent border border-[var(--border)] hover:bg-[var(--border)]/30 cursor-pointer"
                style={{
                  width: '77.49px',
                  height: '33.5px',
                  borderRadius: '10px',
                  fontFamily: 'Inter',
                  fontWeight: 500,
                  fontSize: '13px',
                  lineHeight: '20px',
                  textAlign: 'center',
                  color: 'var(--muted)'
                }}
              >
                Discard
              </button>
              <button
                onClick={handleSaveWrapper}
                disabled={!canEdit}
                title={!canEdit ? 'Only GitHub administrators can modify policies' : undefined}
                className="box-border relative flex justify-center items-center cursor-pointer transition-opacity border-none hover:opacity-90"
                style={{
                  width: '140.94px',
                  height: '31.5px',
                  background: 'var(--color-primary)',
                  borderRadius: '10px',
                  fontFamily: 'Inter',
                  fontWeight: 500,
                  fontSize: '13px',
                  lineHeight: '20px',
                  textAlign: 'center',
                  color: '#0C0E12'
                }}
              >
                Save preferences
              </button>
            </div>
          )}
        </div>

        {/* Pagination & Summary Banner */}
        <div
          className="box-border flex flex-row items-center justify-between px-5 py-3 w-full border-t border-[var(--border)] bg-[var(--surface)] transition-colors"
          style={{ height: '59px' }}
        >
          {/* Summary Text */}
          <div className="flex flex-col items-start justify-center">
            <div className="font-normal text-[11px] leading-4 text-[var(--muted)] font-['Inter']">
              {enabledCount} enabled · {disabledCount} disabled · {filteredPolicies.length} of {bulkBase.length} shown
            </div>
            <div className="mt-0.5 font-normal text-[10px] leading-[15px] text-[var(--muted)] opacity-80 font-['Inter']">
              Use Scan Options to enable or disable scans. Use Policies to define security rules.
            </div>
          </div>

          {/* RIGHT SIDE: Pagination + Last Updated Date Grouped */}
          <div className="flex flex-row items-center gap-6">
            {/* Pagination */}
            <div className="flex flex-row items-center gap-1">
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                className="box-border flex justify-center items-center cursor-pointer transition-colors bg-transparent rounded-sm font-medium text-[13px] leading-5 font-['Inter'] w-7 h-7"
                style={{
                  border: currentPage === 1 ? '1px solid var(--border)' : '1px solid var(--border)',
                  opacity: currentPage === 1 ? 0.4 : 1,
                  color: 'var(--muted)'
                }}
              >
                ‹
              </button>

              {/* Page Numbers */}
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let pageNum;
                if (totalPages <= 5) {
                  pageNum = i + 1;
                } else if (currentPage <= 3) {
                  pageNum = i + 1;
                } else if (currentPage >= totalPages - 2) {
                  pageNum = totalPages - 4 + i;
                } else {
                  pageNum = currentPage - 2 + i;
                }

                const isActive = pageNum === currentPage;

                return (
                  <button
                    key={pageNum}
                    onClick={() => setCurrentPage(pageNum)}
                    className="box-border flex justify-center items-center cursor-pointer transition-colors rounded-sm font-medium text-[12px] leading-[18px] font-['Inter'] w-7 h-7"
                    style={{
                      background: isActive ? 'rgba(var(--color-primary-rgb),0.15)' : 'transparent',
                      border: isActive ? '1px solid rgba(var(--color-primary-rgb),0.3)' : '1px solid var(--border)',
                      color: isActive ? 'var(--color-primary)' : 'var(--muted)'
                    }}
                  >
                    {pageNum}
                  </button>
                );
              })}

              <button
                disabled={currentPage === totalPages || totalPages === 0}
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                className="box-border flex justify-center items-center cursor-pointer transition-colors bg-transparent rounded-sm font-medium text-[13px] leading-5 font-['Inter'] w-7 h-7"
                style={{
                  border: currentPage === totalPages || totalPages === 0 ? '1px solid var(--border)' : '1px solid var(--border)',
                  opacity: currentPage === totalPages || totalPages === 0 ? 0.4 : 1,
                  color: 'var(--muted)'
                }}
              >
                ›
              </button>
            </div>

            {/* Last Updated Date */}
            <div className="font-normal text-[10px] leading-[15px] text-[var(--muted)] opacity-80 font-['Inter']">
              Last updated: 3/28/2026
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanPoliciesList;
