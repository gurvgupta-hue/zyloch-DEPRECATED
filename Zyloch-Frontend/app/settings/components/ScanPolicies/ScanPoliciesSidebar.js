// ScanPolicies/ScanPoliciesSidebar.js
"use client";
import React, { useState } from 'react';
import { ChevronLeft, ChevronRight, ChevronDown } from 'lucide-react';

// ── Icon container colors ─────────────────────────────────────────
const ICON_STYLE = {
  // root-level categories
  workflow: { border: '#22D3EE' },
  iac: { border: '#6B7280' },
  secrets: { border: '#646464' },

  // IaC children
  kubernetes: { border: '#9B72CF' },
  docker: { border: '#22D3EE' },
  terraform: { border: '#7B42F6' },
  cloud: { border: '#6B7280' },
  ansible: { border: '#646464' },

  // Terraform & Cloud children
  aws: { border: '#F5A623' },
  azure: { border: '#5B9BD5' },
  gcp: { border: '#0ABFAD' },
  'cloud-aws': { border: '#F5A623' },
  'cloud-azure': { border: '#5B9BD5' },
  bicep: { border: '#0078D4' },
  cloudformation: { border: '#F5A623' },

  // Secrets children
  'dlp-pii': { border: '#646464' },
  'dlp-pci': { border: '#646464' },
  'dlp-phi': { border: '#646464' },
  'api-keys': { border: '#646464' },
  'access-tokens': { border: '#646464' },
  credentials: { border: '#646464' },
  'generic-secrets': { border: '#646464' },
};

// ── helpers ───────────────────────────────────────────────────────────────────
function countNodePolicies(node, policies) {
  if (node.subCategories && node.subCategories.length > 0) {
    return node.subCategories.reduce((s, c) => s + countNodePolicies(c, policies), 0);
  }
  return policies[node.id]?.length || 0;
}

/** Walk the full tree to find a node by id */
function findNodeById(id, nodes) {
  for (const node of nodes) {
    if (node.id === id) return node;
    if (node.subCategories) {
      const found = findNodeById(id, node.subCategories);
      if (found) return found;
    }
  }
  return null;
}

// ── single row ────────────────────────────────────────────────────────────────
const SidebarRow = ({ node, isActive, hasChildren, isExpanded, isChild, count, onClick }) => {
  const [isHovered, setIsHovered] = useState(false);
  const s = ICON_STYLE[node.id] || { border: '#646464' };
  const accentColor = s.border;

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className="box-border flex flex-row items-center w-full h-[36px] rounded-md relative overflow-hidden"
      style={{
        padding: '6px 8px',
        gap: 8,
        transition: 'all 200ms cubic-bezier(0.4, 0, 0.2, 1)',
        background: isActive
          ? `linear-gradient(90deg, ${accentColor}18 0%, ${accentColor}08 100%)`
          : isHovered
            ? `linear-gradient(90deg, ${accentColor}12 0%, ${accentColor}05 100%)`
            : 'transparent',
        borderLeft: isActive
          ? `2px solid ${accentColor}`
          : isHovered
            ? `2px solid ${accentColor}80`
            : '2px solid transparent',
        paddingLeft: isChild ? (isActive || isHovered ? 38 : 40) : (isActive || isHovered ? 6 : 8),
      }}
    >
      {/* icon container – only for parents */}
      {!isChild && node.icon && (
        <div
          className="flex-shrink-0 flex items-center justify-center"
          style={{
            width: 24,
            height: 24,
            borderRadius: 6,
            backgroundColor: isActive
              ? `${accentColor}25`
              : isHovered
                ? `${accentColor}20`
                : `${accentColor}15`,
            transition: 'all 200ms cubic-bezier(0.4, 0, 0.2, 1)',
            transform: isHovered || isActive ? 'scale(1.08)' : 'scale(1)',
            boxShadow: isActive
              ? `0 0 8px ${accentColor}40`
              : isHovered
                ? `0 0 6px ${accentColor}25`
                : 'none',
            color: accentColor
          }}
        >
          {node.icon}
        </div>
      )}

      {/* label */}
      <span
        className="flex-1 text-left truncate"
        style={{
          fontFamily: 'Inter, sans-serif',
          fontWeight: isActive || isHovered ? 600 : 500,
          fontSize: 15,
          lineHeight: '18px',
          color: isActive
            ? 'var(--text)'
            : isHovered
              ? 'var(--text-secondary, var(--text))'
              : 'var(--muted)',
          transition: 'all 200ms ease',
        }}
      >
        {node.name}
      </span>

      {/* count + arrow */}
      <div className="flex items-center flex-shrink-0" style={{ gap: 6 }}>
        {count != null && count !== '' && (
          <div
            style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              height: 20,
              borderRadius: 10,
              padding: '0 8px',
              minWidth: 24,
              background: isActive || isHovered ? `${accentColor}15` : 'var(--bg-hover, rgba(100, 100, 100, 0.1))',
              transition: 'all 200ms ease',
            }}
          >
            <span
              style={{
                fontFamily: 'Inter, sans-serif',
                fontWeight: 500,
                fontSize: 11,
                lineHeight: '16px',
                color: isHovered || isActive ? accentColor : 'var(--muted)',
                transition: 'color 200ms ease',
              }}
            >
              {count}
            </span>
          </div>
        )}
        {hasChildren && (
          isExpanded ? (
            <ChevronDown
              size={12}
              style={{
                color: isHovered || isActive ? accentColor : 'var(--muted)',
                transform: 'translateY(1px)',
                transition: 'all 200ms ease',
              }}
            />
          ) : (
            <ChevronRight
              size={12}
              style={{
                color: isHovered || isActive ? accentColor : 'var(--muted)',
                transform: isHovered ? 'translateX(2px)' : 'translateX(0)',
                transition: 'all 200ms ease',
              }}
            />
          )
        )}
      </div>
    </button>
  );
};

// ── exported sidebar ──────────────────────────────────────────────────────────
export const ScanPoliciesSidebar = ({
  selectedCategory,
  setSelectedCategory,
  selectedSubCategory,
  setSelectedSubCategory,
  expandedCategories,
  toggleCategory,
  scanCategories,
  navGroups,
  policies,
  policyStats,
  getCategoryCount,
}) => {
  const showBackButton = Boolean(selectedSubCategory);

  const handleItemClick = (node, isChild = false, parentId = null) => {
    const hasChildren = node.subCategories && node.subCategories.length > 0 && !(node.subCategories.length === 1 && node.subCategories[0].id === node.id);

    if (hasChildren && !isChild) {
      const isCurrentlyExpanded = expandedCategories.includes(node.id);
      toggleCategory(node.id);
      // Auto-navigate to first subcategory when expanding
      if (!isCurrentlyExpanded && node.subCategories.length > 0) {
        const firstSub = node.subCategories[0];
        setSelectedCategory(node.id);
        setSelectedSubCategory(firstSub.id);
      }
    } else {
      setSelectedCategory(parentId || node.id);
      setSelectedSubCategory(node.id);
    }
  };

  return (
    <div
      className="box-border flex flex-col items-start p-0 bg-transparent shrink-0 self-stretch overflow-hidden"
      style={{ width: 240, borderRight: '1px solid var(--border)' }}
    >
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div
        className="box-border flex flex-col justify-center w-full border-b border-[var(--border)] flex-shrink-0"
        style={{ padding: '10px 16px 12px', minHeight: 81.5 }}
      >
        {showBackButton && (
          <button
            type="button"
            onClick={() => { setSelectedCategory(null); setSelectedSubCategory(null); }}
            className="inline-flex items-center gap-1.5 border-none bg-transparent p-0 mb-2 cursor-pointer hover:opacity-90 transition-opacity"
            style={{
              fontFamily: 'Inter, sans-serif',
              fontWeight: 600,
              fontSize: 13,
              lineHeight: '16px',
              color: 'var(--color-primary)',
            }}
            aria-label="Back to policy search"
          >
            <ChevronLeft size={14} style={{ color: 'var(--color-primary)' }} />
            Back
          </button>
        )}
        <button
          onClick={() => { setSelectedCategory(null); setSelectedSubCategory(null); }}
          className="text-left bg-transparent border-none p-0 cursor-pointer hover:opacity-75 transition-opacity"
          style={{
            fontFamily: 'Inter, sans-serif',
            fontWeight: 500,
            fontSize: 18,
            lineHeight: '26px',
            color: 'var(--text)',
          }}
        >
          Policy Management
        </button>
        <div
          style={{
            fontFamily: 'Inter, sans-serif',
            fontWeight: 400,
            fontSize: 12,
            lineHeight: '16px',
            color: 'var(--muted)',
            marginTop: 2,
          }}
        >
          {navGroups.length} Categories
        </div>
      </div>

      {/* ── Navigation ─────────────────────────────────────────────────────── */}
      <div className="flex-1 w-full relative min-h-0">
        <div
          className="absolute inset-0 flex flex-col items-start w-full overflow-y-auto custom-scrollbar"
          style={{ padding: '8px 8px' }}
        >
          {navGroups.map((group) => (
            <div
              key={group.id}
              className="flex flex-col items-start w-full"
              style={{ marginBottom: 12 }}
            >
              {/* group label (hidden for workflow/pipeline to match design) */}
              {group.id !== 'pipeline' && (
                <div style={{ padding: '7px 8px', width: '100%' }}>
                  <span
                    style={{
                      fontFamily: 'Inter, sans-serif',
                      fontWeight: 500,
                      fontSize: 11,
                      lineHeight: '16px',
                      letterSpacing: '0.9px',
                      textTransform: 'uppercase',
                      color: 'var(--muted)',
                    }}
                  >
                    {group.label}
                  </span>
                </div>
              )}

              {/* category rows */}
              {group.categories.map((categoryId) => {
                const category = scanCategories.find((c) => c.id === categoryId);
                if (!category) return null;

                const count = getCategoryCount(category);
                const hasChildren = category.subCategories && category.subCategories.length > 0 && !(category.subCategories.length === 1 && category.subCategories[0].id === category.id);
                const isExpanded = expandedCategories.includes(category.id);
                const isActive = !hasChildren && selectedCategory === category.id && selectedSubCategory === category.id;

                return (
                  <React.Fragment key={category.id}>
                    <SidebarRow
                      node={category}
                      isActive={isActive}
                      hasChildren={hasChildren}
                      isExpanded={isExpanded}
                      count={count > 0 ? count : ''}
                      onClick={() => handleItemClick(category)}
                    />

                    {/* Render children if expanded */}
                    {hasChildren && isExpanded && (
                      <div className="flex flex-col w-full" style={{ paddingLeft: '0px' }}>
                        {category.subCategories.map(subNode => {
                          const subCount = countNodePolicies(subNode, policies);
                          const isSubActive = selectedSubCategory === subNode.id;
                          return (
                            <SidebarRow
                              key={subNode.id}
                              node={subNode}
                              isActive={isSubActive}
                              hasChildren={false}
                              isChild={true}
                              count={subCount > 0 ? subCount : ''}
                              onClick={() => handleItemClick(subNode, true, category.id)}
                            />
                          );
                        })}
                      </div>
                    )}
                  </React.Fragment>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* ── Footer ─────────────────────────────────────────────────────────── */}
      <div
        className="box-border flex flex-col items-start w-full border-t border-[var(--border)] flex-shrink-0"
        style={{ padding: '12px 16px' }}
      >
        <div
          className="flex flex-row items-center justify-between w-full"
          style={{ marginBottom: 8 }}
        >
          <span
            style={{
              fontFamily: 'Inter, sans-serif',
              fontWeight: 400,
              fontSize: 12,
              lineHeight: '16px',
              color: 'var(--muted)',
            }}
          >
            {policyStats.enabledPercentage}% Enabled
          </span>
          <span
            style={{
              fontFamily: 'Inter, sans-serif',
              fontWeight: 500,
              fontSize: 12,
              lineHeight: '16px',
              color: 'var(--muted)',
            }}
          >
            {policyStats.enabledPolicies}/{policyStats.totalPolicies}
          </span>
        </div>

        {/* progress bar */}
        <div
          className="w-full overflow-hidden"
          style={{ height: 4, borderRadius: 2, backgroundColor: 'var(--border)' }}
        >
          <div
            className="h-full transition-all duration-300"
            style={{
              width: `${policyStats.enabledPercentage}%`,
              borderRadius: 2,
              backgroundColor: 'var(--color-primary)',
            }}
          />
        </div>
      </div>
    </div>
  );
};