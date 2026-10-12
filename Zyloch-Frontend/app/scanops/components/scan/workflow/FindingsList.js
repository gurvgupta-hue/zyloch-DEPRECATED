"use client";

import React, { useState, useMemo } from "react";
import { FileText, AlertTriangle, Shield, Filter, X, Search } from "lucide-react";
import FindingCard from "./FindingCard";

const FindingsList = ({ workflowFindings }) => {
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all"); // 'all', 'critical', 'high', 'medium', 'low'
  
  // Calculate severity counts
  const severityCounts = useMemo(() => {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0
    };
    
    (workflowFindings || []).forEach(finding => {
      (finding.violated_policies || []).forEach(policy => {
        const sev = String(policy?.severity || "").trim().toLowerCase();
        if (counts[sev] !== undefined) {
          counts[sev] = (counts[sev] || 0) + 1;
        }
        counts.total++;
      });
    });
    
    return counts;
  }, [workflowFindings]);
  
  // Extract all unique policy codes from all findings
  const allPolicyCodes = [];
  workflowFindings.forEach(finding => {
    finding.violated_policies.forEach(policy => {
      if (!allPolicyCodes.includes(policy.policy_code)) {
        allPolicyCodes.push(policy.policy_code);
      }
    });
  });
  
  // Count policy occurrences
  const policyCounts = {};
  workflowFindings.forEach(finding => {
    finding.violated_policies.forEach(policy => {
      const code = policy.policy_code;
      policyCounts[code] = (policyCounts[code] || 0) + 1;
    });
  });

  // Get severity for each policy code
  const policySeverities = {};
  workflowFindings.forEach(finding => {
    finding.violated_policies.forEach(policy => {
      const code = policy.policy_code;
      if (!policySeverities[code]) {
        policySeverities[code] = policy.severity;
      }
    });
  });

  // Severity options with counts
  const severityOptions = [
    { 
      value: 'all', 
      label: 'All Severities', 
      color: 'var(--muted)',
      count: severityCounts.total
    },
    { 
      value: 'critical', 
      label: 'Critical', 
      color: 'var(--danger)',
      count: severityCounts.critical
    },
    { 
      value: 'high', 
      label: 'High', 
      color: 'var(--warning)',
      count: severityCounts.high
    },
    { 
      value: 'medium', 
      label: 'Medium', 
      color: 'var(--info)',
      count: severityCounts.medium
    },
    { 
      value: 'low', 
      label: 'Low', 
      color: 'var(--success)',
      count: severityCounts.low
    }
  ];

  // Filter findings based on search query, selected policy, and severity filter
  const filteredFindings = useMemo(() => {
    let findings = workflowFindings;
    
    // Apply policy filter
    if (selectedPolicy) {
      findings = findings.map(finding => ({
        ...finding,
        violated_policies: finding.violated_policies.filter(
          p => p.policy_code === selectedPolicy
        )
      })).filter(finding => finding.violated_policies.length > 0);
    }
    
    // Apply search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      findings = findings.filter(finding => {
        // Search in file name
        const fileNameMatch = finding.file_name?.toLowerCase().includes(query);
        
        // Search in policy codes and descriptions
        const policyMatch = finding.violated_policies.some(policy => 
          policy.policy_code?.toLowerCase().includes(query) ||
          policy.description?.toLowerCase().includes(query) ||
          policy.severity?.toLowerCase().includes(query)
        );
        
        return fileNameMatch || policyMatch;
      });
    }
    
    // Apply severity filter
    if (severityFilter !== 'all') {
      findings = findings.map(finding => ({
        ...finding,
        violated_policies: finding.violated_policies.filter(
          p => p.severity === severityFilter
        )
      })).filter(finding => finding.violated_policies.length > 0);
    }
    
    return findings;
  }, [workflowFindings, selectedPolicy, searchQuery, severityFilter]);

  const totalFiles = filteredFindings.length;
  const totalIssues = filteredFindings.reduce(
    (sum, finding) => sum + finding.violated_policies.length, 
    0
  );

  // Get severity color using CSS variables
  const getSeverityColor = (severity) => {
    const colorMap = {
      critical: 'var(--danger)',
      high: 'var(--warning)',
      medium: 'var(--info)',
      low: 'var(--success)'
    };
    return colorMap[severity] || 'var(--success)';
  };

  const getSeverityBgColor = (severity) => {
    const bgMap = {
      critical: 'var(--danger)08',
      high: 'var(--warning)08',
      medium: 'var(--info)08',
      low: 'var(--success)08'
    };
    return bgMap[severity] || 'var(--success)08';
  };

  const clearAllFilters = () => {
    setSelectedPolicy(null);
    setSearchQuery("");
    setSeverityFilter("all");
  };

  const hasActiveFilters = selectedPolicy || searchQuery || severityFilter !== 'all';

  return (
    <div style={{
      background: "linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%)",
      borderRadius: 'var(--radius-lg)',
      padding: 'var(--space-4)',
      border: '1px solid rgba(255,255,255,0.10)',
    }}>
      {/* HEADER SECTION */}
      <div style={{ marginBottom: 'var(--space-6)' }}>
        {/* Title and Summary */}
        <div style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          marginBottom: 'var(--space-4)',
          flexWrap: 'wrap',
          gap: 'var(--space-3)'
        }}>
          <div>
            <h3 style={{
              fontSize: 'var(--font-size-xl)',
              fontWeight: 'var(--weight-bold)',
              color: 'var(--text)',
              marginBottom: 'var(--space-1)'
            }}>
              Workflow Findings
            </h3>
            
            {/* Summary Stats */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-3)',
              marginBottom: 'var(--space-4)'
            }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-1)'
              }}>
                <span style={{
                  fontSize: 'var(--font-size-sm)',
                  color: 'var(--text)'
                }}>
                  {totalIssues} total issues
                </span>
              </div>
              
              <div style={{ 
                width: '1px', 
                height: 'var(--space-3)', 
                backgroundColor: 'var(--border)' 
              }} />
              
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-1)'
              }}>
                <span style={{
                  fontSize: 'var(--font-size-sm)',
                  color: 'var(--text)'
                }}>
                  {totalFiles} file{totalFiles !== 1 ? "s" : ""}
                </span>
              </div>
            </div>
          </div>
          
          {/* Clear All Filters Button when any filter is active */}
          {hasActiveFilters && (
            <button
              onClick={clearAllFilters}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
                padding: 'var(--space-1) var(--space-2)',
                backgroundColor: 'var(--surface)',
                color: 'var(--muted)',
                fontSize: 'var(--font-size-xs)',
                fontWeight: 'var(--weight-medium)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border)',
                cursor: 'pointer',
                transition: 'all var(--transition-normal)',
                alignSelf: 'flex-start'
              }}
            >
              <X style={{ width: 'var(--space-3)', height: 'var(--space-3)' }} />
              Clear All
            </button>
          )}
        </div>

        {/* Search Bar - Full Width */}
        <div style={{
          marginBottom: 'var(--space-4)',
          position: 'relative'
        }}>
          <div style={{
            position: 'absolute',
            left: 'var(--space-3)',
            top: '50%',
            transform: 'translateY(-50%)',
            color: 'var(--muted-foreground)',
            display: 'flex',
            alignItems: 'center',
            pointerEvents: 'none'
          }}>
            <Search style={{ width: 'var(--space-4)', height: 'var(--space-4)' }} />
          </div>
          <input
            type="text"
            placeholder="Search by file name, policy code, severity, or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: 'var(--space-3) var(--space-3) var(--space-3) calc(var(--space-3) + var(--space-5))',
              backgroundColor: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-md)',
              color: 'var(--text)',
              fontSize: 'var(--font-size-sm)',
              outline: 'none',
              transition: 'border-color var(--transition-normal)'
            }}
            onFocus={(e) => e.target.style.borderColor = 'var(--color-primary)'}
            onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              style={{
                position: 'absolute',
                right: 'var(--space-3)',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'none',
                border: 'none',
                color: 'var(--muted-foreground)',
                cursor: 'pointer',
                padding: 'var(--space-1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: '50%'
              }}
            >
              <X style={{ width: 'var(--space-3)', height: 'var(--space-3)' }} />
            </button>
          )}
        </div>

        {/* Severity Filter - Professional Segmented Control with Counts */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-2)',
          flexWrap: 'wrap',
          marginBottom: 'var(--space-4)',
          padding: 'var(--space-1)',
          backgroundColor: 'var(--elevated-surface)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border)',
          width: 'fit-content'
        }}>
          {severityOptions.map((option) => {
            const isSelected = severityFilter === option.value;
            
            return (
              <button
                key={option.value}
                onClick={() => setSeverityFilter(option.value)}
                style={{
                  padding: 'var(--space-1) var(--space-3)',
                  borderRadius: 'var(--radius-md)',
                  border: 'none',
                  backgroundColor: isSelected ? 'var(--surface)' : 'transparent',
                  color: isSelected ? option.color : 'var(--muted)',
                  fontSize: 'var(--font-size-sm)',
                  fontWeight: isSelected ? 'var(--weight-medium)' : 'var(--weight-normal)',
                  cursor: 'pointer',
                  transition: 'all var(--transition-normal)',
                  boxShadow: isSelected ? 'var(--shadow-sm)' : 'none',
                  textTransform: 'capitalize',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-1)'
                }}
              >
                <span>{option.label}</span>
                <span style={{
                  backgroundColor: isSelected ? option.color : 'var(--border)',
                  color: isSelected ? 'var(--surface)' : 'var(--text)',
                  fontSize: 'var(--font-size-xs)',
                  fontWeight: 'var(--weight-medium)',
                  padding: '2px var(--space-1)',
                  borderRadius: 'var(--radius-full)',
                  minWidth: 'var(--space-4)',
                  textAlign: 'center',
                  lineHeight: '1.2'
                }}>
                  {option.count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Active Filters Summary */}
      {hasActiveFilters && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-2)',
          marginBottom: 'var(--space-4)',
          padding: 'var(--space-2) var(--space-3)',
          backgroundColor: 'var(--elevated-surface)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)',
          flexWrap: 'wrap'
        }}>
          <Filter style={{ 
            width: 'var(--space-3)', 
            height: 'var(--space-3)', 
            color: 'var(--muted)'
          }} />
          <span style={{
            fontSize: 'var(--font-size-xs)',
            color: 'var(--muted)'
          }}>Active filters:</span>
          
          {searchQuery && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-1)',
              padding: 'var(--space-0) var(--space-2)',
              backgroundColor: 'var(--surface)',
              borderRadius: 'var(--radius-full)',
              border: '1px solid var(--border)'
            }}>
              <Search style={{ width: 'var(--space-2)', height: 'var(--space-2)', color: 'var(--muted)' }} />
              <span style={{
                fontSize: 'var(--font-size-xs)',
                color: 'var(--text)'
              }}>"{searchQuery}"</span>
              <button
                onClick={() => setSearchQuery("")}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--muted)',
                  cursor: 'pointer',
                  padding: '2px',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <X style={{ width: 'var(--space-2)', height: 'var(--space-2)' }} />
              </button>
            </div>
          )}
          
          {severityFilter !== 'all' && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
                padding: 'var(--space-0) var(--space-2)',
                backgroundColor: getSeverityBgColor(severityFilter),
                borderRadius: 'var(--radius-full)',
                border: `1px solid ${getSeverityColor(severityFilter)}30`,
                textTransform: 'capitalize'
              }}
            >
              <span style={{
                fontSize: 'var(--font-size-xs)',
                color: getSeverityColor(severityFilter),
                fontWeight: 'var(--weight-medium)'
              }}>{severityFilter}</span>
              <span style={{
                fontSize: 'var(--font-size-xs)',
                color: getSeverityColor(severityFilter),
                opacity: 0.7
              }}>
                ({severityCounts[severityFilter]})
              </span>
              <button
                onClick={() => setSeverityFilter('all')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: getSeverityColor(severityFilter),
                  cursor: 'pointer',
                  padding: '2px',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <X style={{ width: 'var(--space-2)', height: 'var(--space-2)' }} />
              </button>
            </div>
          )}
          
          {selectedPolicy && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
                padding: 'var(--space-0) var(--space-2)',
                backgroundColor: getSeverityBgColor(policySeverities[selectedPolicy]),
                borderRadius: 'var(--radius-full)',
                border: `1px solid ${getSeverityColor(policySeverities[selectedPolicy])}30`
              }}
            >
              <span style={{
                fontSize: 'var(--font-size-xs)',
                color: getSeverityColor(policySeverities[selectedPolicy]),
                fontWeight: 'var(--weight-medium)',
                fontFamily: 'var(--font-mono)'
              }}>{selectedPolicy}</span>
              <button
                onClick={() => setSelectedPolicy(null)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: getSeverityColor(policySeverities[selectedPolicy]),
                  cursor: 'pointer',
                  padding: '2px',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <X style={{ width: 'var(--space-2)', height: 'var(--space-2)' }} />
              </button>
            </div>
          )}
        </div>
      )}

      {/* FINDINGS LIST */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
        {filteredFindings.map((finding, index) => (
          <FindingCard key={index} finding={finding} />
        ))}
        
        {/* Empty state when no results */}
        {filteredFindings.length === 0 && (
          <div style={{
            textAlign: 'center',
            padding: 'var(--space-8) var(--space-4)',
            border: '1px dashed var(--border)',
            borderRadius: 'var(--radius-lg)',
            backgroundColor: 'var(--elevated-surface)'
          }}>
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 'var(--space-3)',
              color: 'var(--muted)',
              maxWidth: '280px',
              margin: '0 auto'
            }}>
              <div style={{
                width: '48px',
                height: '48px',
                borderRadius: '50%',
                backgroundColor: 'var(--surface)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                border: '1px dashed var(--border)'
              }}>
                <Search style={{ 
                  width: 'var(--space-4)', 
                  height: 'var(--space-4)', 
                  color: 'var(--muted-foreground)' 
                }} />
              </div>
              <div>
                <p style={{ 
                  fontWeight: 'var(--weight-semibold)',
                  fontSize: 'var(--font-size-base)',
                  color: 'var(--text)',
                  marginBottom: 'var(--space-1)'
                }}>
                  No matching findings
                </p>
                <p style={{ 
                  fontSize: 'var(--font-size-xs)',
                  color: 'var(--muted-foreground)',
                  lineHeight: '1.4'
                }}>
                  {hasActiveFilters 
                    ? "Try adjusting your search or filters"
                    : "No findings available"}
                </p>
              </div>
              {hasActiveFilters && (
                <button
                  onClick={clearAllFilters}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--space-1)',
                    padding: 'var(--space-1) var(--space-3)',
                    backgroundColor: 'var(--color-primary)',
                    color: 'var(--text-on-primary)',
                    fontSize: 'var(--font-size-xs)',
                    fontWeight: 'var(--weight-medium)',
                    borderRadius: 'var(--radius-md)',
                    border: 'none',
                    cursor: 'pointer',
                    transition: 'all var(--transition-normal)',
                    marginTop: 'var(--space-1)'
                  }}
                >
                  <X style={{ width: 'var(--space-3)', height: 'var(--space-3)' }} />
                  Clear All Filters
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default FindingsList;