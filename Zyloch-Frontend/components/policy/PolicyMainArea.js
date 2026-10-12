"use client";
import React, { useState } from 'react';
import PolicyRow from './PolicyRow';

const PolicyMainArea = () => {
  const [policies, setPolicies] = useState([
    { id: 1, policyId: 'AZ-SEC-STG-001', title: "storage: Secure Transfer", description: "storage: Secure Transfer", severity: "Medium", enabled: false },
    { id: 2, policyId: 'AZ-SEC-STG-002', title: "storage: HTTPS Only", description: "storage: HTTPS Only", severity: "Medium", enabled: true },
    { id: 3, policyId: 'AZ-SEC-STG-003', title: "storage: Minimum TLS", description: "storage: Minimum TLS", severity: "Medium", enabled: true },
    { id: 4, policyId: 'AZ-SEC-STG-004', title: "storage: Blob Public Access", description: "storage: Blob Public Access", severity: "Medium", enabled: true },
    { id: 5, policyId: 'AZ-SEC-STG-005', title: "storage: Firewall", description: "storage: Firewall", severity: "Medium", enabled: true },
    { id: 6, policyId: 'AZ-SEC-STG-006', title: "storage: Soft Delete", description: "storage: Soft Delete", severity: "Medium", enabled: true },
  ]);

  const handleToggle = (id) => {
    setPolicies(policies.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p));
  };

  const handleEnableAll = () => {
    setPolicies(policies.map(p => ({ ...p, enabled: true })));
  };

  const handleDisableAll = () => {
    setPolicies(policies.map(p => ({ ...p, enabled: false })));
  };

  return (
    <div className="flex flex-col items-start p-0 flex-1 h-full bg-[#141414] min-w-0">
      {/* Header */}
      <div className="box-border flex flex-row justify-between items-center px-5 py-[14px] w-full h-[69px] border-b border-[#1E2028]">
        <div className="flex flex-col items-start">
          <div className="font-medium text-[14px] leading-[21px] text-white">Security › Workflow</div>
          <div className="font-normal text-[11px] leading-4 text-[#6B7280] mt-[2px]">6 policies · {policies.filter(p => p.enabled).length} enabled · {policies.filter(p => !p.enabled).length} disabled</div>
        </div>
        <div className="flex flex-row items-center gap-3">
          {/* Enable All */}
          <div className="box-border flex flex-row items-start h-[36px] border-[0.5px] border-[rgba(10,191,173,0.35)] rounded-lg overflow-hidden cursor-pointer hover:bg-[rgba(10,191,173,0.15)] transition-colors" onClick={handleEnableAll}>
            <div className="flex items-center px-[14px] gap-2 h-full bg-[rgba(10,191,173,0.1)] border-r-[0.5px] border-[rgba(10,191,173,0.35)] text-[#0ABFAD] font-medium text-[12px]">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M2.5 6L5 8.5L9.5 4" stroke="#0ABFAD" strokeWidth="1.08333" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              Enable all
            </div>
            <div className="flex justify-center items-center w-[38px] h-full bg-[rgba(10,191,173,0.1)] border-r-[0.5px] border-[rgba(10,191,173,0.35)] text-[#0ABFAD] font-medium text-[11px]">
              6
            </div>
            <div className="flex justify-center items-center w-[34px] h-full bg-[rgba(10,191,173,0.1)]">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M3 4.5L6 7.5L9 4.5" stroke="#0ABFAD" strokeWidth="1.08333" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
          </div>

          {/* Disable All */}
          <div className="box-border flex flex-row items-start h-[36px] border-[0.5px] border-[rgba(248,81,73,0.35)] rounded-lg overflow-hidden cursor-pointer hover:bg-[rgba(248,81,73,0.15)] transition-colors" onClick={handleDisableAll}>
            <div className="flex items-center px-[14px] gap-2 h-full bg-[rgba(248,81,73,0.1)] border-r-[0.5px] border-[rgba(248,81,73,0.35)] text-[#F85149] font-medium text-[12px]">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="6" cy="6" r="4.5" stroke="#F85149" strokeWidth="1.08333" />
                <path d="M3 3L9 9" stroke="#F85149" strokeWidth="1.08333" strokeLinecap="round" />
              </svg>
              Disable all
            </div>
            <div className="flex justify-center items-center w-[38px] h-full bg-[rgba(248,81,73,0.1)] border-r-[0.5px] border-[rgba(248,81,73,0.35)] text-[#F85149] font-medium text-[11px]">
              6
            </div>
            <div className="flex justify-center items-center w-[34px] h-full bg-[rgba(248,81,73,0.1)]">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M3 4.5L6 7.5L9 4.5" stroke="#F85149" strokeWidth="1.08333" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="box-border flex flex-col items-start px-5 py-[12px] gap-3 w-full border-b border-[#1E2028]">
        {/* Search */}
        <div className="box-border flex flex-row items-center px-3 py-2 gap-2 w-full bg-[#1A1A1A] border border-[#323232] rounded-[10px] focus-within:border-[#00D3F3] transition-colors">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="6.5" cy="6.5" r="4" stroke="#99A1AF" strokeWidth="1.16667" />
            <path d="M9.5 9.5L12 12" stroke="#99A1AF" strokeWidth="1.16667" strokeLinecap="round" />
          </svg>
          <input
            type="text"
            placeholder="Search AWS policies..."
            className="flex-1 bg-transparent border-none outline-none text-[13px] text-white placeholder-[#99A1AF]"
          />
        </div>

        {/* Tags */}
        <div className="flex flex-row items-center gap-2 w-full justify-between mt-1">
          <div className="flex flex-row gap-1 items-center">
            <div className="flex items-center px-[9px] py-[2px] bg-[rgba(30,32,40,0.4)] border border-[#1E2028] rounded-[5px] text-[#9CA3AF] text-[11px]">Security</div>
            <span className="text-[#4B5563] text-[11px] font-bold">›</span>
            <div className="flex items-center px-[8px] py-[2px] bg-[rgba(30,32,40,0.4)] border border-[#1E2028] rounded-[5px] text-[#9CA3AF] text-[11px]">IaC</div>
            <span className="text-[#4B5563] text-[11px] font-bold">›</span>
            <div className="flex items-center px-[9px] py-[2px] bg-[rgba(0,211,243,0.1)] border border-[rgba(0,184,219,0.3)] rounded-[5px] text-[#00D3F3] text-[11px]">Terraform</div>
          </div>
          <div className="flex flex-row gap-2">
            <button className="flex items-center px-[14px] py-[6px] gap-2 bg-[#1E1E1E] border border-[#323232] rounded-[10px] text-white text-[13px] hover:bg-[#2A2D36] transition-colors">
              Severity: All
              <svg width="8" height="5" viewBox="0 0 8 5" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M1 1L4 4L7 1" stroke="#4B5563" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
            <button className="flex items-center px-[14px] py-[6px] gap-2 bg-[#1E1E1E] border border-[#323232] rounded-[10px] text-white text-[13px] hover:bg-[#2A2D36] transition-colors">
              Status: All
              <svg width="8" height="5" viewBox="0 0 8 5" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M1 1L4 4L7 1" stroke="#4B5563" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* Policies List */}
      <div className="flex-1 w-full relative min-h-0">
        <div className="flex flex-col items-start w-full custom-scrollbar overscroll-contain" style={{ height: "50vh", overflow: "scroll" }}>
          {policies.map(policy => (
            <PolicyRow
              key={policy.id}
              policyId={policy.policyId}
              title={policy.title}
              description={policy.description}
              severity={policy.severity}
              enabled={policy.enabled}
              onToggle={() => handleToggle(policy.id)}
            />
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="box-border flex flex-row justify-between items-center px-5 py-4 w-full border-t border-[#1E2028] bg-[#141414] mt-auto">
        <div className="flex items-center gap-2">
          <div className="w-[5px] h-[5px] bg-[#00D3F3] rounded-full shadow-[0_0_8px_rgba(0,211,243,0.8)] animate-pulse"></div>
          <span className="text-[13px] text-[#646464]"><span className="text-white font-medium">1</span> unsaved change</span>
        </div>
        <div className="flex items-center gap-3">
          <button className="px-4 py-2 bg-transparent hover:bg-[#1E1E1E] border border-[#323232] rounded-[8px] text-white text-[13px] font-medium transition-colors cursor-pointer">Discard</button>
          <button className="px-4 py-2 bg-[#00D3F3] hover:bg-[#00E5FF] border border-[rgba(0,184,219,0.5)] rounded-[8px] text-[#141414] text-[13px] font-medium transition-colors cursor-pointer shadow-[0_0_10px_rgba(0,211,243,0.3)]">Save preferences</button>
        </div>
      </div>
    </div>
  );
};

export default PolicyMainArea;
