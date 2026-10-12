import React from 'react';

const SidebarItem = ({ icon, label, count, active, color }) => {
  return (
    <button className={`box-border flex flex-row items-center py-[6px] px-[11px] gap-2 w-full h-[36px] transition-colors ${active ? 'bg-[#1E2028] rounded-md' : 'bg-transparent hover:bg-[#1A1A1A] rounded-md'}`}>
      <div className="flex justify-center items-center w-6 h-6 rounded-md" style={{ backgroundColor: `${color}15` }}>
        {icon}
      </div>
      <div className={`flex-1 text-left font-medium text-[15px] leading-[18px] ${active ? 'text-white' : 'text-[#9CA3AF]'}`}>
        {label}
      </div>
      <div className="font-medium text-[10px] leading-[15px] text-[#6B7280]">
        {count}
      </div>
    </button>
  );
}

const PolicySidebar = () => {
  return (
    <div className="box-border flex flex-col items-start p-0 w-[200px] h-full bg-transparent shrink-0">

      {/* Container - Breadcrumb */}
      <div className="box-border flex flex-col items-start px-[11px] justify-center w-full h-[81.5px] border-b border-[#1E2028]">
        <div className="flex flex-row items-center gap-[6px]">
          {/* Breadcrumb icon/text */}
          <span className="font-medium text-[11px] leading-4 text-[#00D3F3] cursor-pointer hover:underline">Infrastructure as Code › Terraform</span>
        </div>
        <div className="flex flex-col mt-2">
          <div className="font-medium text-[12px] leading-4 text-white">Cloud Providers</div>
          <div className="font-normal text-[10px] leading-[15px] text-[#6B7280] mt-[2px]">Terraform · 249 policies total</div>
        </div>
      </div>

      {/* Navigation */}
      <div className="flex-1 w-full relative min-h-0">
        <div className="absolute inset-0 flex flex-col items-start py-2 px-2 w-full overflow-y-auto custom-scrollbar">
          <div className="flex flex-col items-start w-full gap-1">
            <SidebarItem label="AWS" count="125" color="#F5A623" icon={<div className="w-[13px] h-[13px] border-[1.08px] border-[#F5A623] rounded-[3px]" />} />
            <SidebarItem label="Azure" count="74" color="#5B9BD5" icon={<div className="w-[13px] h-[13px] border-[1.08px] border-[#5B9BD5] rounded-[3px]" />} />
            <SidebarItem label="GCP" count="50" color="#0ABFAD" icon={<div className="w-[13px] h-[13px] border-[1.08px] border-[#0ABFAD] rounded-[3px]" />} />
            <SidebarItem label="Cloud" count="15" active={true} color="#6B7280" icon={<div className="w-[13px] h-[13px] border-[1.08px] border-[#6B7280] rounded-[3px]" />} />
          </div>

          <div className="flex flex-col items-start w-full mt-4 gap-1">
            <div className="px-[11px] py-[4px] w-full">
              <span className="font-normal text-[9px] leading-[14px] tracking-[0.9px] uppercase text-[#646464]">Other Infrastructure as Code</span>
            </div>
            <SidebarItem label="Kubernetes" count="23" color="#9B72CF" icon={<div className="w-[13px] h-[13px] border-[1.08px] border-[#9B72CF] rounded-[3px]" />} />
            <SidebarItem label="Docker" count="26" color="#22D3EE" icon={<div className="w-[13px] h-[13px] border-[1.08px] border-[#22D3EE] rounded-[3px]" />} />
            <SidebarItem label="Ansible" count="8" color="#646464" icon={<div className="w-[13px] h-[13px] border-[1.08px] border-[#646464] rounded-[3px]" />} />
          </div>
        </div>
      </div>

      {/* Workflow Coverage */}
      <div className="box-border flex flex-col items-start p-[12px_11px] w-full h-[72px] border-t border-[#1E2028]">
        <div className="font-normal text-[10px] leading-[15px] text-[#6B7280]">Workflow Coverage</div>
        <div className="flex flex-col items-center mt-[6px] w-full">
          <div className="flex flex-row items-center gap-2 w-full h-[15px]">
            <div className="flex-1 h-[3px] bg-[#1E2028] rounded-[2px] relative overflow-hidden">
              <div className="absolute left-0 top-0 h-[3px] bg-[#00D3F3] rounded-[2px] w-[83%]" />
            </div>
            <div className="font-medium text-[10px] leading-[15px] text-[#00D3F3]">83%</div>
          </div>
        </div>
        <div className="font-normal text-[10px] leading-[15px] text-[#6B7280] mt-1">5 / 6 enabled</div>
      </div>

    </div>
  );
};

export default PolicySidebar;
