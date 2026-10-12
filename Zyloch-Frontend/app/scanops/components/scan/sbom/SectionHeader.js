import React from "react";

const SectionHeader = React.memo(({ title, subtitle, icon }) => (
  <div
    className="flex flex-col items-start w-full rounded-[16px] border border-[var(--border)] overflow-hidden"
    style={{
      padding: "24px",
      gap: "8px",
      background: "var(--bg)",
      alignSelf: "stretch",
      height: "120px"
    }}
  >
    <div className="flex flex-row items-center p-0 gap-[12px] h-[44px]">
      <div
        className="flex flex-col items-center justify-center p-[10px] w-[44px] h-[44px] rounded-[12px] border border-[var(--border)]"
        style={{ background: "var(--surface)" }}
      >
        {icon}
      </div>
      <div className="flex flex-col items-start p-0">
        <h1
          className="whitespace-nowrap font-bold text-[22.7px] leading-[32px] font-sans text-[var(--text)] flex items-center"
        >
          {title}
        </h1>
      </div>
    </div>
    <div className="flex flex-col items-start p-0 w-full h-[20px]">
      <p className="font-normal text-[13.6px] leading-[20px] font-sans text-[var(--muted)] flex items-center">
        {subtitle}
      </p>
    </div>
  </div>
));

export default SectionHeader;
