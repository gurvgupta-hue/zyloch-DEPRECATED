"use client";
import React from 'react';
import PolicySidebar from './PolicySidebar';
import PolicyMainArea from './PolicyMainArea';

const PolicyManagement = () => {
  return (
    <div className="flex flex-row items-stretch w-full max-w-[902px] h-[655px] bg-[#141414] border border-[#1E1E1E] rounded-xl overflow-hidden font-sans">
      <PolicySidebar />
      <PolicyMainArea />
    </div>
  );
};

export default PolicyManagement;
