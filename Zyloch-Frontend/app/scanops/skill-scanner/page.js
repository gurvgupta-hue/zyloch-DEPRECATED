import React from 'react';
import dynamic from 'next/dynamic';

const SkillScannerDashboard = dynamic(() => import('./skill-scanner-scan-dashboard'), {
  loading: () => (
    <div className="flex min-h-[40vh] items-center justify-center text-sm text-muted">
      Loading AI Security Scanner dashboard...
    </div>
  ),
});

const Page = () => {
  return (
    <SkillScannerDashboard />
  );
};

export default Page;