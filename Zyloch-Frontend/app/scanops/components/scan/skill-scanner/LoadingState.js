// components/dashboard/LoadingState.jsx
import React from 'react';

const LoadingState = () => (
  <div className="flex h-full min-h-[350px] items-center justify-center p-8">
    <div className="text-center">
      <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-[var(--color-primary)] mx-auto mb-4"></div>
      <p className="text-sm text-[var(--muted)] font-medium">Loading scan data...</p>
    </div>
  </div>
);

export default LoadingState;