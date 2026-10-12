// components/dashboard/ProviderCard.jsx
import React from 'react';

const ProviderCard = ({ provider, count, color }) => (
  <div className="bg-elevated rounded-lg p-3 border border-default">
    <div className="flex items-center justify-between">
      <span className="text-sm font-medium text-text">{provider}</span>
      <span className="text-lg font-bold" style={{ color }}>{count}</span>
    </div>
  </div>
);

export default ProviderCard;