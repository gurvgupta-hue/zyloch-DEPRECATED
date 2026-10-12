// components/dashboard/SeverityTabs.jsx
import React from 'react';
import { getSeverityIcon } from '../shared/severityVisuals';

const SeverityTabs = ({ activeTab, setActiveTab, summary }) => {
  const tabs = [
    { id: 'all', label: 'All Issues', count: summary.totalIssues },
    { id: 'critical', label: 'Critical', count: summary.bySeverity.critical, icon: getSeverityIcon('critical'), color: 'bg-critical' },
    { id: 'high', label: 'High', count: summary.bySeverity.high, icon: getSeverityIcon('high'), color: 'bg-high' },
    { id: 'medium', label: 'Medium', count: summary.bySeverity.medium, icon: getSeverityIcon('medium'), color: 'bg-medium' },
    { id: 'low', label: 'Low', count: summary.bySeverity.low, icon: getSeverityIcon('low'), color: 'bg-low' },
  ];

  return (
    <div className="flex gap-2 mb-6 border-b border-default pb-4 overflow-x-auto">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => setActiveTab(tab.id)}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-fast flex items-center gap-1 whitespace-nowrap ${activeTab === tab.id
              ? tab.id === 'all'
                ? 'bg-primary text-on-primary'
                : `${tab.color} text-on-primary`
              : 'text-muted hover:text-text'
            }`}
        >
          {tab.icon && <tab.icon className="w-4 h-4" />}
          {tab.label} ({tab.count})
        </button>
      ))}
    </div>
  );
};

export default SeverityTabs;