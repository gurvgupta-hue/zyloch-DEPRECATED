// components/dashboard/StatusCard.jsx
import React from 'react';

const StatusCard = ({ label, status, filesScanned, findings }) => {
  const getStatusColor = (status) => {
    return status === "completed" ? "text-success" : "text-warning";
  };

  return (
    <div className="bg-surface rounded-lg shadow-2 p-4 border border-default">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-text">{label}</span>
        <span className={`text-xs ${getStatusColor(status)}`}>
          {status || "pending"}
        </span>
      </div>
      <div className="flex justify-between text-xs text-muted">
        <span>Files: {filesScanned || 0}</span>
        <span>Issues: {findings}</span>
      </div>
    </div>
  );
};

export default StatusCard;