import React from 'react';
import BarChartUI from "@/components/charts/BarChartUI";
import PieChartUI from "@/components/charts/PieChartUI";
import HorizontalBarChart3D from '@/components/charts/HorizontalBarChart3D';
import IssuesBySeverityCard from "../shared/IssuesBySeverityCard";

const DashboardCharts = ({
  severityData,
  issuesByTypeData,
  terraformAwsCount = 0,
  terraformAzureCount = 0,
  terraformGcpCount = 0
}) => {
  // Prepare provider distribution data for bar chart
  const providerData = [
    {
      name: "AWS",
      value: terraformAwsCount,
      color: "var(--high)"
    },
    {
      name: "Azure",
      value: terraformAzureCount,
      color: "var(--info)"
    },
    {
      name: "GCP",
      value: terraformGcpCount,
      color: "var(--success)"
    }
  ].filter(item => item.value > 0);

  return (
    <div className="flex flex-wrap gap-6">
      {/* Severity Distribution - Overview Style */}
      <IssuesBySeverityCard
        severityData={severityData}
        title="Issues by Severity"
        className="flex-1 min-w-[300px]"
      />

      {/* Issues by IaC Type - Bar Chart */}
      <div className="flex-1 min-w-[300px] rounded-2xl border border-default bg-[var(--surface)] p-6 shadow-2 transition-fast">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-text">Issues by IaC Type</h3>
          <p className="text-xs text-muted mt-1">Distribution across Docker, K8s, and Terraform</p>
        </div>
        <div className="flex items-center justify-center">
          <HorizontalBarChart3D
            data={issuesByTypeData.map(item => ({
              name: item.name,
              value: item.issues,
              color: item.color,
            }))}
          />
        </div>
        <div className="flex flex-wrap justify-center gap-4 mt-4 text-xs text-muted">
          <span>Docker: {issuesByTypeData.find(d => d.name === "Docker")?.issues || 0}</span>
          <span>K8s: {issuesByTypeData.find(d => d.name === "Kubernetes")?.issues || 0}</span>
          <span>Terraform: {issuesByTypeData.find(d => d.name === "Terraform")?.issues || 0}</span>
        </div>
      </div>

      {/* Provider Distribution - Bar Chart */}
      {providerData.length > 0 && (
        <div className="flex-1 min-w-[300px] rounded-2xl border border-default bg-[var(--surface)] p-6 shadow-2 transition-fast">
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-text">Terraform Provider Distribution</h3>
            <p className="text-xs text-muted mt-1">Security issues across cloud providers</p>
          </div>
          <div className="flex items-center justify-center">
            <HorizontalBarChart3D data={providerData} />
          </div>
        </div>
      )}
    </div>
  );
};

export default DashboardCharts;