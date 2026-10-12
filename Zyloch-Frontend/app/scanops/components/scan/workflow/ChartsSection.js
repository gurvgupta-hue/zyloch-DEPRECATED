import IssuesBySeverityCard from "../shared/IssuesBySeverityCard";
import PieChartUI from "@/components/charts/PieChartUI";

const ChartsSection = ({ severityData, pieChartData, severityCounts }) => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <IssuesBySeverityCard
        severityData={severityData}
        severityCounts={severityCounts}
        title="Issues by Severity"
      />

      <div
        className="rounded-2xl p-6"
        style={{
          background: "var(--surface)",
          borderRadius: "var(--radius-lg)",
          boxShadow: "var(--shadow-2)",
          border: "1px solid var(--border)",
        }}
      >
        <h3 className="text-lg font-semibold text-text mb-4">
          Policy Distribution
        </h3>
        <PieChartUI data={pieChartData} />
      </div>
    </div>
  );
};

export default ChartsSection;
