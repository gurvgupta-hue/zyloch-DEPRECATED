import { FileText, Brain, User, AlertCircle } from "lucide-react";
import SummaryCard from "./SummaryCard";

const StatsSummary = ({ stats }) => (
  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
    <SummaryCard
      label="Files Scanned"
      value={stats.totalFiles}
      icon={FileText}
      color="var(--color-primary)"
    />
    <SummaryCard
      label="AI Generated"
      value={stats.aiCount}
      icon={Brain}
      color="var(--warning)"
    />
    <SummaryCard
      label="Human Written"
      value={stats.totalFiles - stats.aiCount}
      icon={User}
      color="var(--success)"
    />
    <SummaryCard
      label="Confidence"
      value="86.7%"
      icon={AlertCircle}
      color="var(--info)"
    />
  </div>
);

export default StatsSummary;
