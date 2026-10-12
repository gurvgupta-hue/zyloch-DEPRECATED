import { FileText, Shield, GitBranch, Calendar, User } from "lucide-react";
import SmartTruncate from "@/components/ui/SmartTruncate";
import ScannerIconTile from "../overview/scores/ScannerIconTile";

const WorkflowHeader = ({ scanMetadata, securityScore }) => {
  // Simple color based on score
  const getScoreColor = (score) => {
    if (score >= 90) return "text-green-500";
    if (score >= 70) return "text-yellow-500";
    return "text-red-500";
  };

  const scoreColor = getScoreColor(securityScore);

  return (
    <div 
      className="bg-surface rounded-2xl shadow-2 p-6"
      style={{
        border: "1px solid var(--border)",
        borderLeft: "4px solid var(--color-violet-65, #8B5CF6)",
      }}
    >
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="flex items-center gap-4">
          <ScannerIconTile scannerKey="workflow" size={26} tileSize={52} />
          <div>
            <h1 className="text-2xl font-bold text-text">
              Workflow Security Analysis
            </h1>
            <p className="text-muted mt-1">
              Comprehensive GitHub Actions workflow security assessment
            </p>
          </div>
        </div>

        {/* UPDATED SCORE SECTION - Larger round with text inside */}
        <div className="flex flex-col items-center">
          <div 
            className="w-28 h-28 relative rounded-full p-1"
            style={{
              border: "2px solid var(--color-violet-65, #8B5CF6)",
              background: "linear-gradient(135deg, color-mix(in srgb, var(--color-violet-65) 5%, transparent) 0%, transparent 100%)",
            }}
          >
            {/* Circular gauge */}
            <div className="w-full h-full rounded-full relative">
              {/* Gauge fill */}
              <div
                className="w-full h-full rounded-full"
                style={{
                  background: `conic-gradient(
                    var(--color-violet-65) ${securityScore}%, 
                    color-mix(in srgb, var(--border) 40%, transparent) 0
                  )`,
                }}
              />
              
              {/* Center content */}
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <div className={`text-2xl font-bold ${scoreColor}`}>
                  {Math.round(securityScore)}
                </div>
                <p 
                  className="text-xs font-medium mt-0.5"
                  style={{ color: "var(--color-violet-65)" }}
                >
                  Security Score
                </p>
              </div>
            </div>

            {/* Score indicator */}
            <div
              className="absolute w-2 h-2 rounded-full shadow-md top-0 left-1/2"
              style={{
                backgroundColor: "var(--color-violet-65)",
                transform: `translateX(-50%) rotate(${securityScore * 3.6 - 90}deg) translateY(50px)`,
                transformOrigin: "center 14px",
              }}
            />
          </div>
        </div>
      </div>

      {/* METADATA GRID */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-6 pt-6 ">
        <MetadataItem
          icon={FileText}
          label="Repository"
          value={scanMetadata.repository}
        />
        <MetadataItem
          icon={GitBranch}
          label="Branch"
          value={scanMetadata.branch}
        />
        <MetadataItem
          icon={User}
          label="Author"
          value={scanMetadata.commit_author}
        />
        <MetadataItem
          icon={Calendar}
          label="Scan Date"
          value={new Date(scanMetadata.scan_timestamp).toLocaleDateString()}
        />
      </div>
    </div>
  );
};

// MetadataItem component - with violet accent border
const MetadataItem = ({ icon: Icon, label, value }) => (
  <div
    className="flex flex-col p-3 rounded-lg hover:shadow-1 transition-all duration-300 relative"
    style={{
      background: "var(--elevated-surface)",
      border: "1px solid var(--border)",
      borderLeft: "3px solid var(--color-violet-65, #8B5CF6)",
    }}
  >
    <div className="flex items-center gap-2 mb-2">
      <div
        className="p-1.5 rounded-md transition-transform duration-300"
        style={{
          background: "color-mix(in srgb, var(--color-violet-65) 10%, transparent)",
        }}
      >
        <Icon className="w-4 h-4" style={{ color: "var(--color-violet-65)" }} />
      </div>
      <span className="text-xs font-medium" style={{ color: "var(--muted)" }}>
        {label}
      </span>
    </div>
    <div className="min-w-0">
      <SmartTruncate
        text={value}
        threshold={25}
        showIcon={false}
        className="text-base font-semibold leading-tight"
        style={{ color: "var(--text)" }}
      />
    </div>
  </div>
);

export default WorkflowHeader;