import React from "react";
import ScanMetadataOverview from "../shared/ScanMetadataOverview";

const AIvsHumanHeader = ({ scanData }) => {
  const metadata = {
    organization: scanData?.repo_org,
    repository: scanData?.repo_name,
    branch: scanData?.branch || "main",
    commit_message: scanData?.commit_message || (scanData?.scan_id ? `${scanData.scan_id.slice(0, 16)}...` : "N/A"),
    commit_author: scanData?.commit_author || scanData?.author || "N/A",
    scan_type: "AI vs Human",
    event_type: scanData?.event_type || scanData?.status || "Completed",
    scan_timestamp: scanData?.created_at,
  };

  return (
    <ScanMetadataOverview
      scanMetadata={metadata}
      scanType="AI vs Human"
      duration={scanData?.created_at ? new Date(scanData.created_at).toLocaleDateString() : "N/A"}
    />
  );
};

export default AIvsHumanHeader;
