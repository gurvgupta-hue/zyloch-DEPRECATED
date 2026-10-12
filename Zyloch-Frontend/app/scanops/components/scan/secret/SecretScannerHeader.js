import React from "react";
import ScanMetadataOverview from "../shared/ScanMetadataOverview";

const SecretScannerHeader = ({ scanMetadata, scanDuration }) => {
  return (
    <ScanMetadataOverview
      scanMetadata={scanMetadata}
      scanType="Secret Scanner"
      duration={scanDuration}
    />
  );
};

export default SecretScannerHeader;