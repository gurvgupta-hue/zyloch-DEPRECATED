"use client";

import React from "react";
import ScanMetadataOverview from "./ScanMetadataOverview";

const ScanHeader = ({ 
  scanMetadata, 
  title = "Repository Overview",
  scanType = null,
  duration = null,
  cards = null,
  className = "",
  style = {},
}) => {
  return (
    <ScanMetadataOverview
      scanMetadata={scanMetadata}
      title={title}
      scanType={scanType}
      duration={duration}
      cards={cards}
      className={className}
      style={style}
    />
  );
};

export default ScanHeader;