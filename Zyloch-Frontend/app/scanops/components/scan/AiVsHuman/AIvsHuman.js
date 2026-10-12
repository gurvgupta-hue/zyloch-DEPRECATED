"use client";

import React, { useMemo } from "react";
import aivshumandemo from "@/data/aivshuman.json";
import AIvsHumanHeader from "./AIvsHumanHeader";
import StatsSummary from "./StatsSummary";
import FindingsList from "./FindingsList";
import SecurityScoreCard from "../shared/SecurityScoreCard";

const AIvsHuman = () => {
  const scanData = aivshumandemo;
  const aiCheckResults = scanData.per_scanner_results?.ai_check;
  const findings = aiCheckResults?.findings || [];
  const metadata = aiCheckResults?.metadata;

  // Calculate stats
  const stats = useMemo(() => {
    const aiCount = findings.filter(f => f.prediction === 'ai').length;
    const humanCount = findings.filter(f => f.prediction === 'human').length;
    
    return {
      aiCount,
      humanCount,
      totalFiles: metadata?.total_files || 0,
    };
  }, [findings, metadata]);

  const authenticityScore = stats.totalFiles > 0
    ? Math.round(((stats.totalFiles - stats.aiCount) / stats.totalFiles) * 100)
    : 100;

  return (
    <div className="relative overflow-x-hidden min-h-screen">
      <main className="relative z-[1] p-4 sm:p-6 flex flex-col gap-6 min-h-screen">
        <AIvsHumanHeader scanData={scanData} stats={stats} />
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">
          <SecurityScoreCard score={authenticityScore} title="Authenticity Score" subtitle="Human-written code confidence ratio" />
          <div className="lg:col-span-2 flex flex-col justify-center">
            <StatsSummary stats={stats} />
          </div>
        </div>

        <FindingsList findings={findings} />
      </main>
    </div>
  );
};

export default AIvsHuman;