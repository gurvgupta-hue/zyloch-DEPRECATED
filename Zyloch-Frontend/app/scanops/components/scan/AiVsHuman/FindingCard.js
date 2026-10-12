import { motion } from "framer-motion";
import { AnimatePresence } from "framer-motion";
import { Brain, User } from "lucide-react";
import DetailSection from "./DetailSection";

const FindingCard = ({ finding, isOpen, onToggle }) => {
  const confidencePercent = Math.round(finding.confidence * 100);
  const isPredictionAI = finding.prediction === 'ai';

  return (
    <div className="border border-border rounded-xl bg-elevated-surface">
      {/* Card Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-5 hover:bg-surface/50 transition-all duration-200 rounded-xl focus-ring"
      >
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg" style={{
            backgroundColor: isPredictionAI
              ? 'color-mix(in srgb, var(--warning) 10%, transparent)'
              : 'color-mix(in srgb, var(--success) 10%, transparent)'
          }}>
            {isPredictionAI ? (
              <Brain className="w-5 h-5" style={{ color: 'var(--warning)' }} />
            ) : (
              <User className="w-5 h-5" style={{ color: 'var(--success)' }} />
            )}
          </div>

          <div className="text-left">
            <h4 className="font-semibold text-text">
              {finding.file?.split('/').pop()}
            </h4>
            <p className="text-xs text-muted mt-0.5">
              {finding.file}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="px-3 py-1 text-sm font-medium rounded-full" style={{
            backgroundColor: isPredictionAI
              ? 'color-mix(in srgb, var(--warning) 10%, transparent)'
              : 'color-mix(in srgb, var(--success) 10%, transparent)',
            border: `1px solid ${isPredictionAI ? 'var(--warning)' : 'var(--success)'}30`,
            color: isPredictionAI ? 'var(--warning)' : 'var(--success)',
            textTransform: 'capitalize'
          }}>
            {finding.prediction}
          </span>

          <span className="px-3 py-1 text-sm font-medium rounded-full" style={{
            backgroundColor: `color-mix(in srgb, var(--info) 10%, transparent)`,
            border: '1px solid var(--info)30',
            color: 'var(--info)'
          }}>
            {confidencePercent}%
          </span>

          <motion.div
            animate={{ rotate: isOpen ? 180 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <svg 
              width="20" 
              height="20" 
              viewBox="0 0 24 24" 
              fill="none" 
              stroke="currentColor" 
              className="text-muted"
            >
              <path d="M6 9l6 6 6-6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </motion.div>
        </div>
      </button>

      {/* Card Expanded Content */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden"
          >
            <div className="p-5 border-t border-border space-y-4 bg-surface">
              <DetailSection label="Description" value={finding.description} />
              <DetailSection label="Policy" value={finding.policy} />
              
              <div className="flex gap-4">
                <DetailSection label="Start Line" value={finding.start_line} />
                <DetailSection label="End Line" value={finding.end_line} />
              </div>

              <DetailSection label="Severity">
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    padding: '2px 10px',
                    backgroundColor: `color-mix(in srgb, var(--info) 10%, transparent)`,
                    borderRadius: 'var(--radius-full)',
                    border: `1px solid color-mix(in srgb, var(--info) 30%, transparent)`,
                    color: 'var(--info)',
                    fontSize: 'var(--font-size-xs)',
                    fontWeight: 'var(--weight-medium)',
                    textTransform: 'capitalize'
                  }}
                >
                  {finding.severity}
                </span>
              </DetailSection>

              <div className="space-y-2">
                <p className="text-sm font-medium text-muted">Confidence Score</p>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 rounded-full" style={{ backgroundColor: 'var(--border)' }}>
                    <div 
                      className="h-full rounded-full"
                      style={{ 
                        width: `${confidencePercent}%`,
                        backgroundColor: 'var(--info)'
                      }}
                    />
                  </div>
                  <span className="text-sm font-medium text-info">{confidencePercent}%</span>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default FindingCard;
