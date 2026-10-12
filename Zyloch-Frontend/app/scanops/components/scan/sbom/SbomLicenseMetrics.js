import React from "react";
import MetricBar from "./MetricBar";
import styles from "./Sbom.module.css";

const SbomLicenseMetrics = React.memo(({ licenseTypes, totalPackages }) => {
  const metricColors = [
    "var(--color-primary)",
    "var(--info)",
    "var(--color-accent)",
    "var(--color-secondary)"
  ];

  return (
    <article className={styles.metricsCard}>
      <h3>License Metrics</h3>
      <p className="mb-4 text-xs text-[var(--muted)]">Top license categories by package share</p>
      <div className={styles.metricsGrid}>
        {licenseTypes.slice(0, 4).map((item, idx) => {
          const percentage = totalPackages > 0 ? Math.round((item.value / totalPackages) * 100) : 0;
          return (
            <MetricBar
              key={idx}
              label={item.name}
              percentage={percentage}
              color={metricColors[idx % metricColors.length]}
            />
          );
        })}
      </div>
    </article>
  );
});

export default SbomLicenseMetrics;
