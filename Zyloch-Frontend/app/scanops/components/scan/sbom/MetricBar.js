import React from "react";
import styles from "./Sbom.module.css";

const MetricBar = React.memo(({ label, percentage, color }) => (
  <div className={styles.metricBar}>
    <div className={styles.metricBarHead}>
      <span className={styles.metricBarLabel}>{label}</span>
      <span className={styles.metricBarValue}>{percentage}%</span>
    </div>
    <div className={styles.metricBarTrack}>
      <div
        className={styles.metricBarFill}
        style={{ width: `${percentage}%`, background: color }}
      ></div>
    </div>
  </div>
));

export default MetricBar;
