import React from "react";
import PieChartUI from "@/components/charts/PieChartUI";
import BarChartUI from "@/components/charts/BarChartUI";
import styles from "./Sbom.module.css";

const SbomRiskCharts = React.memo(({ licenseTypes, packageManagers }) => (
  <section className={styles.chartGrid}>
    <article className={styles.panelCard}>
      <h3>License Distribution</h3>
      <p className="mb-3 text-xs text-[var(--muted)]">Distribution of dependency licenses by category</p>
      {licenseTypes.length > 0 ? (
        <PieChartUI data={licenseTypes} hideLegend={false} />
      ) : (
        <div className={styles.chartLoading}>No license data</div>
      )}
    </article>

    <article className={styles.panelCard}>
      <h3>Package Managers</h3>
      <p className="mb-3 text-xs text-[var(--muted)]">Dependency counts by package manager and ecosystem</p>
      {packageManagers.length > 0 ? (
        <BarChartUI data={packageManagers} showLegend={false} barSize={32} />
      ) : (
        <div className={styles.chartLoading}>No package manager data</div>
      )}
    </article>
  </section>
));

export default SbomRiskCharts;
