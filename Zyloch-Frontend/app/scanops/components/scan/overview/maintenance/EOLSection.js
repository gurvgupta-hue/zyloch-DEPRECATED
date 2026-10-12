import React from "react";
import {
  Calendar,
  Cpu,
  ShieldCheck,
  Coffee,
  Code2,
  Boxes,
  Activity,
  Layers,
  ExternalLink,
  CloudCog,
  ArrowRight,
  Tag,
  Server,
} from "lucide-react";
import { formatApiText } from "../utils";
import { OVERVIEW_CARD_STYLE, OVERVIEW_DS, OVERVIEW_EYEBROW_STYLE } from "../designSystem";

const getTechIcon = (name) => {
  const n = (name || "").toLowerCase();
  if (n.includes("java")) return <Coffee className="w-[18px] h-[18px]" />;
  if (n === "go" || n.includes("golang")) return <Code2 className="w-[18px] h-[18px]" />;
  if (n.includes("gradle")) return <Boxes className="w-[18px] h-[18px]" />;
  if (n.includes("maven")) return <Layers className="w-[18px] h-[18px]" />;
  if (n.includes("terraform")) return <CloudCog className="w-[18px] h-[18px]" />;
  return <Cpu className="w-[18px] h-[18px]" />;
};

const StatusBadge = ({ isRisk, riskLabel, okLabel }) => {
  const color = isRisk ? "var(--warning)" : "var(--success)";
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full"
      style={{
        background: `color-mix(in srgb, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 28%, transparent)`,
        color,
      }}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full shrink-0 ${isRisk ? "animate-pulse" : ""}`}
        style={{ background: color }}
      />
      <span
        style={{
          fontSize: OVERVIEW_DS.typography.micro,
          fontWeight: 800,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
        }}
      >
        {isRisk ? riskLabel : okLabel}
      </span>
    </span>
  );
};

const MetaChip = ({ label, value, icon: Icon }) => (
  <div className="flex flex-col gap-0.5">
    <span
      className="text-[var(--muted)] opacity-70 uppercase"
      style={{ ...OVERVIEW_EYEBROW_STYLE, fontSize: "9px", letterSpacing: "0.1em" }}
    >
      {label}
    </span>
    <div className="flex items-center gap-1">
      {Icon && <Icon className="w-3 h-3 text-[var(--muted)] opacity-50 shrink-0" />}
      <span
        className="font-semibold text-[var(--text)]"
        style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.label }}
      >
        {value || "\u2014"}
      </span>
    </div>
  </div>
);

const VersionPill = ({ version, highlight, color }) => (
  <span
    className="font-mono rounded-md px-2 py-0.5 border whitespace-nowrap"
    style={{
      fontSize: OVERVIEW_DS.typography.label,
      background: highlight
        ? `color-mix(in srgb, ${color} 10%, transparent)`
        : "rgba(128,128,128,0.06)",
      borderColor: highlight
        ? `color-mix(in srgb, ${color} 30%, transparent)`
        : "var(--border)",
      color: highlight ? color : "var(--text)",
    }}
  >
    {version || "\u2014"}
  </span>
);

const MaintenanceRow = ({ name, data }) => {
  if (!data) return null;
  const isEol = data.status?.toLowerCase() === "eol";
  const statusColor = isEol ? "var(--warning)" : "var(--success)";

  return (
    <div className="group p-4 md:p-5 border border-[var(--border)] rounded-xl mb-3 last:mb-0 hover:bg-[var(--text)]/[0.015] transition-all bg-[var(--surface)]">
      <div className="flex items-center gap-4 min-w-0">
        <div
          className="p-2.5 rounded-xl shrink-0 transition-transform duration-200 group-hover:scale-105"
          style={{
            background: `color-mix(in srgb, ${statusColor} 10%, transparent)`,
            border: `1px solid color-mix(in srgb, ${statusColor} 22%, transparent)`,
            color: statusColor,
          }}
        >
          {getTechIcon(name)}
        </div>

        <div className="flex flex-col gap-0.5 min-w-0 w-[110px] shrink-0">
          <span
            className="font-semibold text-[var(--text)] truncate leading-tight"
            style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.body }}
          >
            {formatApiText(data.product || name)}
          </span>
          <span
            className="text-[var(--muted)] opacity-60"
            style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.micro }}
          >
            runtime
          </span>
        </div>

        <div className="hidden sm:flex items-center gap-2 shrink-0">
          <VersionPill version={`v${data.current_version || data.cycle || "?"}`} />
          <ArrowRight className="w-3 h-3 text-[var(--muted)] opacity-40 shrink-0" />
          <VersionPill version={`v${data.latest || "?"}`} highlight color={statusColor} />
        </div>

        <div className="flex-1" />

        <div className="hidden md:flex items-center gap-6 shrink-0">
          <MetaChip label="EOL Date" value={data.eol || "Perpetual"} icon={Calendar} />
          <MetaChip
            label="LTS"
            value={data.lts === true ? "Yes" : data.lts === false ? "No" : "\u2014"}
            icon={ShieldCheck}
          />
        </div>

        <div className="shrink-0">
          <StatusBadge isRisk={isEol} riskLabel="End of Life" okLabel="Supported" />
        </div>
      </div>

      <div className="sm:hidden flex items-center gap-3 mt-3 pl-[52px] flex-wrap">
        <VersionPill version={`v${data.current_version || data.cycle || "?"}`} />
        <ArrowRight className="w-3 h-3 text-[var(--muted)] opacity-40" />
        <VersionPill version={`v${data.latest || "?"}`} highlight color={statusColor} />
        <span className="text-[var(--muted)] opacity-60 ml-1" style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: "10px" }}>
          EOL: {data.eol || "Perpetual"}
        </span>
      </div>

      {data.source_files?.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-3 pl-[52px]">
          {data.source_files.map((f) => (
            <span
              key={f}
              className="inline-flex items-center gap-1 font-mono px-2 py-0.5 rounded border border-[var(--border)] text-[var(--muted)] bg-[var(--text)]/[0.03] truncate max-w-[280px]"
              style={{ fontSize: "10px" }}
              title={f}
            >
              <Tag className="w-2.5 h-2.5 opacity-50 shrink-0" />
              {f}
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

const ProviderRow = ({ name, data }) => {
  if (!data) return null;
  const isOutdated = data.status?.toLowerCase() === "outdated";
  const statusColor = isOutdated ? "var(--warning)" : "var(--success)";

  return (
    <div className="group p-4 md:p-5 border border-[var(--border)] rounded-xl mb-3 last:mb-0 hover:bg-[var(--text)]/[0.015] transition-all bg-[var(--surface)]">
      <div className="flex items-center gap-4 min-w-0">
        <div
          className="p-2.5 rounded-xl shrink-0 transition-transform duration-200 group-hover:scale-105"
          style={{
            background: `color-mix(in srgb, ${statusColor} 10%, transparent)`,
            border: `1px solid color-mix(in srgb, ${statusColor} 22%, transparent)`,
            color: statusColor,
          }}
        >
          <CloudCog className="w-[18px] h-[18px]" />
        </div>

        <div className="flex flex-col gap-0.5 min-w-0 w-[110px] shrink-0">
          <span
            className="font-semibold text-[var(--text)] truncate leading-tight"
            style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.body }}
          >
            {formatApiText(data.product || name)}
          </span>
          <span
            className="text-[var(--muted)] opacity-60 truncate"
            style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.micro }}
          >
            {data.cloudProvider || data.providerSource || "AWS"}
          </span>
        </div>

        <div className="hidden sm:flex items-center gap-2 shrink-0">
          <VersionPill version={`v${data.current_version || "?"}`} />
          <ArrowRight className="w-3 h-3 text-[var(--muted)] opacity-40 shrink-0" />
          <VersionPill version={`v${data.latest || "?"}`} highlight color={statusColor} />
        </div>

        <div className="flex-1" />

        {data.registryUrl && (
          <div className="hidden md:block shrink-0 mr-2">
            <a
              href={data.registryUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 hover:opacity-70 transition-opacity"
              style={{
                color: "var(--color-primary)",
                fontFamily: OVERVIEW_DS.typography.family,
                fontSize: OVERVIEW_DS.typography.label,
                fontWeight: 700,
              }}
            >
              <ExternalLink className="w-3 h-3" />
              Docs
            </a>
          </div>
        )}

        <div className="shrink-0">
          <StatusBadge isRisk={isOutdated} riskLabel="Outdated" okLabel="Current" />
        </div>
      </div>

      <div className="sm:hidden flex items-center gap-3 mt-3 pl-[52px] flex-wrap">
        <VersionPill version={`v${data.current_version || "?"}`} />
        <ArrowRight className="w-3 h-3 text-[var(--muted)] opacity-40" />
        <VersionPill version={`v${data.latest || "?"}`} highlight color={statusColor} />
      </div>

      {data.source_files?.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-3 pl-[52px]">
          {data.source_files.map((f) => (
            <span
              key={f}
              className="inline-flex items-center gap-1 font-mono px-2 py-0.5 rounded border border-[var(--border)] text-[var(--muted)] bg-[var(--text)]/[0.03] truncate max-w-[280px]"
              style={{ fontSize: "10px" }}
              title={f}
            >
              <Tag className="w-2.5 h-2.5 opacity-50 shrink-0" />
              {f}
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

/**
 * Row for a Kubernetes deprecated API entry.
 * data shape (from backend metadata.k8s_deprecated values):
 *   { kind, deprecated_version, replacement_version, removed_in, since, source_files }
 */
const DeprecatedAPIRow = ({ name, data }) => {
  if (!data) return null;
  const statusColor = "var(--warning)";

  return (
    <div className="group py-4 px-1 border-b border-[var(--border)] last:border-0 hover:bg-[var(--text)]/[0.015] transition-colors rounded-lg">
      <div className="flex items-center gap-4 min-w-0">
        <div
          className="p-2 rounded-xl shrink-0 transition-transform duration-200 group-hover:scale-110"
          style={{
            background: `color-mix(in srgb, ${statusColor} 10%, transparent)`,
            border: `1px solid color-mix(in srgb, ${statusColor} 22%, transparent)`,
            color: statusColor,
          }}
        >
          <Server className="w-[18px] h-[18px]" />
        </div>

        <div className="flex flex-col gap-0.5 min-w-0 w-[110px] shrink-0">
          <span
            className="font-bold text-[var(--text)] truncate leading-tight"
            style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.body }}
          >
            {data.kind || name}
          </span>
          <span
            className="text-[var(--muted)] opacity-60"
            style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.micro }}
          >
            kubernetes api
          </span>
        </div>

        {/* apiVersion: deprecated → replacement (no v prefix — these are API group strings) */}
        <div className="hidden sm:flex items-center gap-2 shrink-0 min-w-0 max-w-[400px]">
          <VersionPill version={data.deprecated_version || "?"} />
          <ArrowRight className="w-3 h-3 text-[var(--muted)] opacity-40 shrink-0" />
          <VersionPill version={data.replacement_version || "?"} highlight color={statusColor} />
        </div>

        <div className="flex-1" />

        <div className="hidden md:flex items-center gap-6 shrink-0">
          <MetaChip label="Removed In" value={`K8s ${data.removed_in || "?"}`} icon={Calendar} />
          <MetaChip label="Since" value={`K8s ${data.since || "?"}`} icon={ShieldCheck} />
        </div>

        <div className="shrink-0">
          <StatusBadge isRisk={true} riskLabel="Deprecated" okLabel="Current" />
        </div>
      </div>

      {/* Mobile: versions stacked below */}
      <div className="sm:hidden flex flex-col gap-2 mt-3 pl-[52px]">
        <div className="flex items-center gap-3 flex-wrap">
          <VersionPill version={data.deprecated_version || "?"} />
          <ArrowRight className="w-3 h-3 text-[var(--muted)] opacity-40" />
          <VersionPill version={data.replacement_version || "?"} highlight color={statusColor} />
        </div>
        <span
          className="text-[var(--muted)] opacity-60"
          style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: "10px" }}
        >
          Removed in K8s {data.removed_in || "?"}
        </span>
      </div>

      {data.source_files?.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-3 pl-[52px]">
          {data.source_files.map((f) => (
            <span
              key={f}
              className="inline-flex items-center gap-1 font-mono px-2 py-0.5 rounded border border-[var(--border)] text-[var(--muted)] bg-[var(--text)]/[0.03] truncate max-w-[280px]"
              style={{ fontSize: "10px" }}
              title={f}
            >
              <Tag className="w-2.5 h-2.5 opacity-50 shrink-0" />
              {f}
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

const SectionDivider = ({ label }) => (
  <div className="flex items-center gap-3 py-2">
    <div className="h-px flex-1 bg-[var(--border)]" />
    <span style={{ ...OVERVIEW_EYEBROW_STYLE, opacity: 0.45, fontSize: "9px" }}>{label}</span>
    <div className="h-px flex-1 bg-[var(--border)]" />
  </div>
);

const EOLSection = ({ eolData, terraformProviders, k8sDeprecated }) => {
  const activeEol =
    eolData && typeof eolData === "object"
      ? Object.entries(eolData).filter(([, val]) => val !== null && typeof val === "object")
      : [];

  const activeProviders =
    terraformProviders && typeof terraformProviders === "object"
      ? Object.entries(terraformProviders).filter(([, val]) => val !== null && typeof val === "object")
      : [];

  const activeK8sDeprecated =
    k8sDeprecated && typeof k8sDeprecated === "object"
      ? Object.entries(k8sDeprecated).filter(([, val]) => val !== null && typeof val === "object")
      : [];

  const hasAny = activeEol.length > 0 || activeProviders.length > 0 || activeK8sDeprecated.length > 0;

  return (
    <div
      style={{
        ...OVERVIEW_CARD_STYLE,
        padding: OVERVIEW_DS.spacing.x3,
        display: "flex",
        flexDirection: "column",
        gap: OVERVIEW_DS.spacing.x2,
      }}
      className="transition-all duration-300 hover:translate-y-[-2px] hover:shadow-xl"
    >
      <div className="flex items-start justify-between">
        <div className="flex flex-col gap-0.5">
          <h4 style={OVERVIEW_EYEBROW_STYLE}>Technology Maintenance Track</h4>
          <span
            style={{
              fontFamily: OVERVIEW_DS.typography.family,
              fontSize: OVERVIEW_DS.typography.label,
              color: "var(--muted)",
              opacity: 0.8,
              lineHeight: "18px",
            }}
          >
            Lifecycle monitoring for project stack and runtimes
          </span>
        </div>
        <Activity className="w-4 h-4 text-[var(--muted)] opacity-40 mt-0.5 shrink-0" />
      </div>

      <div className="h-px w-full bg-[var(--border)]" />

      {hasAny ? (
        <div className="flex flex-col">
          {activeEol.length > 0 && (
            <>
              {(activeProviders.length > 0 || activeK8sDeprecated.length > 0) && (
                <SectionDivider label="Runtimes" />
              )}
              {activeEol.map(([name, data]) => (
                <MaintenanceRow key={name} name={name} data={data} />
              ))}
            </>
          )}
          {activeProviders.length > 0 && (
            <>
              {(activeEol.length > 0 || activeK8sDeprecated.length > 0) && (
                <SectionDivider label="Terraform Providers" />
              )}
              {activeProviders.map(([name, data]) => (
                <ProviderRow key={name} name={name} data={data} />
              ))}
            </>
          )}
          {activeK8sDeprecated.length > 0 && (
            <>
              {(activeEol.length > 0 || activeProviders.length > 0) && (
                <SectionDivider label="Kubernetes Deprecated APIs" />
              )}
              {activeK8sDeprecated.map(([name, data]) => (
                <DeprecatedAPIRow key={name} name={name} data={data} />
              ))}
            </>
          )}
        </div>
      ) : (
        <div className="py-10 flex flex-col items-center justify-center border border-dashed border-[var(--border)] rounded-xl bg-[var(--text)]/[0.01]">
          <Activity className="w-7 h-7 text-[var(--muted)] opacity-20 mb-3" />
          <p style={{ ...OVERVIEW_EYEBROW_STYLE, opacity: 0.4 }}>Insights Pending</p>
          <p
            className="text-[var(--muted)] opacity-40 mt-1 text-center"
            style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.micro }}
          >
            No supported runtimes detected in this repository
          </p>
        </div>
      )}
    </div>
  );
};

export default EOLSection;
