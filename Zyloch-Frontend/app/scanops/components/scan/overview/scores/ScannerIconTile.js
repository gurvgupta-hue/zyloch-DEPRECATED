"use client";

import React from "react";
import { Shield } from "lucide-react";
import { SiDocker, SiKubernetes, SiTerraform } from "react-icons/si";

const ICON_COLOR = "#0EA5E9";
const BG_COLOR = "#00B8DB26";
const BORDER_COLOR = "rgba(0, 184, 219, 0.35)";

const ICON_BASE_PATH = "/assets/icons/scan/overviewscanicon";

export const OVERVIEW_SCAN_ICONS = {
  admin: `${ICON_BASE_PATH}/ADMIN%20CONSOLE.svg`,
  adminConsole: `${ICON_BASE_PATH}/ADMIN%20CONSOLE.svg`,
  ai: `${ICON_BASE_PATH}/AI.svg`,
  aiAgent: `${ICON_BASE_PATH}/AIAgent.svg`,
  aiSkill: `${ICON_BASE_PATH}/AISkill.svg`,
  ansible: `${ICON_BASE_PATH}/ANSIBL.svg`,
  api: `${ICON_BASE_PATH}/API.svg`,
  apiScanner: `${ICON_BASE_PATH}/API%20SCANNER.svg`,
  secret: `${ICON_BASE_PATH}/Artboard%2025.svg`,
  aws: `${ICON_BASE_PATH}/AWS.svg`,
  azure: `${ICON_BASE_PATH}/AZURE.svg`,
  cloudformation: `${ICON_BASE_PATH}/CLOUDFORMATION.svg`,
  cloud: `${ICON_BASE_PATH}/Cloud.svg`,
  codeQuality: `${ICON_BASE_PATH}/CODE%20QUALITY.svg`,
  codex: `${ICON_BASE_PATH}/CODEX.svg`,
  cve: `${ICON_BASE_PATH}/CVE.svg`,
  docs: `${ICON_BASE_PATH}/DOCS.svg`,
  docker: `${ICON_BASE_PATH}/Docker.svg`,
  gcp: `${ICON_BASE_PATH}/GCP.svg`,
  githubWorkflow: `${ICON_BASE_PATH}/GITHUB%20WORKFLOW.svg`,
  github: `${ICON_BASE_PATH}/GITHUM.svg`,
  iac: `${ICON_BASE_PATH}/INFRA%20CODE%20SCANNING.svg`,
  kubernetes: `${ICON_BASE_PATH}/kubernetes.svg`,
  mcp: `${ICON_BASE_PATH}/MCP.svg`,
  overview: `${ICON_BASE_PATH}/OVERVIEW.svg`,
  plugins: `${ICON_BASE_PATH}/PLUGINS.svg`,
  policyManagement: `${ICON_BASE_PATH}/POLICY%20MANAGEMENT.svg`,
  pulumi: `${ICON_BASE_PATH}/PULUMI.svg`,
  terraform: `${ICON_BASE_PATH}/TERRAFORM.svg`,
  default: `${ICON_BASE_PATH}/OVERVIEW.svg`,
};

export const getScannerIconConfig = (rawKey) => {
  if (!rawKey) {
    return {
      icon: Shield,
      svgPath: OVERVIEW_SCAN_ICONS.default,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  const k = String(rawKey || "").trim().toLowerCase().replace(/[\s_-]+/g, "");

  // Cloud & Infrastructure as Code
  if (k.includes("terraform") || k.includes("tf")) {
    return {
      icon: SiTerraform,
      svgPath: OVERVIEW_SCAN_ICONS.terraform,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("ansible")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.ansible,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("pulumi")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.pulumi,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("cloudformation")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.cloudformation,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("aws")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.aws,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("azure") || k.includes("azur")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.azure,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("gcp") || k.includes("googlecloud")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.gcp,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("iac") || k.includes("infra") || k.includes("infracode") || k.includes("infrastructure")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.iac,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // Containers & Orchestration
  if (k.includes("docker") || k.includes("container") || k.includes("dockerfile")) {
    return {
      icon: SiDocker,
      svgPath: OVERVIEW_SCAN_ICONS.docker,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (
    k.includes("kuber") ||
    k.includes("k8s") ||
    k.includes("k8") ||
    k.includes("kube") ||
    k.includes("uberneet") ||
    k.includes("uberneetes") ||
    k.includes("uberneetess") ||
    k.includes("kubernetes")
  ) {
    return {
      icon: SiKubernetes,
      svgPath: OVERVIEW_SCAN_ICONS.kubernetes,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // Workflows & CI/CD
  if (k.includes("workflow") || k.includes("githubaction") || k.includes("cicd")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.githubWorkflow,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // Secrets & Keys
  if (k.includes("secret") || k.includes("key")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.secret,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // Code Quality
  if (k.includes("codequality") || k.includes("quality")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.codeQuality,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // SBOM / CVE / Vulnerabilities
  if (k.includes("sbom") || k.includes("cve") || k.includes("vulnerab")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.cve,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // Spec / API Scanner / API Discovery
  if (
    k.includes("spec") ||
    k.includes("apiscanner") ||
    k.includes("apidiscovery") ||
    k.includes("openapi") ||
    k.includes("swagger")
  ) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.apiScanner,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("api")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.api,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // AI & Skills
  if (
    k.includes("aiskill") ||
    k.includes("skill") ||
    k.includes("aisecurity") ||
    k.includes("aisecurityscanner")
  ) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.aiSkill,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("aiagent")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.aiAgent,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("aivshuman") || k.includes("ai")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.ai,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // Policies / CIS
  if (k.includes("cis") || k.includes("cisagent") || k.includes("policy")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.policyManagement,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // Management, Platform & Tools
  if (k.includes("mcp")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.mcp,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("admin") || k.includes("console")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.adminConsole,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("doc")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.docs,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("plugin")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.plugins,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("overview")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.overview,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("github") || k.includes("git") || k.includes("repo")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.github,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }
  if (k.includes("cloud") || k.includes("bicep")) {
    return {
      svgPath: OVERVIEW_SCAN_ICONS.cloud,
      color: ICON_COLOR,
      bg: BG_COLOR,
    };
  }

  // Default fallback if no scanner matches
  return {
    icon: Shield,
    svgPath: OVERVIEW_SCAN_ICONS.default,
    color: ICON_COLOR,
    bg: BG_COLOR,
  };
};

export const SvgMaskIcon = ({ src, color = ICON_COLOR, size = 22, className = "" }) => {
  if (!src) return null;
  return (
    <span
      className={className}
      role="img"
      aria-hidden="true"
      style={{
        display: "inline-block",
        width: `${size}px`,
        height: `${size}px`,
        backgroundColor: color,
        WebkitMaskImage: `url("${src}")`,
        maskImage: `url("${src}")`,
        WebkitMaskRepeat: "no-repeat",
        maskRepeat: "no-repeat",
        WebkitMaskPosition: "center",
        maskPosition: "center",
        WebkitMaskSize: "contain",
        maskSize: "contain",
        flexShrink: 0,
      }}
    />
  );
};

const ScannerIconTile = ({ scannerKey, className = "", size = 22, tileSize = 44 }) => {
  const [imgError, setImgError] = React.useState(false);
  const config = getScannerIconConfig(scannerKey);
  const IconComp = config?.icon || Shield;
  const isPng = config?.svgPath && config.svgPath.toLowerCase().endsWith(".png");

  React.useEffect(() => {
    setImgError(false);
  }, [scannerKey]);

  return (
    <div
      className={className}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: `${tileSize}px`,
        height: `${tileSize}px`,
        borderRadius: "14px",
        background: BG_COLOR,
        border: `1px solid ${BORDER_COLOR}`,
        color: ICON_COLOR,
        flexShrink: 0,
        transform: "translateZ(0)",
        backfaceVisibility: "hidden",
        WebkitFontSmoothing: "antialiased",
      }}
    >
      {!imgError && config?.svgPath ? (
        isPng ? (
          <img
            src={config.svgPath}
            alt={String(scannerKey || "Scanner Icon")}
            onError={() => setImgError(true)}
            style={{ width: `${size}px`, height: `${size}px`, objectFit: "contain" }}
          />
        ) : (
          <SvgMaskIcon src={config.svgPath} color={ICON_COLOR} size={size} />
        )
      ) : IconComp ? (
        <IconComp style={{ width: `${size}px`, height: `${size}px`, color: ICON_COLOR, strokeWidth: 1.8, shapeRendering: "geometricPrecision" }} />
      ) : (
        <Shield style={{ width: `${size}px`, height: `${size}px`, color: ICON_COLOR, strokeWidth: 1.8, shapeRendering: "geometricPrecision" }} />
      )}
    </div>
  );
};

export default ScannerIconTile;





