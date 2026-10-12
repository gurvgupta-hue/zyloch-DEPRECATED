import {
  SiDocker,
  SiKubernetes,
  SiTerraform,
  SiGithubactions,
  SiGooglecloud,
  SiAnsible,
} from "react-icons/si";
import { FaKey, FaBoxOpen, FaGears, FaAws } from "react-icons/fa6";
import { VscAzure } from "react-icons/vsc";
import { BsShieldFillExclamation } from "react-icons/bs";
import {
  Brain,
  LayoutDashboard,
  ScanSearch,
  ShieldCheck,
  ShieldAlert,
  Layers,
  Cloud,
  Sparkles,
} from "lucide-react";

const SCANNER_ICON_COMPONENTS = {
  overview: LayoutDashboard,
  workflow: SiGithubactions,
  githubaction: SiGithubactions,
  docker: SiDocker,
  kubernetes: SiKubernetes,
  k8s: SiKubernetes,
  terraform: SiTerraform,
  "terraform-aws": FaAws,
  "terraform-azure": VscAzure,
  "terraform-gcp": SiGooglecloud,
  sbom: FaBoxOpen,
  "secret-scanner": FaKey,
  secret: FaKey,
  "code-quality": ShieldCheck,
  quality: ShieldCheck,
  "spec-scanner": ScanSearch,
  "spec-scanner-findings": ScanSearch,
  bicep: Layers,
  ansible: SiAnsible,
  cloudformation: Cloud,
  "skill-scanner": Sparkles,
  skill: Sparkles,
  "cis-agent": ShieldAlert,
  cis: ShieldAlert,
  "ai-vs-human": Brain,
  iac: FaGears,
  default: BsShieldFillExclamation,
};

export const normalizeScannerKey = (value) =>
  String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/_/g, "-");

export const getScannerIconComponent = (scannerType) => {
  const key = normalizeScannerKey(scannerType);
  return SCANNER_ICON_COMPONENTS[key] || SCANNER_ICON_COMPONENTS.default;
};

