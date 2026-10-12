// components/TechIcon.jsx
// Centralized TechIcon component for all icons - Primary: lucide-react, Fallback: react-icons

import * as Lucide from "lucide-react";
import * as SiIcons from "react-icons/si";
import { FaAws } from "react-icons/fa6";
import { VscAzure } from "react-icons/vsc"
import { SiGooglecloud } from "react-icons/si";

// Map normalized names to icon components
const iconMap = {
  // Cloud Providers (using react-icons for brand-specific icons)
  aws: FaAws,
  azure: VscAzure,
  gcp: SiIcons.SiGooglecloud,
  google: SiIcons.SiGooglecloud,

  // IaC / DevOps (mix of lucide and react-icons)
  docker: SiIcons.SiDocker,
  kubernetes: SiIcons.SiKubernetes,
  k8s: SiIcons.SiKubernetes,
  terraform: SiIcons.SiTerraform,
  ansible: SiIcons.SiAnsible,
  bicep: Lucide.FileCode2,
  arm: Lucide.FileJson2,
  cloudformation: Lucide.Cloud,
  cfn: Lucide.Cloud,
  pulumi: Lucide.Database,

  // Generic / Security (all lucide)
  workflow: Lucide.GitBranch,
  gitbranch: Lucide.GitBranch,
  key: Lucide.Key,
  secrets: Lucide.Key,
  iac: Lucide.Braces,
  braces: Lucide.Braces,

  // Frontend / Backend (react-icons for brands)
  react: SiIcons.SiReact,
  nextjs: SiIcons.SiNextdotjs,
  mongodb: SiIcons.SiMongodb,

  // File / UI (all lucide - primary library)
  file: Lucide.FileText,
  folder: Lucide.FolderOpen,
  tag: Lucide.Tag,
  database: Lucide.Database,
  cloud: Lucide.Cloud,
  server: Lucide.Server,
  hash: Lucide.Hash,
  box: Lucide.Box,
  layers: Lucide.Layers,
  eye: Lucide.Eye,

  // Navigation (all lucide)
  chevronleft: Lucide.ChevronLeft,
  chevronright: Lucide.ChevronRight,

  // Alerts / Security (all lucide)
  shield: Lucide.ShieldCheck,
  shieldcheck: Lucide.ShieldCheck,
  alert: Lucide.AlertTriangle,
  alerttriangle: Lucide.AlertTriangle,
  alertcircle: Lucide.AlertCircle,

  // Misc (all lucide)
  help: Lucide.HelpCircle,
};

// Dynamic fallback - tries react-icons/si first, then lucide
function getDynamicIcon(name) {
  // Try react-icons/si first (for brand icons)
  const siFormatted = "Si" + name.charAt(0).toUpperCase() + name.slice(1);
  if (SiIcons[siFormatted]) {
    return SiIcons[siFormatted];
  }
  
  // Try lucide-react as fallback
  const lucideFormatted = name
    .split(/[-_]/)
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
  
  if (Lucide[lucideFormatted]) {
    return Lucide[lucideFormatted];
  }
  
  return null;
}

/**
 * TechIcon component - uses lucide-react as primary icon library
 * @param {string} name - Icon name (case-insensitive)
 * @param {number} size - Icon size in pixels
 * @param {string} className - Additional CSS classes
 * @param {string} color - Icon color
 * @param {object} style - Inline styles
 * @param {boolean} strict - If true, only use lucide-react icons
 */
export default function TechIcon({
  name,
  size = 24,
  className = "",
  color,
  style = {},
  strict = false,
}) {
  const normalized = String(name || "").toLowerCase();
  
  // Get icon from predefined map
  let Icon = iconMap[normalized];
  
  // If not found and not in strict mode, try dynamic lookup
  if (!Icon && !strict) {
    Icon = getDynamicIcon(normalized);
  }
  
  // Final fallback
  Icon = Icon || Lucide.HelpCircle;
  
  return (
    <Icon
      size={size}
      className={className}
      color={color}
      style={style}
    />
  );
}