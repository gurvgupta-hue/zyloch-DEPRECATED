"use client";

import React from "react";
import { SiGoogle, SiBitbucket } from "react-icons/si";
import { FaGithub, FaGitlab } from "react-icons/fa6";
import { Monitor, Shield } from "lucide-react";
import { useTheme } from "@/context/ThemeContext";

const ICONS = {
  google: SiGoogle,
  microsoft: Monitor,
  github: FaGithub,
  gitlab: FaGitlab,
  bitbucket: SiBitbucket,
};

const TechStackIcon = ({ name, size = 20, variant, className = "", style = {} }) => {
  const { theme } = useTheme();
  const normalizedName = String(name || "").trim().toLowerCase();
  const IconComponent = ICONS[normalizedName] || Shield;
  const resolvedColor = variant === "dark" || theme === "dark" ? "currentColor" : "currentColor";

  return (
    <span
      className={className}
      style={{
        width: size,
        height: size,
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        ...style,
      }}
      aria-hidden="true"
    >
      <IconComponent size={size} color={resolvedColor} />
    </span>
  );
};

export default TechStackIcon;
