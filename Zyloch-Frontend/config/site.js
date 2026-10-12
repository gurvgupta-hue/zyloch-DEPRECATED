/**
 * Site Configuration
 *
 * Centralized configuration for public application URL, SEO, metadata,
 * OpenGraph, Twitter cards, and structured data.
 *
 * Base public URL is resolved from NEXT_PUBLIC_FRONTEND_URL,
 * defaulting to 'https://zyloch.dev'.
 */

let rawBaseUrl = process.env.NEXT_PUBLIC_FRONTEND_URL || "https://zyloch.dev";

// Ensure protocol exists (handles VM IPs like 100.23.23.56:3000 or localhost:3000)
if (!/^https?:\/\//i.test(rawBaseUrl)) {
  rawBaseUrl = `http://${rawBaseUrl}`;
}

// Ensure base URL has no trailing slash
const baseUrl = rawBaseUrl.replace(/\/+$/, "");

export const siteConfig = {
  name: "Zyloch",
  title: "Zyloch – Secure Your Entire Application Posture",
  titleTemplate: "%s | Zyloch",
  description:
    "Zyloch automatically detects vulnerabilities, misconfigurations, and compliance issues across your entire codebase, Infrastructure-as-Code, and CI/CD workflows. Get actionable security reports, minimal-permission GitHub integration, and instant setup.",
  url: baseUrl,
  logo: `${baseUrl}/logo.png`,
  ogImage: `${baseUrl}/logo.png`,
  category: "technology",
  authors: [{ name: "Zyloch", url: baseUrl }],
  creator: "@zyloch",
  twitterHandle: "@zyloch",
  keywords: [
    "Zyloch",
    "application security",
    "secure code scanning",
    "IaC security",
    "Terraform scanning",
    "Kubernetes security",
    "Docker misconfigurations",
    "CI/CD security",
    "GitHub security tool",
    "DevSecOps",
    "security automation",
    "source code analysis",
    "security posture management",
    "repository scanning",
    "workflow security",
  ],
  links: {
    github: "https://github.com/Secure-Code-dev/zyloch",
    twitter: "https://twitter.com/zyloch",
  },
};

export default siteConfig;
