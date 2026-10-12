import { siteConfig } from "@/config/site";

/**
 * Programmatic sitemap — Next.js App Router
 * Rendered at /sitemap.xml
 *
 * Only public-facing routes are included.
 * Authenticated routes (/dashboard, /settings, /scanops) are excluded
 * because they require login and should not be indexed.
 */
export default function sitemap() {
  const baseUrl = siteConfig.url;

  return [
    {
      url: baseUrl,
      lastModified: new Date(),
      changeFrequency: "monthly",
      priority: 1.0,
    },
    {
      url: `${baseUrl}/home`,
      lastModified: new Date(),
      changeFrequency: "monthly",
      priority: 0.9,
    },
    {
      url: `${baseUrl}/login`,
      lastModified: new Date(),
      changeFrequency: "yearly",
      priority: 0.6,
    },
    {
      url: `${baseUrl}/signup`,
      lastModified: new Date(),
      changeFrequency: "yearly",
      priority: 0.6,
    },
  ];
}
