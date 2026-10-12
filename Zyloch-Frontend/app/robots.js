import { siteConfig } from "@/config/site";

/**
 * Programmatic robots.txt — Next.js App Router
 * Rendered at /robots.txt
 *
 * Disallows crawling of authenticated/private app routes.
 * Only public marketing & auth pages are indexable.
 */
export default function robots() {
  return {
    rules: [
      {
        userAgent: "*",
        allow: ["/", "/login", "/signup", "/home"],
        disallow: [
          "/dashboard/",
          "/settings/",
          "/scanops/",
          "/auth/",
          "/api/",
        ],
      },
    ],
    sitemap: `${siteConfig.url}/sitemap.xml`,
    host: siteConfig.url,
  };
}
