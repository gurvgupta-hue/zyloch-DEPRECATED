# SEO, Performance & Accessibility — Layout Documentation

> Covers `app/layout.js`, `next.config.mjs`, and the supporting App Router files
> (`app/robots.js`, `app/sitemap.js`, `app/manifest.js`).
> Last updated: May 2026

---

## Table of Contents

1. [Metadata Structure](#1-metadata-structure)
2. [Viewport Configuration](#2-viewport-configuration)
3. [Changes Implemented](#3-changes-implemented)
4. [SEO & Performance Improvements](#4-seo--performance-improvements)
5. [Accessibility Improvements](#5-accessibility-improvements)
6. [Security Headers](#6-security-headers)
7. [New Files](#7-new-files)
8. [Environment Variables](#8-environment-variables)
9. [Recommended Future Enhancements](#9-recommended-future-enhancements)

---

## 1. Metadata Structure

All root metadata is exported from `app/layout.js` using Next.js App Router's
native `metadata` export. This generates correct `<head>` tags at build time
with no client-side JavaScript required.

### Title

```js
title: {
  default: "Zyloch – Secure Your Entire Application Posture",
  template: "%s | Zyloch",
}
```

- `default` is used on pages that do not export their own `metadata.title`.
- `template` appends `| Zyloch` to any page-level title.
- **To set a page-specific title**, export from any `page.js` or nested `layout.js`:

```js
// app/dashboard/page.js
export const metadata = {
  title: "Dashboard",  // renders as "Dashboard | Zyloch"
};
```

### Description

Used for search engine result snippets and social previews. 155–160 characters
is optimal for avoiding truncation.

### Keywords

The `keywords` array is included for legacy compatibility; modern search engines
primarily rely on page content and structured data rather than the keywords meta
tag.

### Authors & Category

```js
authors: [{ name: "Zyloch", url: "https://zyloch.dev" }],
category: "technology",
```

Helps search engines classify the site correctly.

### Canonical URL

```js
alternates: { canonical: "/" }
```

Declares the authoritative URL for the homepage and prevents duplicate content
penalties from crawlers. Page-level layouts should override this with their own
`alternates.canonical`.

### Robots

```js
robots: {
  index: true,
  follow: true,
  googleBot: {
    index: true,
    follow: true,
    "max-video-preview": -1,
    "max-image-preview": "large",
    "max-snippet": -1,
  },
}
```

Explicitly allows full indexing with unlimited snippet/image preview sizes.
Combine with `app/robots.js` (which produces `/robots.txt`) to block
authenticated routes.

### Icons

```js
icons: {
  icon: [
    { url: "/favicon.ico" },
    { url: "/favicon-16x16.png", sizes: "16x16", type: "image/png" },
    { url: "/favicon-32x32.png", sizes: "32x32", type: "image/png" },
  ],
  shortcut: "/favicon-16x16.png",
  apple: "/apple-touch-icon.png",
}
```

> **Note:** `/favicon-32x32.png` and `/apple-touch-icon.png` are declared but
> must be placed in `/public/`. Generate them with
> [realfavicongenerator.net](https://realfavicongenerator.net).

### OpenGraph

| Property | Value |
|---|---|
| `og:title` | Zyloch – Securing Application Posture Automatically |
| `og:description` | 155-char description |
| `og:url` | https://zyloch.dev |
| `og:site_name` | Zyloch |
| `og:locale` | en_US |
| `og:type` | website |
| `og:image` | /logo.png (1200×630 declared) |

> **Important:** `/logo.png` is currently used as the OG image. For best social
> card rendering, replace it with a dedicated 1200×630px image designed for
> social previews. See [Section 9](#9-recommended-future-enhancements).

### Twitter Card

| Property | Value |
|---|---|
| `twitter:card` | summary_large_image |
| `twitter:site` | @zyloch |
| `twitter:creator` | @zyloch |
| `twitter:image` | /logo.png |

Update `twitter:site` and `twitter:creator` to the actual Twitter/X handle when
the account is created or confirmed.

---

## 2. Viewport Configuration

```js
export const viewport = {
  width: "device-width",
  initialScale: 1,
  colorScheme: "light dark",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0f1117" },
  ],
};
```

- **`maximumScale` removed** — setting `maximumScale: 1` violated WCAG 1.4.4
  (Resize Text, Level AA) by blocking user zoom. It has been removed so users
  can zoom freely.
- **`colorScheme: "light dark"`** — tells the browser the page supports both
  schemes, enabling correct scrollbar and form-control rendering in dark mode.
- **`themeColor` array** — provides OS/browser toolbar color for both light and
  dark preferences.

---

## 3. Changes Implemented

### `app/layout.js`

| Change | Reason |
|---|---|
| Added `display: "swap"` to Inter font | Prevents invisible-text flash (FOIT) during font load |
| Removed `maximumScale: 1` from viewport | WCAG 1.4.4 — user zoom must not be restricted |
| Added `colorScheme: "light dark"` to viewport | Correct dark-mode browser UI rendering |
| Added `themeColor` array (light + dark) | Accurate toolbar colour for both OS preferences |
| Added `robots` directive | Explicit crawl instructions for Google |
| Added `alternates.canonical: "/"` | Canonical URL declaration for the homepage |
| Added `authors` and `category` | Search engine classification signals |
| Added `openGraph.locale: "en_US"` | Explicit locale for OG crawlers |
| Added `twitter.site` and `twitter.creator` | Twitter card attribution |
| Added `manifest: "/manifest.json"` | Links to Web App Manifest |
| Added expanded `icons` array | All standard favicon sizes declared |
| Moved `<ToastContainer>` outside `<main>` | Toasts are not page content; avoids ARIA pollution |
| Added `id="main-content"` to `<main>` | Target for skip-navigation link |
| Added `aria-label="Main content"` to `<main>` | Screen reader landmark label |
| Added `aria-hidden="true"` on blob container | Decorative; hidden from assistive technology |
| Added skip-to-main-content link | Keyboard/screen-reader accessibility (WCAG 2.4.1) |
| Replaced inline body `style` with CSS class | Moves transition to `.theme-transition` in globals.css |
| Added `<Script>` JSON-LD Organization schema | Structured data for Google rich results |
| Added `next/script` import | Required for `<Script>` component |

### `next.config.mjs`

| Change | Reason |
|---|---|
| Replaced hardcoded `148.72.153.121` with `process.env.NEXT_ALLOWED_DEV_ORIGINS` | Secrets/IPs must not be hardcoded in source |
| Added `headers()` with security headers | Defense-in-depth HTTP hardening |

### `app/globals.css`

| Change | Reason |
|---|---|
| Added `body { background-color, color }` | Ensures CSS-driven base styles |
| Added `.theme-transition` class | Replaces the inline `transition` style from `<body>` |

---

## 4. SEO & Performance Improvements

### Font Loading

`display: "swap"` ensures text renders immediately in a fallback font while
Inter loads, then swaps in. This eliminates the Flash of Invisible Text (FOIT)
and improves Cumulative Layout Shift (CLS) scores.

### Structured Data (JSON-LD)

An `Organization` schema is injected via `<Script strategy="afterInteractive">`:

```json
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "Zyloch",
  "url": "https://zyloch.dev",
  "logo": "https://zyloch.dev/logo.png",
  "description": "..."
}
```

This enables Google Knowledge Panel and rich results. Extend with `sameAs`
links (LinkedIn, GitHub, Twitter) when available.

### robots.txt (`app/robots.js`)

Blocks authenticated routes from being crawled:

```
Disallow: /dashboard/
Disallow: /settings/
Disallow: /scanops/
Disallow: /auth/
Disallow: /api/
```

Public routes (`/`, `/login`, `/signup`, `/home`) are allowed.

### Sitemap (`app/sitemap.js`)

Declares all publicly indexable pages with `changeFrequency` and `priority`
hints. Exclude auth-protected pages. Extend as new public pages are added.

### Security Headers

Added via `headers()` in `next.config.mjs`:

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing attacks |
| `X-Frame-Options` | `SAMEORIGIN` | Prevents clickjacking |
| `X-DNS-Prefetch-Control` | `on` | Improves DNS resolution performance |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Restricts sensitive browser APIs |

---

## 5. Accessibility Improvements

### Skip Navigation Link

A visually hidden link is the first element in `<body>`:

```jsx
<a href="#main-content" className="sr-only focus:not-sr-only ...">
  Skip to main content
</a>
```

This allows keyboard users to bypass repeated navigation and jump directly to
page content. Satisfies WCAG 2.4.1 (Bypass Blocks, Level A).

### Main Landmark

```jsx
<main id="main-content" aria-label="Main content" className="min-h-screen">
```

- `id="main-content"` is the target for the skip link.
- `aria-label` provides a descriptive label for the `<main>` landmark.

### Decorative Elements

```jsx
<div aria-hidden="true">
  {/* animated blobs */}
</div>
```

The animated gradient blobs are decorative and are now hidden from assistive
technology via `aria-hidden="true"`.

---

## 6. Security Headers

See [Section 4 – Security Headers](#security-headers) for the full table.

For a Content Security Policy (CSP), see
[Section 9 – Recommended Future Enhancements](#9-recommended-future-enhancements).

---

## 7. New Files

| File | Route | Purpose |
|---|---|---|
| `config/site.js` | N/A | Centralized site & SEO configuration (`siteConfig`) |
| `app/robots.js` | `/robots.txt` | Crawler access rules |
| `app/sitemap.js` | `/sitemap.xml` | Search engine page discovery |

All dynamic metadata files consume `siteConfig` from `config/site.js`.

---

## 8. Environment Variables

| Variable | File | Purpose | Default |
|---|---|---|---|
| `NEXT_PUBLIC_FRONTEND_URL` | `.env` / `.env.local` | Public frontend URL used for the browser, `metadataBase`, canonicals, OG tags, sitemap, robots, and JSON-LD | `http://localhost:3000` (dev) / `https://zyloch.dev` (fallback) |
| `NEXT_ALLOWED_DEV_ORIGINS` | `.env.local` | Comma-separated list of allowed dev origins (e.g. `148.72.153.121`) | (empty) |

### Environment-driven Setup (Local, QA, Production)

The public base URL is determined dynamically in `config/site.js` via:
```js
process.env.NEXT_PUBLIC_FRONTEND_URL || "https://zyloch.dev"
```

- **Local:** `NEXT_PUBLIC_FRONTEND_URL=http://localhost:3000`
- **QA:** `NEXT_PUBLIC_FRONTEND_URL=https://qa.zyloch.dev`
- **Production:** `NEXT_PUBLIC_FRONTEND_URL=https://zyloch.dev` (or omitted to use the fallback `https://zyloch.dev`)

---

## 9. Recommended Future Enhancements

### Dedicated OG Social Image

Create a `1200×630px` branded image (e.g. `public/og-image.png`) designed
specifically for social card previews. Update both `openGraph.images` and
`twitter.images` in `layout.js`. Tools: Figma, Canva, or
[og-image.vercel.app](https://og-image.vercel.app).

### Dynamic Page-Level Metadata

Each route should export its own `metadata` or `generateMetadata` for targeted
SEO. Example:

```js
// app/dashboard/page.js
export const metadata = {
  title: "Dashboard",
  description: "Your Zyloch security dashboard. Monitor findings, repositories, and CI/CD pipeline health.",
  alternates: { canonical: "/dashboard" },
  robots: { index: false, follow: false },  // auth-protected; no indexing
};
```

### Content Security Policy (CSP)

Add a CSP header in `next.config.mjs` to restrict script, style, and resource
origins. Use `report-uri` during rollout to capture violations before enforcing.

### Twitter/X Handle

Update `twitter.site` and `twitter.creator` in `layout.js` from `@zyloch` to
the verified handle once confirmed.

### `sameAs` in JSON-LD

Populate the `sameAs` array in the `organizationSchema` constant in `layout.js`:

```js
sameAs: [
  "https://github.com/Secure-Code-dev/zyloch",
  "https://twitter.com/zyloch",
  "https://www.linkedin.com/company/zyloch",
],
```

### Favicon Assets

Generate the full favicon set from [realfavicongenerator.net](https://realfavicongenerator.net)
and place in `/public/`:
- `favicon.ico`
- `favicon-16x16.png`
- `favicon-32x32.png`
- `apple-touch-icon.png`

### Google Search Console Verification

Add a verification meta tag to `metadata` after registering the domain:

```js
verification: {
  google: "your-verification-token",
}
```

### `optimizeCss`

`experimental.optimizeCss` is currently `false`. Enabling it (requires
`critters` package) inlines critical CSS and defers non-critical styles,
improving First Contentful Paint (FCP). Test thoroughly before enabling in
production.

### Toast Dark Mode

`ToastContainer` has `theme="light"` hardcoded. Connect it to the `ThemeContext`
value to render the correct theme in dark mode.
