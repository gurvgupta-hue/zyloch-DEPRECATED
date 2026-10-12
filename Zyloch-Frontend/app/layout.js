import "./globals.css";
import { Inter } from "next/font/google";
import Script from "next/script";
import { ThemeProvider } from "@/context/ThemeContext";
import { TenantProvider } from "@/context/TenantContext";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { siteConfig } from "@/config/site";

const inter = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-inter",
});

// JSON-LD structured data — Organization schema for rich results
const organizationSchema = {
  "@context": "https://schema.org",
  "@type": "Organization",
  name: siteConfig.name,
  url: siteConfig.url,
  logo: siteConfig.logo,
  description: siteConfig.description,
  sameAs: [],
};

export const metadata = {
  metadataBase: new URL(siteConfig.url),

  title: {
    default: siteConfig.title,
    template: siteConfig.titleTemplate,
  },

  description: siteConfig.description,

  keywords: siteConfig.keywords,

  authors: siteConfig.authors,
  category: siteConfig.category,

  alternates: {
    canonical: "/",
  },

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
  },

  icons: {
    icon: [
      { url: "/favicon.ico" },
      { url: "/favicon-16x16.png", sizes: "16x16", type: "image/png" },
      { url: "/favicon-32x32.png", sizes: "32x32", type: "image/png" },
    ],
    shortcut: "/favicon-16x16.png",
    apple: "/apple-touch-icon.png",
  },

  openGraph: {
    title: "Zyloch – Securing Application Posture Automatically",
    description:
      "Detect vulnerabilities, misconfigurations, and compliance issues across codebases, IaC files, and CI/CD pipelines. Install Zyloch on GitHub in under 2 minutes with minimal read-only permissions.",
    url: siteConfig.url,
    siteName: siteConfig.name,
    locale: "en_US",
    images: [
      {
        url: siteConfig.ogImage,
        width: 1200,
        height: 630,
        alt: "Zyloch – Automatic Application Security Platform",
      },
    ],
    type: "website",
  },

  twitter: {
    card: "summary_large_image",
    site: siteConfig.twitterHandle,
    creator: siteConfig.creator,
    title: "Zyloch – Automatic Application Security & CI/CD Scanning",
    description:
      "Zyloch scans your repositories, IaC, and GitHub workflows for vulnerabilities with minimal permissions. Get prioritized findings with step-by-step fixes.",
    images: [siteConfig.ogImage],
  },
};

export const viewport = {
  width: "device-width",
  initialScale: 1,
  // maximumScale intentionally omitted — WCAG 1.4.4 requires user zoom to be unrestricted
  colorScheme: "light dark",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0f1117" },
  ],
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body
        suppressHydrationWarning={true}
        className={`${inter.variable} ${inter.className} min-h-screen font-sans antialiased theme-transition`}
      >
        {/* JSON-LD structured data */}
        <Script
          id="organization-schema"
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(organizationSchema) }}
          strategy="afterInteractive"
        />

        {/* Skip to main content — keyboard & screen-reader accessibility */}
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-[9999] focus:px-4 focus:py-2 focus:rounded-md focus:bg-white focus:text-black focus:font-semibold focus:shadow-lg focus:outline-none"
        >
          Skip to main content
        </a>

        <ThemeProvider>
          <TenantProvider>
          {/* Background gradient animations */}
          <div className="fixed inset-0 overflow-hidden pointer-events-none z-10" aria-hidden="true">
            <div className="absolute -top-40 -right-32 w-80 h-80 bg-primary rounded-full mix-blend-multiply filter blur-xl opacity-10 animate-blob"></div>
            <div className="absolute -bottom-40 -left-32 w-80 h-80 bg-secondary rounded-full mix-blend-multiply filter blur-xl opacity-10 animate-blob animation-delay-2000"></div>
            <div className="absolute top-40 left-1/2 w-80 h-80 bg-accent rounded-full mix-blend-multiply filter blur-xl opacity-10 animate-blob animation-delay-4000"></div>
          </div>

          {/* Toast notifications — outside <main> as they are not page content */}
          <ToastContainer
            position="top-right"
            autoClose={3000}
            hideProgressBar={false}
            newestOnTop={false}
            closeOnClick
            rtl={false}
            pauseOnFocusLoss
            draggable
            pauseOnHover
            theme="light"
            toastClassName="bg-surface text-text border border-border rounded-md shadow-2 font-sans"
            progressClassName="bg-primary"
          />

          {/* Main content */}
          <div className="relative z-20">
            <main id="main-content" aria-label="Main content" className="min-h-screen">
              {children}
            </main>
          </div>
        </TenantProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}