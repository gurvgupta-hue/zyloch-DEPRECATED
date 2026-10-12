// app/not-found.js
"use client"; // Add this directive to make it a Client Component

import Link from "next/link";
import { useRouter } from "next/navigation";
import { AlertTriangle, Home, ArrowLeft, Search, Mail } from "lucide-react";

export default function NotFound() {
  const router = useRouter();

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4 md:p-8"
      style={{ 
        background: "var(--bg)",
        backgroundImage: "radial-gradient(circle at 25% 25%, var(--elevated-surface) 0%, transparent 50%)"
      }}
    >
      <div className="relative w-full max-w-2xl">
        {/* Background decorative elements */}
        <div 
          className="absolute -top-20 -left-20 w-64 h-64 rounded-full opacity-10 blur-3xl"
          style={{ background: "var(--gradient-primary)" }}
        />
        <div 
          className="absolute -bottom-20 -right-20 w-64 h-64 rounded-full opacity-10 blur-3xl"
          style={{ background: "var(--gradient-primary)" }}
        />

        <div
          className="relative text-center p-8 md:p-12 border backdrop-blur-sm"
          style={{
            background: "var(--surface)",
            borderColor: "var(--border)",
            borderRadius: "var(--radius-2xl)",
            boxShadow: "0 20px 60px var(--shadow-lg)",
            backgroundImage: "linear-gradient(to bottom, var(--surface), transparent)"
          }}
        >
          {/* Error badge */}
          <div className="inline-flex items-center gap-2 px-4 py-2 mb-8 rounded-full"
            style={{
              background: "var(--elevated-surface)",
              border: "1px solid var(--border)",
            }}
          >
            <AlertTriangle size={16} style={{ color: "var(--color-warning)" }} />
            <span className="text-sm font-medium" style={{ color: "var(--muted)" }}>
              Error 404
            </span>
          </div>

          {/* Large 404 with gradient */}
          <div className="relative mb-6">
            <h1
              className="font-black tracking-tighter"
              style={{
                fontSize: "clamp(6rem, 15vw, 9rem)",
                background: "var(--gradient-primary)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                lineHeight: 0.8,
                letterSpacing: "-0.05em"
              }}
            >
              404
            </h1>
            <div 
              className="absolute inset-0 blur-3xl opacity-20 -z-10"
              style={{ background: "var(--gradient-primary)" }}
            />
          </div>

          {/* Main content */}
          <div className="max-w-lg mx-auto">
            <h2
              className="font-bold mb-3"
              style={{
                fontSize: "var(--font-size-3xl)",
                color: "var(--text)",
              }}
            >
              Lost in Cyberspace?
            </h2>
            
            <p
              className="mb-8 leading-relaxed"
              style={{
                color: "var(--muted)",
                fontSize: "var(--font-size-lg)",
              }}
            >
              The page you&apos;re looking for has been moved, deleted, or never existed. 
              Let&apos;s get you back on track.
            </p>

            {/* Suggested actions */}
            <div className="mb-10 p-6 rounded-2xl" style={{ 
              background: "var(--elevated-surface)",
              border: "1px solid var(--border)",
            }}>
              <h3 className="font-semibold mb-4 text-left" style={{ color: "var(--text)" }}>
                Suggested Actions
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <Link
                  href="/"
                  className="group flex items-center justify-between p-4 rounded-xl transition-all hover:scale-[1.02]"
                  style={{
                    background: "var(--surface)",
                    border: "1px solid var(--border)",
                  }}
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg" style={{ background: "var(--bg)" }}>
                      <Home size={20} style={{ color: "var(--color-primary)" }} />
                    </div>
                    <div className="text-left">
                      <div className="font-medium" style={{ color: "var(--text)" }}>Go Home</div>
                      <div className="text-sm" style={{ color: "var(--muted)" }}>Back to homepage</div>
                    </div>
                  </div>
                  <ArrowLeft size={16} className="opacity-0 group-hover:opacity-100 transition-opacity rotate-180" />
                </Link>

                <button
                  onClick={() => router.back()}
                  className="group flex items-center justify-between p-4 rounded-xl transition-all hover:scale-[1.02] text-left"
                  style={{
                    background: "var(--surface)",
                    border: "1px solid var(--border)",
                  }}
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg" style={{ background: "var(--bg)" }}>
                      <ArrowLeft size={20} style={{ color: "var(--color-primary)" }} />
                    </div>
                    <div className="text-left">
                      <div className="font-medium" style={{ color: "var(--text)" }}>Go Back</div>
                      <div className="text-sm" style={{ color: "var(--muted)" }}>Previous page</div>
                    </div>
                  </div>
                  <ArrowLeft size={16} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                </button>
              </div>
            </div>

            {/* Quick links */}
            <div className="mb-8">
              <h3 className="font-semibold mb-4" style={{ color: "var(--text)" }}>
                Quick Links
              </h3>
              <div className="flex flex-wrap justify-center gap-3">
                {[
                  { href: "/dashboard", label: "Dashboard" },
                  { href: "/scanops", label: "ScanOps", icon: Search },
                  { href: "/settings", label: "Settings" },
                  { href: "/support", label: "Contact Support", icon: Mail },
                ].map((link) => (
                  <Link
                    key={link.href}
                    href={link.href}
                    className="px-5 py-3 rounded-lg font-medium transition-all hover:translate-y-[-2px]"
                    style={{
                      background: link.label === "Dashboard" 
                        ? "var(--gradient-primary)" 
                        : "var(--elevated-surface)",
                      color: link.label === "Dashboard" ? "white" : "var(--text)",
                      border: link.label !== "Dashboard" ? "1px solid var(--border)" : "none",
                      boxShadow: link.label === "Dashboard" ? "0 4px 20px var(--shadow-primary)" : "none",
                    }}
                  >
                    <span className="flex items-center gap-2">
                      {link.icon && <link.icon size={18} />}
                      {link.label}
                    </span>
                  </Link>
                ))}
              </div>
            </div>

            {/* Help text */}
            <p className="text-sm mt-8" style={{ color: "var(--muted)" }}>
              Still lost?{" "}
              <Link 
                href="/support" 
                className="font-medium underline decoration-2 underline-offset-4 hover:decoration-primary transition-colors"
                style={{ color: "var(--color-primary)" }}
              >
                Contact our support team
              </Link>
            </p>
          </div>
        </div>

        {/* Decorative corners */}
        <div className="absolute top-0 left-0 w-8 h-8 border-t border-l" style={{ borderColor: "var(--border)" }} />
        <div className="absolute top-0 right-0 w-8 h-8 border-t border-r" style={{ borderColor: "var(--border)" }} />
        <div className="absolute bottom-0 left-0 w-8 h-8 border-b border-l" style={{ borderColor: "var(--border)" }} />
        <div className="absolute bottom-0 right-0 w-8 h-8 border-b border-r" style={{ borderColor: "var(--border)" }} />
      </div>
    </div>
  );
}