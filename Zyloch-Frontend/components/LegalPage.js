"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import Link from "next/link";
import {
  Cookie,
  FileText,
  Scale,
  Download,
  Printer,
  Search,
  X,
  ArrowUp,
  ChevronRight,
  Home,
  CheckCircle2,
  AlertCircle,
} from "lucide-react";
import { toast, Toaster } from "sonner";
import styles from "../styles/LegalPage.module.css";

/**
 * Robust Client-Side MDX Parser
 */
function parseMDX(rawText) {
  if (!rawText) return { title: "", lastUpdated: "", intro: [], sections: [] };

  const lines = rawText.split(/\r?\n/);
  let title = "";
  let lastUpdated = "";
  const intro = [];
  const sections = [];
  let currentSection = null;
  let currentSubItem = null;
  let inIntro = true;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Extract Title #
    if (line.startsWith("# ")) {
      title = line.replace("# ", "").trim();
      continue;
    }

    // Extract Last Updated date
    if (line.toLowerCase().includes("**last updated:")) {
      const match = line.match(/\*\*Last Updated:\s*([^*]+)\*\*/i);
      if (match) {
        lastUpdated = match[1].trim();
      } else {
        lastUpdated = line.replace(/\*\*|Last Updated:/gi, "").trim();
      }
      continue;
    }

    // Extract Section Header ##
    if (line.startsWith("## ")) {
      inIntro = false;
      const sectionTitle = line.replace("## ", "").trim();
      const kebabId = sectionTitle
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, "")
        .trim()
        .replace(/\s+/g, "-");

      currentSection = {
        id: kebabId || `section-${sections.length + 1}`,
        title: sectionTitle,
        items: [],
      };
      sections.push(currentSection);
      currentSubItem = null;
      continue;
    }

    if (inIntro) {
      intro.push(line);
      continue;
    }

    if (currentSection) {
      // Bullet list item
      if (line.startsWith("- ")) {
        const bulletText = line.replace(/^- /, "").trim();
        if (currentSubItem) {
          if (!currentSubItem.bullets) currentSubItem.bullets = [];
          currentSubItem.bullets.push(bulletText);
        } else {
          let lastItem = currentSection.items[currentSection.items.length - 1];
          if (!lastItem || lastItem.type !== "bullets") {
            lastItem = { type: "bullets", text: "", bullets: [] };
            currentSection.items.push(lastItem);
          }
          lastItem.bullets.push(bulletText);
        }
      } else {
        // Subsection content line
        currentSubItem = {
          type: "text",
          text: line,
          bullets: [],
        };
        currentSection.items.push(currentSubItem);
      }
    }
  }

  return { title, lastUpdated, intro, sections };
}

/**
 * Text renderer supporting live search highlighting (<mark>) and linkifying URLs & Emails
 */
function HighlightedText({ text, query }) {
  if (!text) return null;

  // Render linkified text & highlight query if present
  const renderFormattedText = (str) => {
    // URL and Email Regex
    const urlPattern = /(https?:\/\/[^\s]+|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)/gi;
    const parts = str.split(urlPattern);

    return parts.map((part, index) => {
      if (part.match(/^https?:\/\//i)) {
        return (
          <a
            key={index}
            href={part}
            target="_blank"
            rel="noopener noreferrer"
            className={styles.inlineLink}
          >
            {part}
          </a>
        );
      }
      if (part.match(/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/i)) {
        return (
          <a
            key={index}
            href={`mailto:${part}`}
            className={styles.inlineLink}
          >
            {part}
          </a>
        );
      }

      // If search query is active, highlight matching tokens
      if (query && query.trim() !== "") {
        const subParts = part.split(new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, "gi"));
        return subParts.map((sub, i) =>
          sub.toLowerCase() === query.toLowerCase() ? (
            <mark key={i}>{sub}</mark>
          ) : (
            sub
          )
        );
      }

      return part;
    });
  };

  return <>{renderFormattedText(text)}</>;
}

export default function LegalPage({ content, type }) {
  const [searchQuery, setSearchQuery] = useState("");
  const [activeSectionId, setActiveSectionId] = useState("");
  const [showBackToTop, setShowBackToTop] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  // Parse raw MDX content
  const parsedData = useMemo(() => parseMDX(content), [content]);

  // Determine Icon based on legal page type
  const getHeaderIcon = () => {
    switch (type?.toLowerCase()) {
      case "cookies":
        return <Cookie className={styles.docIcon} size={24} />;
      case "privacy":
        return <FileText className={styles.docIcon} size={24} />;
      case "terms":
        return <Scale className={styles.docIcon} size={24} />;
      default:
        return <FileText className={styles.docIcon} size={24} />;
    }
  };

  // Determine Breadcrumb title
  const getBreadcrumbTitle = () => {
    switch (type?.toLowerCase()) {
      case "cookies":
        return "Cookie Policy";
      case "privacy":
        return "Privacy Policy";
      case "terms":
        return "Terms and Conditions";
      default:
        return parsedData.title || "Legal Document";
    }
  };

  // Filter sections based on live search query
  const filteredSections = useMemo(() => {
    if (!searchQuery.trim()) return parsedData.sections;

    const q = searchQuery.toLowerCase();
    return parsedData.sections
      .map((section) => {
        const titleMatch = section.title.toLowerCase().includes(q);
        const filteredItems = section.items.filter((item) => {
          const textMatch = item.text?.toLowerCase().includes(q);
          const bulletMatch = item.bullets?.some((b) => b.toLowerCase().includes(q));
          return textMatch || bulletMatch;
        });

        if (titleMatch || filteredItems.length > 0) {
          return {
            ...section,
            items: titleMatch ? section.items : filteredItems,
          };
        }
        return null;
      })
      .filter(Boolean);
  }, [parsedData.sections, searchQuery]);

  // Scrollspy via IntersectionObserver
  useEffect(() => {
    if (typeof window === "undefined" || parsedData.sections.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveSectionId(entry.target.id);
          }
        });
      },
      {
        rootMargin: "-20% 0px -70% 0px",
        threshold: 0,
      }
    );

    parsedData.sections.forEach((section) => {
      const el = document.getElementById(section.id);
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, [parsedData.sections]);

  // Back to Top button scroll listener
  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 400) {
        setShowBackToTop(true);
      } else {
        setShowBackToTop(false);
      }
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // PDF Download Handler with Toast Feedback & Fallback to window.print()
  const handleDownloadPDF = async () => {
    if (isDownloading) return;
    setIsDownloading(true);

    const toastId = toast.loading(`Preparing ${getBreadcrumbTitle()} PDF download...`);

    try {
      const res = await fetch(`/api/download?type=${type}`);

      if (!res.ok) {
        throw new Error(`PDF not available (Status: ${res.status})`);
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${parsedData.title || getBreadcrumbTitle()}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      toast.success(`${getBreadcrumbTitle()} downloaded successfully!`, { id: toastId });
    } catch (err) {
      console.warn("Official PDF download failed, falling back to window.print():", err);
      toast.error(`Official PDF unavailable. Launching print view as fallback...`, {
        id: toastId,
        duration: 4000,
      });

      setTimeout(() => {
        window.print();
      }, 800);
    } finally {
      setIsDownloading(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const scrollToSection = (e, id) => {
    e.preventDefault();
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: "smooth" });
      setActiveSectionId(id);
    }
  };

  return (
    <div className={styles.container}>
      <Toaster position="bottom-right" richColors />

      <div className={styles.wrapper}>
        {/* Top Header / Breadcrumbs Toolbar */}
        <nav className={styles.topNav} aria-label="Breadcrumb">
          <div className={styles.breadcrumbs}>
            <Link href="/" prefetch={false} className={styles.breadcrumbLink}>
              <Home size={14} style={{ marginRight: 4, display: "inline-block" }} />
              Home
            </Link>
            <ChevronRight className={styles.breadcrumbSeparator} size={14} />
            <span className={styles.breadcrumbActive}>{getBreadcrumbTitle()}</span>
          </div>

          <div className={styles.actionButtons}>
            <button
              onClick={handlePrint}
              className={styles.btn}
              title="Print document"
            >
              <Printer className={styles.btnIcon} />
              <span>Print</span>
            </button>

            <button
              onClick={handleDownloadPDF}
              className={`${styles.btn} ${styles.btnPrimary}`}
              disabled={isDownloading}
            >
              <Download className={styles.btnIcon} />
              <span>{isDownloading ? "Downloading..." : "Download PDF"}</span>
            </button>
          </div>
        </nav>

        {/* Page Header Card */}
        <header className={styles.headerCard}>
          <div className={styles.headerTitleRow}>
            <div className={styles.docIconBadge}>{getHeaderIcon()}</div>
            <div>
              <h1 className={styles.docTitle}>{parsedData.title || getBreadcrumbTitle()}</h1>
              {parsedData.lastUpdated && (
                <div className={styles.lastUpdated}>
                  <strong>Last Updated:</strong> {parsedData.lastUpdated}
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Live Search Section */}
        <div className={styles.searchSection}>
          <div className={styles.searchContainer}>
            <Search className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder={`Search within ${getBreadcrumbTitle()}...`}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search within document"
            />
            {searchQuery && (
              <button
                className={styles.searchClear}
                onClick={() => setSearchQuery("")}
                aria-label="Clear search query"
              >
                <X size={16} />
              </button>
            )}
          </div>
          {searchQuery && (
            <div className={styles.searchMeta}>
              <span>
                Showing results for <strong>&ldquo;{searchQuery}&rdquo;</strong>
              </span>
              <span>
                {filteredSections.length}{" "}
                {filteredSections.length === 1 ? "section" : "sections"} found
              </span>
            </div>
          )}
        </div>

        {/* Mobile Horizontal Pill Navigation */}
        {parsedData.sections.length > 0 && (
          <div className={styles.mobileNav} role="tablist">
            {parsedData.sections.map((sec) => (
              <a
                key={sec.id}
                href={`#${sec.id}`}
                onClick={(e) => scrollToSection(e, sec.id)}
                className={`${styles.mobilePill} ${
                  activeSectionId === sec.id ? styles.mobilePillActive : ""
                }`}
              >
                {sec.title}
              </a>
            ))}
          </div>
        )}

        {/* 2-Column Responsive Layout */}
        <div className={styles.layoutGrid}>
          {/* Sticky Table of Contents Sidebar */}
          <aside className={styles.sidebar}>
            <div className={styles.sidebarTitle}>Table of Contents</div>
            <ul className={styles.tocList}>
              {parsedData.sections.map((sec) => (
                <li key={sec.id} className={styles.tocItem}>
                  <a
                    href={`#${sec.id}`}
                    onClick={(e) => scrollToSection(e, sec.id)}
                    className={`${styles.tocLink} ${
                      activeSectionId === sec.id ? styles.tocLinkActive : ""
                    }`}
                    title={sec.title}
                  >
                    {sec.title}
                  </a>
                </li>
              ))}
            </ul>
          </aside>

          {/* Main Legal Content */}
          <main className={styles.contentArea}>
            {/* Introductory Paragraphs */}
            {!searchQuery && parsedData.intro.length > 0 && (
              <section className={styles.introSection}>
                {parsedData.intro.map((pText, i) => (
                  <p key={i} className={styles.introParagraph}>
                    <HighlightedText text={pText} query={searchQuery} />
                  </p>
                ))}
              </section>
            )}

            {/* Sections */}
            {filteredSections.length > 0 ? (
              filteredSections.map((sec) => (
                <section
                  key={sec.id}
                  id={sec.id}
                  className={`${styles.sectionCard} ${
                    activeSectionId === sec.id ? styles.sectionCardActive : ""
                  }`}
                >
                  <div className={styles.sectionHeader}>
                    <h2 className={styles.sectionTitle}>
                      <HighlightedText text={sec.title} query={searchQuery} />
                    </h2>
                    <a
                      href={`#${sec.id}`}
                      className={styles.sectionAnchor}
                      title="Link to section"
                      onClick={(e) => scrollToSection(e, sec.id)}
                    >
                      #
                    </a>
                  </div>

                  {sec.items.map((item, idx) => (
                    <div key={idx} className={styles.subItem}>
                      {item.text && (
                        <p className={styles.subItemText}>
                          <HighlightedText text={item.text} query={searchQuery} />
                        </p>
                      )}
                      {item.bullets && item.bullets.length > 0 && (
                        <ul className={styles.bulletList}>
                          {item.bullets.map((bText, bIdx) => (
                            <li key={bIdx} className={styles.bulletItem}>
                              <HighlightedText text={bText} query={searchQuery} />
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </section>
              ))
            ) : (
              <div className={styles.emptyState}>
                <AlertCircle size={40} style={{ margin: "0 auto 12px auto", opacity: 0.6 }} />
                <div className={styles.emptyStateTitle}>No results found</div>
                <div className={styles.emptyStateText}>
                  No sections matched &ldquo;{searchQuery}&rdquo;. Try searching for another keyword.
                </div>
                <button
                  className={`${styles.btn} ${styles.btnPrimary}`}
                  onClick={() => setSearchQuery("")}
                >
                  Clear Search
                </button>
              </div>
            )}
          </main>
        </div>

        {/* Floating Back to Top Button */}
        <button
          onClick={scrollToTop}
          className={`${styles.backToTop} ${
            showBackToTop ? styles.backToTopVisible : ""
          }`}
          aria-label="Back to top"
          title="Back to top"
        >
          <ArrowUp size={20} />
        </button>
      </div>
    </div>
  );
}
