 "use client";

import React, { useState, useEffect, useRef } from "react";
import { ChevronDown, ChevronLeft, ChevronRight, Check } from "lucide-react";

export const getPaginationPages = (currentPage, totalPages) => {
  if (totalPages <= 5) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }
  if (currentPage <= 3) {
    return [1, 2, 3, 4, "...", totalPages];
  }
  if (currentPage >= totalPages - 2) {
    return [1, "...", totalPages - 3, totalPages - 2, totalPages - 1, totalPages];
  }
  return [1, "...", currentPage - 1, currentPage, currentPage + 1, "...", totalPages];
};

const TablePagination = ({
  currentPage = 1,
  totalPages = 1,
  totalItems = 0,
  pageSize = 25,
  setPageSize,
  setCurrentPage,
  pageSizeOptions = [10, 25, 50, 100],
  className = "",
}) => {
  const [pageSizeDropdownOpen, setPageSizeDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setPageSizeDropdownOpen(false);
      }
    };
    if (pageSizeDropdownOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [pageSizeDropdownOpen]);

  const safePage = Math.min(Math.max(currentPage, 1), Math.max(totalPages, 1));
  const pageStart = totalItems === 0 ? 0 : (safePage - 1) * pageSize + 1;
  const pageEnd = Math.min(safePage * pageSize, totalItems);

  const goToPage = (page) => {
    if (page < 1 || page > totalPages || page === safePage) return;
    setCurrentPage(page);
  };

  if (totalItems === 0) return null;

  return (
    <div className={`flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 px-6 py-4 border-t border-default bg-surface ${className}`.trim()}>
      <div className="flex items-center gap-3">
        {setPageSize && (
          <div className="relative" ref={dropdownRef}>
            <button
              type="button"
              onClick={() => setPageSizeDropdownOpen((v) => !v)}
              className="inline-flex items-center gap-2 rounded-lg border border-default bg-surface px-3 py-1.5 text-xs text-text hover:border-hover hover:bg-elevated transition-colors shadow-sm"
              aria-label="Rows per page"
            >
              <span>Show: {pageSize} rows</span>
              <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${pageSizeDropdownOpen ? "rotate-180" : ""}`} />
            </button>

            {pageSizeDropdownOpen && (
              <div className="absolute left-0 bottom-full mb-1.5 w-32 rounded-lg border border-default bg-surface shadow-xl z-50 py-1 overflow-hidden">
                {pageSizeOptions.map((size) => (
                  <button
                    key={size}
                    type="button"
                    onClick={() => {
                      setPageSize(size);
                      if (setCurrentPage) setCurrentPage(1);
                      setPageSizeDropdownOpen(false);
                    }}
                    className="w-full flex items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                  >
                    <span>{size}</span>
                    {pageSize === size && <Check className="h-3.5 w-3.5 text-primary" />}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        <span className="text-xs text-muted">
          Showing {pageStart}–{pageEnd} of {totalItems}
        </span>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center gap-1.5 self-end sm:self-auto">
          <button
            type="button"
            onClick={() => goToPage(safePage - 1)}
            disabled={safePage <= 1}
            aria-label="Previous page"
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-default bg-surface text-text hover:bg-elevated disabled:opacity-30 disabled:pointer-events-none transition-colors"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>

          {getPaginationPages(safePage, totalPages).map((page, idx) =>
            page === "..." || page === "…" ? (
              <span key={`ellipsis-${idx}`} className="inline-flex h-8 w-8 items-center justify-center text-xs text-muted">
                ...
              </span>
            ) : (
              <button
                key={page}
                type="button"
                onClick={() => goToPage(page)}
                aria-label={`Page ${page}`}
                aria-current={safePage === page ? "page" : undefined}
                className={`inline-flex h-8 w-8 items-center justify-center rounded-lg text-xs font-medium transition-colors border ${
                  safePage === page
                    ? "border-primary/70 bg-elevated font-semibold text-primary"
                    : "border-default bg-surface text-muted hover:bg-elevated hover:text-text"
                }`}
              >
                {page}
              </button>
            )
          )}

          <button
            type="button"
            onClick={() => goToPage(safePage + 1)}
            disabled={safePage >= totalPages}
            aria-label="Next page"
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-default bg-surface text-text hover:bg-elevated disabled:opacity-30 disabled:pointer-events-none transition-colors"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  );
};

export default TablePagination;
