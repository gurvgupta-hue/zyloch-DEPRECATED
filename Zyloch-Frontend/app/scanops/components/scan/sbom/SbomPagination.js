import React from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import styles from "./Sbom.module.css";

const getPaginationPages = (current, total) => {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 4) return [1, 2, 3, 4, 5, "...", total];
  if (current >= total - 3) return [1, "...", total - 4, total - 3, total - 2, total - 1, total];
  return [1, "...", current - 1, current, current + 1, "...", total];
};

const SbomPagination = React.memo(({ currentPage, totalPages, setCurrentPage, itemsPerPage, totalFilteredCount }) => {
  if (totalPages <= 1) return null;
  const pages = getPaginationPages(currentPage, totalPages);
  return (
    <article className={styles.paginationCard}>
      <div className={styles.paginationFrame}>
        <div className={styles.pageSizeChip}>
          Show: {itemsPerPage} rows
        </div>
        <div className={styles.pageInfo}>
          Showing {(currentPage - 1) * itemsPerPage + 1}-{Math.min(currentPage * itemsPerPage, totalFilteredCount)} of {totalFilteredCount}
        </div>
        <div className={styles.pagerBtns}>
          <button
            type="button"
            onClick={() => setCurrentPage((prev) => Math.max(prev - 1, 1))}
            disabled={currentPage === 1}
            aria-label="Previous page"
            className={styles.pagerBtn}
          >
            <ChevronLeft size={14} />
          </button>
          {pages.map((page, idx) =>
            page === "..." ? (
              <span key={`ellipsis-${idx}`} className={styles.pagerEllipsis}>...</span>
            ) : (
              <button
                key={page}
                type="button"
                onClick={() => setCurrentPage(page)}
                aria-label={`Page ${page}`}
                aria-current={currentPage === page ? "page" : undefined}
                className={`${styles.pagerBtn} ${currentPage === page ? styles.pagerBtnActive : ""}`}
              >
                {page}
              </button>
            )
          )}
          <button
            type="button"
            onClick={() => setCurrentPage((prev) => Math.min(prev + 1, totalPages))}
            disabled={currentPage === totalPages}
            aria-label="Next page"
            className={styles.pagerBtn}
          >
            <ChevronRight size={14} />
          </button>
        </div>
      </div>
    </article>
  );
});

export default SbomPagination;
