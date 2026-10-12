// components/ui/Pagination.jsx
import React from 'react';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, MoreHorizontal } from 'lucide-react';

const sizeClasses = {
  sm: {
    button: 'w-8 h-8 text-sm',
    icon: 'w-4 h-4',
    gap: 'gap-1',
  },
  md: {
    button: 'w-10 h-10 text-base',
    icon: 'w-5 h-5',
    gap: 'gap-2',
  },
  lg: {
    button: 'w-12 h-12 text-lg',
    icon: 'w-6 h-6',
    gap: 'gap-3',
  },
};

export const Pagination = ({
  currentPage = 1,
  totalPages = 1,
  onPageChange,
  siblingCount = 1,
  showFirstLast = true,
  showEdges = true,
  size = 'md',
  variant = 'default',
  className = '',
  disabled = false,
}) => {
  // Generate page numbers to display
  const generatePagination = () => {
    // If total pages is less than 7, show all pages
    if (totalPages <= 7) {
      return Array.from({ length: totalPages }, (_, i) => i + 1);
    }

    const leftSiblingIndex = Math.max(currentPage - siblingCount, 1);
    const rightSiblingIndex = Math.min(currentPage + siblingCount, totalPages);

    const showLeftDots = leftSiblingIndex > 2;
    const showRightDots = rightSiblingIndex < totalPages - 1;

    if (!showLeftDots && showRightDots) {
      const leftItemsCount = 3 + 2 * siblingCount;
      const leftRange = Array.from({ length: leftItemsCount }, (_, i) => i + 1);
      return [...leftRange, '...', totalPages];
    }

    if (showLeftDots && !showRightDots) {
      const rightItemsCount = 3 + 2 * siblingCount;
      const rightRange = Array.from(
        { length: rightItemsCount },
        (_, i) => totalPages - rightItemsCount + i + 1
      );
      return [1, '...', ...rightRange];
    }

    if (showLeftDots && showRightDots) {
      const middleRange = Array.from(
        { length: rightSiblingIndex - leftSiblingIndex + 1 },
        (_, i) => leftSiblingIndex + i
      );
      return [1, '...', ...middleRange, '...', totalPages];
    }
  };

  const paginationRange = generatePagination();

  const handlePageChange = (page) => {
    if (!disabled && page >= 1 && page <= totalPages && page !== currentPage) {
      onPageChange(page);
    }
  };

  // Variant styles
  const variantClasses = {
    default: {
      base: 'bg-surface border border-border hover:border-border-accent hover:bg-elevated-surface text-text-secondary',
      active: 'bg-color-primary text-text-on-primary border-color-primary hover:bg-color-primary-600',
      disabled: 'opacity-40 cursor-not-allowed hover:border-border hover:bg-surface',
    },
    simple: {
      base: 'bg-transparent hover:bg-elevated-surface hover:text-color-primary text-muted',
      active: 'text-color-primary font-semibold bg-elevated-surface border-b-2 border-color-primary rounded-none',
      disabled: 'opacity-40 cursor-not-allowed hover:bg-transparent',
    },
    compact: {
      base: 'bg-surface/50 hover:bg-color-primary/10 text-muted rounded-md',
      active: 'bg-color-primary text-text-on-primary hover:bg-color-primary-600',
      disabled: 'opacity-40 cursor-not-allowed hover:bg-surface/50',
    },
  };

  // Edge button styles
  const edgeClasses = showEdges 
    ? 'block' 
    : 'hidden sm:block';

  return (
    <nav 
      className={`flex items-center justify-center ${className}`}
      aria-label="Pagination"
    >
      <ul className={`flex items-center ${sizeClasses[size].gap} list-none p-0 m-0`}>
        {/* First page button */}
        {showFirstLast && (
          <li>
            <button
              onClick={() => handlePageChange(1)}
              disabled={disabled || currentPage === 1}
              className={`
                ${sizeClasses[size].button}
                ${edgeClasses}
                flex items-center justify-center
                rounded-radius transition-all duration-200
                ${variantClasses[variant].base}
                ${(disabled || currentPage === 1) ? variantClasses[variant].disabled : ''}
                focus:outline-none focus:ring-2 focus:ring-color-primary/50
              `}
              aria-label="Go to first page"
            >
              <ChevronsLeft className={sizeClasses[size].icon} />
            </button>
          </li>
        )}

        {/* Previous page button */}
        <li>
          <button
            onClick={() => handlePageChange(currentPage - 1)}
            disabled={disabled || currentPage === 1}
            className={`
              ${sizeClasses[size].button}
              flex items-center justify-center
              rounded-radius transition-all duration-200
              ${variantClasses[variant].base}
              ${(disabled || currentPage === 1) ? variantClasses[variant].disabled : ''}
              focus:outline-none focus:ring-2 focus:ring-color-primary/50
            `}
            aria-label="Go to previous page"
          >
            <ChevronLeft className={sizeClasses[size].icon} />
          </button>
        </li>

        {/* Page numbers */}
        {paginationRange.map((pageNumber, index) => {
          if (pageNumber === '...') {
            return (
              <li key={`dots-${index}`}>
                <span
                  className={`
                    ${sizeClasses[size].button}
                    flex items-center justify-center
                    text-muted
                  `}
                >
                  <MoreHorizontal className={sizeClasses[size].icon} />
                </span>
              </li>
            );
          }

          return (
            <li key={pageNumber}>
              <button
                onClick={() => handlePageChange(pageNumber)}
                disabled={disabled}
                className={`
                  ${sizeClasses[size].button}
                  flex items-center justify-center
                  rounded-radius transition-all duration-200
                  font-medium
                  ${currentPage === pageNumber 
                    ? variantClasses[variant].active 
                    : variantClasses[variant].base
                  }
                  ${disabled ? variantClasses[variant].disabled : ''}
                  focus:outline-none focus:ring-2 focus:ring-color-primary/50
                `}
                aria-label={`Go to page ${pageNumber}`}
                aria-current={currentPage === pageNumber ? 'page' : undefined}
              >
                {pageNumber}
              </button>
            </li>
          );
        })}

        {/* Next page button */}
        <li>
          <button
            onClick={() => handlePageChange(currentPage + 1)}
            disabled={disabled || currentPage === totalPages}
            className={`
              ${sizeClasses[size].button}
              flex items-center justify-center
              rounded-radius transition-all duration-200
              ${variantClasses[variant].base}
              ${(disabled || currentPage === totalPages) ? variantClasses[variant].disabled : ''}
              focus:outline-none focus:ring-2 focus:ring-color-primary/50
            `}
            aria-label="Go to next page"
          >
            <ChevronRight className={sizeClasses[size].icon} />
          </button>
        </li>

        {/* Last page button */}
        {showFirstLast && (
          <li>
            <button
              onClick={() => handlePageChange(totalPages)}
              disabled={disabled || currentPage === totalPages}
              className={`
                ${sizeClasses[size].button}
                ${edgeClasses}
                flex items-center justify-center
                rounded-radius transition-all duration-200
                ${variantClasses[variant].base}
                ${(disabled || currentPage === totalPages) ? variantClasses[variant].disabled : ''}
                focus:outline-none focus:ring-2 focus:ring-color-primary/50
              `}
              aria-label="Go to last page"
            >
              <ChevronsRight className={sizeClasses[size].icon} />
            </button>
          </li>
        )}
      </ul>
    </nav>
  );
};

// Simple info display component
export const PaginationInfo = ({
  currentPage,
  totalItems,
  pageSize,
  className = '',
  variant = 'default',
}) => {
  const startItem = (currentPage - 1) * pageSize + 1;
  const endItem = Math.min(currentPage * pageSize, totalItems);

  const variantClasses = {
    default: 'text-muted',
    light: 'text-text-secondary',
    subtle: 'text-muted/80 text-sm',
  };

  return (
    <div className={`${variantClasses[variant]} ${className}`}>
      Showing {startItem} to {endItem} of {totalItems} results
    </div>
  );
};

// Simple page size selector
export const PageSizeSelector = ({
  pageSize,
  onPageSizeChange,
  options = [10, 25, 50, 100],
  className = '',
  disabled = false,
}) => {
  return (
    <select
      value={pageSize}
      onChange={(e) => onPageSizeChange(Number(e.target.value))}
      disabled={disabled}
      className={`
        px-3 py-2
        bg-surface
        border border-border
        rounded-radius
        text-text-secondary
        focus:outline-none focus:ring-2 focus:ring-color-primary/50
        disabled:opacity-40 disabled:cursor-not-allowed
        cursor-pointer
        ${className}
      `}
      aria-label="Items per page"
    >
      {options.map((option) => (
        <option key={option} value={option}>
          {option} per page
        </option>
      ))}
    </select>
  );
};