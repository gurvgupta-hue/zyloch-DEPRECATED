import { useRef, useCallback } from "react";

export function useDebounce(func, wait = 300) {
  const timeoutRef = useRef(null);

  const debouncedFunction = useCallback(
    (...args) => {
      clearTimeout(timeoutRef.current);

      timeoutRef.current = setTimeout(() => {
        func(...args);
      }, wait);
    },
    [func, wait]
  );

  return debouncedFunction;
}
