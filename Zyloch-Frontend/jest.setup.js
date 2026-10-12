import "@testing-library/jest-dom";

// API clients capture `process.env.NEXT_PUBLIC_API_URL` at module load, and ES
// import hoisting runs before any assignment inside a test file. Set it here so
// every suite sees a stable base URL.
process.env.NEXT_PUBLIC_API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";
