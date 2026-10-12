import React, { Suspense } from 'react';
import LoginPage from './components/LoginPage';

export const metadata = {
  title: "Sign In",
  description: "Sign in to Zyloch to access your security dashboard, scan results, and repository insights.",
  robots: { index: true, follow: false },
  alternates: { canonical: "/login" },
};

function LoadingSpinner() {
  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--bg)" }}>
      <div role="status" aria-label="Loading sign-in page">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-neutral-300 border-t-transparent" />
        <span className="sr-only">Loading…</span>
      </div>
    </div>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<LoadingSpinner />}>
      <LoginPage />
    </Suspense>
  );
}
