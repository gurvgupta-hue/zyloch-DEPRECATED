const LoadingState = () => (
  <div className="min-h-screen  flex items-center justify-center bg-[var(--card-bg)]">
    <div className="text-center">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
      <p className="text-muted">Loading workflow data...</p>
    </div>
  </div>
);

export default LoadingState;