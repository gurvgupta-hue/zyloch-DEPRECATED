import { AlertCircle } from "lucide-react";

const ErrorState = ({ error }) => (
  <div className="flex h-full min-h-[350px] items-center justify-center p-8">
    <div className="text-center p-6 max-w-md flex flex-col items-center gap-2">
      <AlertCircle className="w-10 h-10 text-danger mx-auto mb-2" />
      <h2 className="text-lg font-semibold text-[var(--text)] mb-1">Error Loading Data</h2>
      <p className="text-sm text-[var(--muted)] leading-relaxed">{error}</p>
    </div>
  </div>
);

export default ErrorState;