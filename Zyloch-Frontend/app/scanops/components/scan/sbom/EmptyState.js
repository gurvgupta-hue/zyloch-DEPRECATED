import { PackageSearch } from "lucide-react";

const EmptyState = ({
  title = "No SBOM Data",
  message = "No software bill of materials data was found for this scan."
}) => (
  <div className="flex h-full min-h-[350px] items-center justify-center p-8">
    <div className="text-center p-6 max-w-md flex flex-col items-center gap-2">
      <PackageSearch className="w-12 h-12 text-info mx-auto mb-2" />
      <h2 className="text-lg font-semibold text-[var(--text)]">{title}</h2>
      <p className="text-sm text-[var(--muted)] leading-relaxed">{message}</p>
    </div>
  </div>
);

export default EmptyState;