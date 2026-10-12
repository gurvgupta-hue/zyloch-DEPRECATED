const DetailSection = ({ label, value, children }) => (
  <div className="space-y-2">
    <p className="text-sm font-medium text-muted">{label}</p>
    {children || <p className="text-sm text-text">{value}</p>}
  </div>
);

export default DetailSection;
