const SummaryCard = ({ label, value, icon: Icon, color }) => (
  <div 
    className="bg-surface rounded-xl shadow-2 p-5 hover:shadow-1 transition-all duration-200"
    style={{ border: `2px solid ${color}` }}
  >
    <div className="flex flex-col items-center text-center space-y-3">
      <div className="p-3 rounded-lg" style={{ backgroundColor: `${color}15` }}>
        <Icon className="w-6 h-6" style={{ color }} />
      </div>
      <p className="text-sm font-medium" style={{ color: "var(--muted)" }}>
        {label}
      </p>
      <p className="text-2xl font-bold" style={{ color }}>
        {value}
      </p>
    </div>
  </div>
);

export default SummaryCard;
