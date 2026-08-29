export default function KPICard({ label, value, sub, icon: Icon, color, glow }) {
  return (
    <div
      className="kpi-card"
      style={{ '--kpi-color': color, '--kpi-glow': glow }}
    >
      <div className="kpi-header">
        <span className="kpi-label">{label}</span>
        {Icon && (
          <div className="kpi-icon">
            <Icon size={20} />
          </div>
        )}
      </div>
      <span className="kpi-value">{value}</span>
      {sub && <span className="kpi-sub">{sub}</span>}
    </div>
  );
}
