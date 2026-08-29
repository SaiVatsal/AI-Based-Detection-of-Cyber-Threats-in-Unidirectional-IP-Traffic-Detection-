import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from 'recharts';

const COLORS = ['#ff3b5c', '#ff6b3b', '#ffb524', '#00d4ff', '#8b5cf6', '#00e676'];

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div
      style={{
        background: '#0f1425',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '8px',
        padding: '10px 14px',
        fontSize: '12px',
        fontFamily: 'var(--font-mono)',
      }}
    >
      <p style={{ color: payload[0].payload.fill, fontWeight: 600 }}>
        {payload[0].name}
      </p>
      <p style={{ color: '#8892a8' }}>Count: {payload[0].value}</p>
    </div>
  );
};

export default function ThreatDistribution({ data, title }) {
  const chartData = data
    ? Object.entries(data).map(([name, value]) => ({ name, value }))
    : [];

  if (!chartData.length) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title">{title || 'Threat Distribution'}</span>
        </div>
        <div className="empty-state">
          <p>No threat data available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{title || 'Threat Distribution'}</span>
      </div>
      <div className="chart-container">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={100}
              paddingAngle={3}
              dataKey="value"
            >
              {chartData.map((_, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={COLORS[index % COLORS.length]}
                  stroke="transparent"
                />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
            <Legend
              verticalAlign="bottom"
              iconType="circle"
              iconSize={8}
              formatter={(value) => (
                <span style={{ color: '#8892a8', fontSize: '11px' }}>
                  {value.length > 25 ? value.slice(0, 25) + '…' : value}
                </span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
