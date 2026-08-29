import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
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
      <p style={{ color: '#8892a8', marginBottom: '4px' }}>{label}</p>
      {payload.map((entry, i) => (
        <p key={i} style={{ color: entry.color }}>
          {entry.name}: {typeof entry.value === 'number' ? entry.value.toLocaleString() : entry.value}
        </p>
      ))}
    </div>
  );
};

export default function TrafficChart({ data, title }) {
  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{title || 'Traffic Volume'}</span>
      </div>
      <div className="chart-container">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
            <defs>
              <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
            <XAxis dataKey="window" stroke="#5a6478" fontSize={11} />
            <YAxis stroke="#5a6478" fontSize={11} />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey="packets"
              stroke="#00d4ff"
              fill="url(#colorPackets)"
              strokeWidth={2}
              name="Packets"
            />
            <Area
              type="monotone"
              dataKey="bytes"
              stroke="#8b5cf6"
              fill="url(#colorBytes)"
              strokeWidth={2}
              name="Bytes (KB)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
