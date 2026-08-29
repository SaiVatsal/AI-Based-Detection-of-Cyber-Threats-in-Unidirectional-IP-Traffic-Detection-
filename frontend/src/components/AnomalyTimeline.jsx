import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const score = payload[0]?.value;
  let severity = 'LOW';
  if (score > 80) severity = 'CRITICAL';
  else if (score > 60) severity = 'HIGH';
  else if (score > 30) severity = 'MEDIUM';

  const colors = {
    CRITICAL: '#ff3b5c',
    HIGH: '#ff6b3b',
    MEDIUM: '#ffb524',
    LOW: '#00e676',
  };

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
      <p style={{ color: '#8892a8' }}>Window {label}</p>
      <p style={{ color: colors[severity], fontWeight: 700 }}>
        Score: {score?.toFixed(1)} ({severity})
      </p>
    </div>
  );
};

export default function AnomalyTimeline({ data, title }) {
  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{title || 'Anomaly Score Timeline'}</span>
      </div>
      <div className="chart-container">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
            <XAxis dataKey="window" stroke="#5a6478" fontSize={11} />
            <YAxis domain={[0, 100]} stroke="#5a6478" fontSize={11} />
            <Tooltip content={<CustomTooltip />} />
            <ReferenceLine y={30} stroke="#ffb524" strokeDasharray="4 4" opacity={0.5} />
            <ReferenceLine y={60} stroke="#ff6b3b" strokeDasharray="4 4" opacity={0.5} />
            <ReferenceLine y={80} stroke="#ff3b5c" strokeDasharray="4 4" opacity={0.5} />
            <Line
              type="monotone"
              dataKey="score"
              stroke="#00d4ff"
              strokeWidth={2}
              dot={(props) => {
                const { cx, cy, payload } = props;
                if (!payload.is_anomaly) return null;
                const color =
                  payload.score > 80 ? '#ff3b5c' :
                  payload.score > 60 ? '#ff6b3b' :
                  payload.score > 30 ? '#ffb524' : '#00e676';
                return (
                  <circle
                    cx={cx}
                    cy={cy}
                    r={5}
                    fill={color}
                    stroke="#0a0e1a"
                    strokeWidth={2}
                  />
                );
              }}
              activeDot={{ r: 7, fill: '#00d4ff', stroke: '#0a0e1a', strokeWidth: 2 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
