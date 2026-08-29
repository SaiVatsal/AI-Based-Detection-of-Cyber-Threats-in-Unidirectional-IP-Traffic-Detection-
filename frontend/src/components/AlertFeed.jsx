import { useNavigate } from 'react-router-dom';

export default function AlertFeed({ alerts = [] }) {
  const navigate = useNavigate();

  if (!alerts.length) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title">Live Alert Feed</span>
        </div>
        <div className="empty-state">
          <p>No alerts yet. Run a simulation to generate traffic.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Live Alert Feed</span>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          {alerts.length} alerts
        </span>
      </div>
      <div className="alert-feed">
        {alerts.map((alert, i) => (
          <div
            key={alert.id || i}
            className={`alert-item ${alert.severity?.toLowerCase()}`}
            onClick={() => alert.id && navigate(`/alerts?id=${alert.id}`)}
            style={{ animationDelay: `${i * 50}ms` }}
          >
            <div className="alert-item-content">
              <div className="alert-item-title">{alert.title}</div>
              <div className="alert-item-meta">
                <span className={`severity-badge ${alert.severity?.toLowerCase()}`}>
                  <span className="severity-dot" />
                  {alert.severity}
                </span>
                {' · '}
                Score: {alert.threat_score?.toFixed(1)}
                {alert.confidence != null && ` · ${(alert.confidence * 100).toFixed(0)}% conf`}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
