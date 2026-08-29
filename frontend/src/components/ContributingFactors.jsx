export default function ContributingFactors({ factors = [] }) {
  if (!factors.length) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title">Contributing Factors</span>
        </div>
        <div className="empty-state">
          <p>No contributing factors available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ overflow: 'auto' }}>
      <div className="card-header">
        <span className="card-title">Contributing Factors</span>
      </div>
      <table className="factors-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Feature</th>
            <th>Observed</th>
            <th>Baseline</th>
            <th>Deviation</th>
            <th>Direction</th>
          </tr>
        </thead>
        <tbody>
          {factors.map((f, i) => {
            const maxDev = Math.max(...factors.map((x) => Math.abs(x.deviation_pct)));
            const barWidth = maxDev > 0 ? (Math.abs(f.deviation_pct) / maxDev) * 100 : 0;

            return (
              <tr key={i}>
                <td style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                  {f.contribution_rank || i + 1}
                </td>
                <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                  {f.feature_name}
                </td>
                <td>
                  {typeof f.observed_value === 'number'
                    ? f.observed_value > 1000
                      ? f.observed_value.toLocaleString(undefined, { maximumFractionDigits: 0 })
                      : f.observed_value.toFixed(3)
                    : f.observed_value}
                </td>
                <td>
                  {typeof f.baseline_value === 'number'
                    ? f.baseline_value > 1000
                      ? f.baseline_value.toLocaleString(undefined, { maximumFractionDigits: 0 })
                      : f.baseline_value.toFixed(3)
                    : f.baseline_value}
                </td>
                <td style={{ minWidth: '150px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div className="deviation-bar" style={{ flex: 1 }}>
                      <div
                        className={`deviation-fill ${f.direction}`}
                        style={{ width: `${Math.min(barWidth, 100)}%` }}
                      />
                    </div>
                    <span style={{
                      fontSize: '11px',
                      color: f.direction === 'above' ? 'var(--severity-high)' : 'var(--accent-blue)',
                      minWidth: '55px',
                      textAlign: 'right',
                    }}>
                      {f.deviation_pct > 0 ? '+' : ''}{f.deviation_pct.toFixed(1)}%
                    </span>
                  </div>
                </td>
                <td>
                  <span style={{
                    color: f.direction === 'above' ? 'var(--severity-high)' : 'var(--accent-blue)',
                    fontSize: '11px',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                  }}>
                    {f.direction === 'above' ? '▲ Above' : '▼ Below'}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
