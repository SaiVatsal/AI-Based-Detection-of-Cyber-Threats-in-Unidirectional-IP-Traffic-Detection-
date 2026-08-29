import { useState } from 'react';
import { updateDetectionConfig } from '../services/api';

export default function SensitivityControl({ config, onUpdate }) {
  const [value, setValue] = useState(config?.contamination || 0.05);
  const [saving, setSaving] = useState(false);

  const handleChange = (e) => {
    setValue(parseFloat(e.target.value));
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateDetectionConfig({ contamination: value });
      if (onUpdate) onUpdate(value);
    } catch (e) {
      console.error('Failed to update config:', e);
    }
    setSaving(false);
  };

  const sensitivityLabel =
    value < 0.02 ? 'Very Low (few alerts)' :
    value < 0.05 ? 'Low' :
    value < 0.1 ? 'Medium (default)' :
    value < 0.2 ? 'High' :
    'Very High (many alerts)';

  return (
    <div className="card sensitivity-control">
      <div className="card-header">
        <span className="card-title">Detection Sensitivity</span>
      </div>

      <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
        Controls the anomaly detection threshold. Higher sensitivity flags more traffic
        as anomalous (more alerts, more false positives). Lower sensitivity is more
        conservative (fewer alerts, may miss subtle threats).
      </p>

      <input
        type="range"
        className="sensitivity-slider"
        min="0.005"
        max="0.4"
        step="0.005"
        value={value}
        onChange={handleChange}
      />

      <div className="sensitivity-labels">
        <span>Conservative</span>
        <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
          {(value * 100).toFixed(1)}% — {sensitivityLabel}
        </span>
        <span>Aggressive</span>
      </div>

      <div style={{ marginTop: '16px', display: 'flex', gap: '8px', alignItems: 'center' }}>
        <button
          className="btn btn-primary btn-sm"
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? 'Saving...' : 'Apply'}
        </button>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          Requires re-analysis to take effect
        </span>
      </div>
    </div>
  );
}
