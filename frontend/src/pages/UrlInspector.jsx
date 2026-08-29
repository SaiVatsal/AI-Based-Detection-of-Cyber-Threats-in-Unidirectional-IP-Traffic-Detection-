import { useState, useEffect } from 'react';
import {
  Globe,
  Search,
  Zap,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Server,
  Activity,
  ArrowRight,
  Loader2,
  CheckCircle2,
  RefreshCw,
  HardDrive,
  Radio,
} from 'lucide-react';
import PipelineVisualizer from '../components/PipelineVisualizer';
import TrafficChart from '../components/TrafficChart';
import AnomalyTimeline from '../components/AnomalyTimeline';
import ThreatDistribution from '../components/ThreatDistribution';
import ContributingFactors from '../components/ContributingFactors';
import { inspectUrl, getDetectionResults, getContributingFactors } from '../services/api';

const QUICK_PRESETS = [
  { label: 'Local API (8000)', url: 'http://localhost:8000/api' },
  { label: 'Local Frontend (5173)', url: 'http://localhost:5173' },
  { label: 'Local Dev (3000)', url: 'http://localhost:3000' },
  { label: 'Campus Portal', url: 'https://portal.campus.edu/login' },
  { label: 'Internal Gateway', url: 'http://192.168.1.1:8080' },
];

const TRAFFIC_PROFILES = [
  {
    id: 'standard',
    name: 'Standard Legitimate Traffic',
    desc: 'Normal HTTP/HTTPS request distribution to test baseline behavior.',
    severity: 'LOW',
    color: 'var(--severity-low)',
  },
  {
    id: 'stress_spike',
    name: 'Volumetric Request Flood (DDoS)',
    desc: 'High-rate request burst targeting host to detect volume anomalies.',
    severity: 'CRITICAL',
    color: 'var(--severity-critical)',
  },
  {
    id: 'sweep_probe',
    name: 'Port & Path Sweep (Recon)',
    desc: 'Sequential probes across sensitive ports and paths (/.env, /admin).',
    severity: 'HIGH',
    color: 'var(--severity-high)',
  },
  {
    id: 'payload_anomaly',
    name: 'Protocol & Payload Injection',
    desc: 'Exotic protocol mix, fragmented payloads, high-entropy byte vectors.',
    severity: 'HIGH',
    color: 'var(--severity-high)',
  },
  {
    id: 'exfil_probe',
    name: 'Data Exfiltration Outflow',
    desc: 'Sustained high-entropy outbound transmissions to remote destinations.',
    severity: 'MEDIUM',
    color: 'var(--severity-medium)',
  },
];

export default function UrlInspector({ wsAlerts = [], wsProgress }) {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8000');
  const [profile, setProfile] = useState('standard');
  const [packetCount, setPacketCount] = useState(1500);
  const [isInspecting, setIsInspecting] = useState(false);
  const [sessionId, setSessionId] = useState(null);
  const [targetInfo, setTargetInfo] = useState(null);
  const [results, setResults] = useState(null);
  const [factors, setFactors] = useState([]);
  const [chartData, setChartData] = useState([]);
  const [timelineData, setTimelineData] = useState([]);
  const [categoryData, setCategoryData] = useState({});

  // Auto-complete if WebSocket signals finish
  useEffect(() => {
    if (wsProgress?.stage === 'complete' && wsProgress?.session_id === sessionId) {
      setIsInspecting(false);
      loadSessionData(sessionId);
    }
  }, [wsProgress, sessionId]);

  const loadSessionData = async (sid) => {
    try {
      const res = await getDetectionResults(sid);
      const data = res.data;
      setResults(data);

      setChartData(
        data.map((r, i) => ({
          window: `W${i}`,
          packets: r.features?.packet_count || 0,
          bytes: Math.round((r.features?.total_bytes || 0) / 1024),
        }))
      );

      setTimelineData(
        data.map((r, i) => ({
          window: `W${i}`,
          score: r.normalized_score || 0,
          is_anomaly: r.is_anomaly,
        }))
      );

      const cats = {};
      data.filter((r) => r.is_anomaly && r.threat_category).forEach((r) => {
        cats[r.threat_category] = (cats[r.threat_category] || 0) + 1;
      });
      setCategoryData(cats);

      // Load contributing factors for first anomaly
      const firstAnomaly = data.find((r) => r.is_anomaly);
      if (firstAnomaly) {
        const factorsRes = await getContributingFactors(firstAnomaly.id || 1).catch(() => ({ data: [] }));
        setFactors(factorsRes.data);
      }
    } catch (err) {
      console.error('Failed to load inspection results:', err);
    }
  };

  const handleInspect = async (e) => {
    if (e) e.preventDefault();
    if (!targetUrl.trim() || isInspecting) return;

    setIsInspecting(true);
    setResults(null);
    setFactors([]);
    setChartData([]);
    setTimelineData([]);
    setCategoryData({});

    try {
      const res = await inspectUrl({
        url: targetUrl.trim(),
        traffic_profile: profile,
        packet_count: packetCount,
      });

      setSessionId(res.data.session_id);
      setTargetInfo(res.data.target_info);

      // Fallback timer for demo mode or rapid completion
      setTimeout(() => {
        setIsInspecting(false);
        loadSessionData(res.data.session_id);
      }, 1500);
    } catch (err) {
      console.error('URL inspection failed:', err);
      setIsInspecting(false);
    }
  };

  // Compute summary metrics
  const totalAnomalies = results ? results.filter((r) => r.is_anomaly).length : 0;
  const maxScore = results && results.length ? Math.max(...results.map((r) => r.normalized_score), 0) : 0;
  const threatSeverity =
    maxScore > 80 ? 'CRITICAL' :
    maxScore > 60 ? 'HIGH' :
    maxScore > 30 ? 'MEDIUM' :
    maxScore > 10 ? 'LOW' : 'CLEAN';

  return (
    <div className="animate-in">
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: 12,
              background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-purple))',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'white',
            }}
          >
            <Globe size={24} />
          </div>
          <div>
            <h1>Target URL Traffic Inspector</h1>
            <p>Inspect, ingest, and detect cyber threats targeting any website, domain, or localhost URL</p>
          </div>
        </div>
      </div>

      {/* Target Input Card */}
      <div className="card" style={{ marginBottom: '24px' }}>
        <div className="card-header">
          <span className="card-title">Target Host Configuration</span>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            Unidirectional Observable Telemetry
          </span>
        </div>

        <form onSubmit={handleInspect}>
          <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
            <div style={{ flex: 1, position: 'relative' }}>
              <input
                type="text"
                className="input"
                style={{ width: '100%', paddingLeft: '40px', fontSize: '15px', fontFamily: 'var(--font-mono)' }}
                placeholder="Enter URL (e.g. http://localhost:8000, http://127.0.0.1:3000, https://campus.edu)"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isInspecting}
              />
              <Search
                size={18}
                style={{ position: 'absolute', left: '14px', top: '14px', color: 'var(--text-muted)' }}
              />
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isInspecting || !targetUrl.trim()}
              style={{ minWidth: '180px' }}
            >
              {isInspecting ? (
                <>
                  <Loader2 size={16} className="loading-pulse" />
                  Analyzing Traffic...
                </>
              ) : (
                <>
                  <Zap size={16} />
                  Inspect URL Traffic
                </>
              )}
            </button>
          </div>

          {/* Quick Presets */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '20px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)', marginRight: '4px' }}>Quick Presets:</span>
            {QUICK_PRESETS.map((p) => (
              <button
                key={p.url}
                type="button"
                className="btn btn-secondary btn-sm"
                style={{
                  fontSize: '11px',
                  padding: '4px 10px',
                  background: targetUrl === p.url ? 'var(--accent-cyan-glow)' : undefined,
                  borderColor: targetUrl === p.url ? 'var(--border-active)' : undefined,
                  color: targetUrl === p.url ? 'var(--accent-cyan)' : undefined,
                }}
                onClick={() => setTargetUrl(p.url)}
                disabled={isInspecting}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* Traffic Profile Selector */}
          <div style={{ marginBottom: '16px' }}>
            <label className="input-label" style={{ marginBottom: '10px', display: 'block' }}>
              Traffic Profile Vector
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
              {TRAFFIC_PROFILES.map((tp) => (
                <div
                  key={tp.id}
                  onClick={() => !isInspecting && setProfile(tp.id)}
                  style={{
                    padding: '12px 14px',
                    borderRadius: 'var(--radius-md)',
                    background: profile === tp.id ? 'var(--bg-surface)' : 'var(--bg-card)',
                    border: `1px solid ${profile === tp.id ? 'var(--accent-cyan)' : 'var(--border-default)'}`,
                    cursor: isInspecting ? 'default' : 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {tp.name}
                    </span>
                    <span
                      style={{
                        fontSize: '9px',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: profile === tp.id ? 'var(--accent-cyan-glow)' : 'transparent',
                        color: tp.color,
                        fontWeight: 700,
                        border: `1px solid ${tp.color}40`,
                      }}
                    >
                      {tp.severity}
                    </span>
                  </div>
                  <p style={{ fontSize: '11px', color: 'var(--text-muted)', margin: 0, lineHeight: 1.4 }}>
                    {tp.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </form>
      </div>

      {/* Real-time Telemetry & Target Card */}
      {targetInfo && (
        <div className="card" style={{ marginBottom: '24px' }}>
          <div className="card-header">
            <span className="card-title">Target Host Telemetry</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: isInspecting ? 'var(--accent-cyan)' : 'var(--severity-low)',
                }}
              />
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                {isInspecting ? 'Inspecting Flow...' : 'Analysis Complete'}
              </span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px' }}>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Target Host</div>
              <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                {targetInfo.hostname}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Resolved IP</div>
              <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                {targetInfo.resolved_ip}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Port & Protocol</div>
              <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                Port {targetInfo.port} ({targetInfo.scheme?.toUpperCase()})
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Threat Score</div>
              <div style={{ fontSize: '18px', fontWeight: 800, fontFamily: 'var(--font-mono)', color: maxScore > 60 ? 'var(--severity-critical)' : 'var(--severity-low)' }}>
                {results ? `${maxScore.toFixed(1)} / 100` : 'Evaluating...'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Overall Status</div>
              <div>
                <span className={`severity-badge ${threatSeverity.toLowerCase()}`}>
                  <span className="severity-dot" /> {threatSeverity}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Live Pipeline Visualizer */}
      {isInspecting && (
        <div style={{ marginBottom: '24px' }}>
          <PipelineVisualizer currentStage="anomaly_detection" />
          <div className="processing-bar">
            <span className="stage">Extracting Unidirectional Features for {targetUrl}...</span>
            <div className="progress-track">
              <div className="progress-fill" style={{ width: '80%' }} />
            </div>
            <span className="pct">80%</span>
          </div>
        </div>
      )}

      {/* Results View */}
      {results && (
        <div className="animate-in">
          <div className="charts-grid">
            <TrafficChart data={chartData} title={`Traffic Volume Flow → ${targetInfo?.hostname || 'Target'}`} />
            <AnomalyTimeline data={timelineData} title="Isolation Forest Anomaly Timeline" />
          </div>

          <div className="charts-grid">
            <ThreatDistribution data={categoryData} title="Threat Category Breakdown" />
            <div className="card">
              <div className="card-header">
                <span className="card-title">Inspection Summary</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div style={{ padding: '16px', background: 'var(--bg-card)', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Analyzed Packets</div>
                  <div style={{ fontSize: '22px', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                    {packetCount.toLocaleString()}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    100% Unidirectional Safe
                  </div>
                </div>
                <div style={{ padding: '16px', background: 'var(--bg-card)', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Anomalous Windows</div>
                  <div style={{ fontSize: '22px', fontWeight: 800, fontFamily: 'var(--font-mono)', color: totalAnomalies > 0 ? 'var(--severity-high)' : 'var(--severity-low)' }}>
                    {totalAnomalies} / {results.length}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    {totalAnomalies > 0 ? 'Requires SOC Review' : 'Nominal Baseline'}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {factors.length > 0 && (
            <div style={{ marginTop: '24px' }}>
              <ContributingFactors factors={factors} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
