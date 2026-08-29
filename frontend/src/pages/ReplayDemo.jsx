import { useState, useEffect } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Search,
  AlertCircle,
  UploadCloud,
  PlayCircle,
  Loader2,
} from 'lucide-react';
import PipelineVisualizer from '../components/PipelineVisualizer';
import TrafficChart from '../components/TrafficChart';
import AnomalyTimeline from '../components/AnomalyTimeline';
import AlertFeed from '../components/AlertFeed';
import { simulateTraffic, getScenarios, getDetectionResults } from '../services/api';

const SCENARIO_ICONS = {
  normal: ShieldCheck,
  ddos: AlertTriangle,
  scan: Search,
  protocol_anomaly: AlertCircle,
  exfiltration: UploadCloud,
};

export default function ReplayDemo({ wsAlerts, wsProgress }) {
  const [scenarios, setScenarios] = useState({});
  const [selectedScenario, setSelectedScenario] = useState(null);
  const [running, setRunning] = useState(false);
  const [sessionId, setSessionId] = useState(null);
  const [results, setResults] = useState(null);
  const [chartData, setChartData] = useState([]);
  const [timelineData, setTimelineData] = useState([]);

  useEffect(() => {
    getScenarios().then((res) => setScenarios(res.data)).catch(console.error);
  }, []);

  // Watch for completion via WebSocket progress
  useEffect(() => {
    if (
      wsProgress?.stage === 'complete' &&
      wsProgress?.session_id === sessionId
    ) {
      setRunning(false);
      loadResults(sessionId);
    }
  }, [wsProgress, sessionId]);

  const loadResults = async (sid) => {
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
    } catch (e) {
      console.error('Failed to load results:', e);
    }
  };

  const handleRun = async (scenario) => {
    setSelectedScenario(scenario);
    setRunning(true);
    setResults(null);
    setChartData([]);
    setTimelineData([]);

    try {
      const res = await simulateTraffic(scenario);
      setSessionId(res.data.session_id);
    } catch (e) {
      console.error('Simulation failed:', e);
      setRunning(false);
    }
  };

  const currentStage = wsProgress?.session_id === sessionId
    ? wsProgress.stage
    : running ? 'ingestion' : null;

  return (
    <div className="animate-in">
      <div className="page-header">
        <h1>Replay Demo</h1>
        <p>
          Run synthetic traffic scenarios to demonstrate the detection pipeline.
          Each scenario generates simulated packet telemetry — no real attacks.
        </p>
      </div>

      {/* Scenario Selection */}
      <div className="scenarios-grid">
        {Object.entries(scenarios).map(([key, scenario]) => {
          const Icon = SCENARIO_ICONS[key] || AlertCircle;
          const isActive = selectedScenario === key;
          const isRunningThis = isActive && running;

          return (
            <div
              key={key}
              className={`scenario-card ${isActive ? 'active' : ''}`}
              onClick={() => !running && handleRun(key)}
              style={{ opacity: running && !isActive ? 0.5 : 1, cursor: running ? 'default' : 'pointer' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div
                  style={{
                    width: 40,
                    height: 40,
                    borderRadius: 10,
                    background: isActive ? 'var(--accent-cyan-glow)' : 'var(--bg-surface)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  }}
                >
                  {isRunningThis ? <Loader2 size={20} className="loading-pulse" /> : <Icon size={20} />}
                </div>
                <h3 style={{ margin: 0 }}>{scenario.name}</h3>
              </div>
              <p>{scenario.description}</p>
              <div className="expected">→ {scenario.expected_result}</div>
            </div>
          );
        })}
      </div>

      {/* Pipeline Progress */}
      {currentStage && (
        <>
          <PipelineVisualizer currentStage={currentStage} />
          {wsProgress?.session_id === sessionId && (
            <div className="processing-bar">
              <span className="stage">{wsProgress.message || 'Processing...'}</span>
              <div className="progress-track">
                <div
                  className="progress-fill"
                  style={{ width: `${wsProgress.progress || 0}%` }}
                />
              </div>
              <span className="pct">{wsProgress.progress || 0}%</span>
            </div>
          )}
        </>
      )}

      {/* Results */}
      {results && (
        <div style={{ marginTop: '24px' }}>
          <div className="charts-grid">
            <TrafficChart data={chartData} title="Traffic Volume by Window" />
            <AnomalyTimeline data={timelineData} title="Anomaly Scores" />
          </div>

          <div style={{ marginTop: '16px' }}>
            <AlertFeed
              alerts={
                wsAlerts?.filter((a) => a.session_id === sessionId) || []
              }
            />
          </div>

          {/* Stats summary */}
          <div className="card" style={{ marginTop: '16px' }}>
            <div className="card-header">
              <span className="card-title">Analysis Summary</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '16px' }}>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Total Windows</div>
                <div style={{ fontSize: '24px', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                  {results.length}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Anomalous</div>
                <div style={{ fontSize: '24px', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--severity-high)' }}>
                  {results.filter((r) => r.is_anomaly).length}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Normal</div>
                <div style={{ fontSize: '24px', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--severity-low)' }}>
                  {results.filter((r) => !r.is_anomaly).length}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Max Score</div>
                <div style={{ fontSize: '24px', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--severity-critical)' }}>
                  {Math.max(...results.map((r) => r.normalized_score), 0).toFixed(1)}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
