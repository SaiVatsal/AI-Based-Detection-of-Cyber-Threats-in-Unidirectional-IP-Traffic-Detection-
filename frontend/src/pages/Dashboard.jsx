import { useState, useEffect } from 'react';
import {
  Activity,
  Wifi,
  ShieldAlert,
  ShieldCheck,
  Zap,
  AlertTriangle,
  HardDrive,
  TrendingUp,
} from 'lucide-react';
import KPICard from '../components/KPICard';
import TrafficChart from '../components/TrafficChart';
import AnomalyTimeline from '../components/AnomalyTimeline';
import ThreatDistribution from '../components/ThreatDistribution';
import AlertFeed from '../components/AlertFeed';
import SensitivityControl from '../components/SensitivityControl';
import { getSessions, getAlertStats, getDetectionResults, getDetectionConfig } from '../services/api';

export default function Dashboard({ wsAlerts = [], wsProgress }) {
  const [sessions, setSessions] = useState([]);
  const [alertStats, setAlertStats] = useState(null);
  const [detectionConfig, setDetectionConfig] = useState(null);
  const [chartData, setChartData] = useState([]);
  const [timelineData, setTimelineData] = useState([]);
  const [categoryData, setCategoryData] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const [sessRes, statsRes, configRes] = await Promise.all([
        getSessions(),
        getAlertStats(),
        getDetectionConfig(),
      ]);

      setSessions(sessRes.data);
      setAlertStats(statsRes.data);
      setDetectionConfig(configRes.data);

      // Load results from most recent completed session
      const completedSession = sessRes.data.find((s) => s.status === 'completed');
      if (completedSession) {
        const resultsRes = await getDetectionResults(completedSession.id);
        const results = resultsRes.data;

        // Build chart data
        setChartData(
          results.map((r, i) => ({
            window: `W${i}`,
            packets: r.features?.packet_count || 0,
            bytes: Math.round((r.features?.total_bytes || 0) / 1024),
          }))
        );

        setTimelineData(
          results.map((r, i) => ({
            window: `W${i}`,
            score: r.normalized_score || 0,
            is_anomaly: r.is_anomaly,
          }))
        );

        // Category distribution
        const cats = {};
        results.filter((r) => r.is_anomaly && r.threat_category).forEach((r) => {
          cats[r.threat_category] = (cats[r.threat_category] || 0) + 1;
        });
        setCategoryData(cats);
      }
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    }
    setLoading(false);
  };

  // Compute KPIs from sessions
  const latestSession = sessions.find((s) => s.status === 'completed');
  const stats = latestSession?.traffic_stats || {};
  const totalPackets = stats.total_packets || 0;
  const totalWindows = stats.total_windows || 0;
  const normalPct = totalWindows ? ((stats.normal_windows || 0) / totalWindows * 100).toFixed(1) : '—';
  const anomalyPct = totalWindows ? ((stats.anomalous_windows || 0) / totalWindows * 100).toFixed(1) : '—';
  const criticalAlerts = alertStats?.by_severity?.CRITICAL || 0;
  const totalAlerts = alertStats?.total || 0;

  return (
    <div className="animate-in">
      <div className="page-header">
        <h1>Threat Detection Dashboard</h1>
        <p>Real-time unidirectional traffic analysis · SIH26145</p>
      </div>

      {/* KPI Grid */}
      <div className="kpi-grid">
        <KPICard
          label="Total Packets"
          value={totalPackets.toLocaleString()}
          icon={Activity}
          color="var(--accent-cyan)"
          glow="var(--accent-cyan-glow)"
        />
        <KPICard
          label="Analysis Windows"
          value={totalWindows.toLocaleString()}
          icon={HardDrive}
          color="var(--accent-blue)"
          glow="rgba(59,130,246,0.15)"
        />
        <KPICard
          label="Normal"
          value={`${normalPct}%`}
          sub={`${stats.normal_windows || 0} windows`}
          icon={ShieldCheck}
          color="var(--severity-low)"
          glow="var(--severity-low-glow)"
        />
        <KPICard
          label="Anomalous"
          value={`${anomalyPct}%`}
          sub={`${stats.anomalous_windows || 0} windows`}
          icon={ShieldAlert}
          color="var(--severity-high)"
          glow="var(--severity-high-glow)"
        />
        <KPICard
          label="Total Alerts"
          value={totalAlerts.toLocaleString()}
          icon={AlertTriangle}
          color="var(--severity-medium)"
          glow="var(--severity-medium-glow)"
        />
        <KPICard
          label="Critical"
          value={criticalAlerts.toLocaleString()}
          icon={Zap}
          color="var(--severity-critical)"
          glow="var(--severity-critical-glow)"
        />
      </div>

      {/* Charts */}
      <div className="charts-grid">
        <TrafficChart data={chartData} />
        <AnomalyTimeline data={timelineData} />
      </div>

      <div className="charts-grid">
        <ThreatDistribution data={categoryData} />
        <AlertFeed alerts={wsAlerts.length ? wsAlerts : (alertStats ? [] : [])} />
      </div>

      {/* Sensitivity Control */}
      {detectionConfig && (
        <SensitivityControl
          config={detectionConfig}
          onUpdate={() => loadDashboardData()}
        />
      )}
    </div>
  );
}
