/**
 * Mock data for standalone demo mode.
 * Used when the backend API is unreachable (e.g., Vercel static deployment).
 */

const MOCK_SESSIONS = [
  {
    id: 1,
    name: "Demo: Normal Campus Traffic",
    source_type: "simulation",
    status: "completed",
    packet_count: 2000,
    flow_count: 40,
    traffic_stats: {
      total_packets: 2000,
      total_windows: 40,
      normal_windows: 38,
      anomalous_windows: 2,
    },
    created_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
  },
  {
    id: 2,
    name: "Demo: DDoS Simulation",
    source_type: "simulation",
    status: "completed",
    packet_count: 2000,
    flow_count: 40,
    traffic_stats: {
      total_packets: 2000,
      total_windows: 40,
      normal_windows: 12,
      anomalous_windows: 28,
    },
    created_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
  },
];

function generateTimelineData(count, attackStart, attackEnd) {
  const data = [];
  for (let i = 0; i < count; i++) {
    const isAttack = i >= attackStart && i < attackEnd;
    const baseScore = isAttack ? 55 + Math.random() * 40 : 5 + Math.random() * 20;
    data.push({
      window_index: i,
      is_anomaly: baseScore > 30,
      normalized_score: parseFloat(baseScore.toFixed(1)),
      threat_category: isAttack
        ? ["Volumetric Anomaly (DDoS-like)", "Scan-like Behavior", "Protocol Anomaly"][i % 3]
        : null,
      features: {
        packet_count: isAttack ? 800 + Math.random() * 400 : 40 + Math.random() * 60,
        total_bytes: isAttack ? 120000 + Math.random() * 80000 : 8000 + Math.random() * 12000,
        packets_per_second: isAttack ? 400 + Math.random() * 300 : 20 + Math.random() * 30,
        mean_packet_size: isAttack ? 80 + Math.random() * 40 : 300 + Math.random() * 200,
        unique_dst_ports: isAttack ? 20 + Math.floor(Math.random() * 80) : 2 + Math.floor(Math.random() * 5),
        protocol_entropy: isAttack ? 0.3 + Math.random() * 0.5 : 0.8 + Math.random() * 0.5,
      },
    });
  }
  return data;
}

const MOCK_RESULTS = generateTimelineData(40, 12, 32);

const MOCK_ALERT_STATS = {
  total: 28,
  by_severity: { CRITICAL: 5, HIGH: 10, MEDIUM: 8, LOW: 5 },
  by_status: { new: 20, acknowledged: 8 },
};

const MOCK_ALERTS = MOCK_RESULTS
  .filter((r) => r.is_anomaly)
  .map((r, i) => ({
    id: i + 1,
    title: r.threat_category || "Unclassified Anomaly",
    severity: r.normalized_score > 80 ? "CRITICAL" : r.normalized_score > 60 ? "HIGH" : r.normalized_score > 30 ? "MEDIUM" : "LOW",
    threat_score: r.normalized_score,
    threat_category: r.threat_category,
    confidence: 0.7 + Math.random() * 0.25,
    status: i < 8 ? "acknowledged" : "new",
    session_id: 2,
    description: `Anomalous traffic detected in window ${r.window_index}. Features deviate significantly from learned baseline. Score: ${r.normalized_score.toFixed(1)}/100.`,
    created_at: new Date(Date.now() - (28 - i) * 60000).toISOString(),
  }));

const MOCK_CONFIG = { contamination: 0.05, n_estimators: 100, max_samples: "auto" };

const MOCK_SCENARIOS = {
  normal: { name: "Normal Campus Traffic", description: "Steady HTTP/HTTPS traffic with typical browsing patterns.", expected_result: "No anomalies detected (baseline behavior)" },
  ddos: { name: "DDoS Volumetric Flood", description: "High-rate SYN flood from 500+ spoofed sources targeting a single destination.", expected_result: "Volumetric Anomaly alerts with high threat scores" },
  scan: { name: "Port Scan Sweep", description: "Sequential TCP SYN probes across 1000+ destination ports.", expected_result: "Scan-like Behavior alerts detecting port sweep pattern" },
  protocol_anomaly: { name: "Protocol Anomaly", description: "Unusual protocol mix — large ICMP, GRE tunnels, exotic IP protocols.", expected_result: "Protocol Anomaly alerts flagging unusual protocol distribution" },
  exfiltration: { name: "Data Exfiltration", description: "Sustained high-entropy encrypted transfer to an external host.", expected_result: "Exfiltration Pattern alerts detecting large encrypted outflows" },
};

const MOCK_FACTORS = [
  { feature_name: "packets_per_second", observed_value: 742, baseline_value: 95, deviation_pct: 681.1, direction: "above", contribution_rank: 1 },
  { feature_name: "unique_dst_ports", observed_value: 1, baseline_value: 6.2, deviation_pct: -83.9, direction: "below", contribution_rank: 2 },
  { feature_name: "mean_packet_size", observed_value: 62, baseline_value: 412, deviation_pct: -84.9, direction: "below", contribution_rank: 3 },
  { feature_name: "std_packet_size", observed_value: 4.2, baseline_value: 156, deviation_pct: -97.3, direction: "below", contribution_rank: 4 },
  { feature_name: "payload_entropy", observed_value: 1.2, baseline_value: 4.8, deviation_pct: -75.0, direction: "below", contribution_rank: 5 },
];

export const DEMO_MODE = true;

export const mockApi = {
  getSessions: () => Promise.resolve({ data: MOCK_SESSIONS }),
  getSession: (id) => Promise.resolve({ data: MOCK_SESSIONS.find((s) => s.id === id) || MOCK_SESSIONS[0] }),
  getAlertStats: () => Promise.resolve({ data: MOCK_ALERT_STATS }),
  getDetectionConfig: () => Promise.resolve({ data: MOCK_CONFIG }),
  getDetectionResults: () => Promise.resolve({ data: MOCK_RESULTS }),
  getAnomalousResults: () => Promise.resolve({ data: MOCK_RESULTS.filter((r) => r.is_anomaly) }),
  getAlerts: (params) => {
    let filtered = MOCK_ALERTS;
    if (params?.severity) filtered = filtered.filter((a) => a.severity === params.severity);
    return Promise.resolve({ data: filtered });
  },
  getAlert: (id) => Promise.resolve({ data: MOCK_ALERTS.find((a) => a.id === id) || MOCK_ALERTS[0] }),
  getContributingFactors: () => Promise.resolve({ data: MOCK_FACTORS }),
  acknowledgeAlert: (id) => {
    const alert = MOCK_ALERTS.find((a) => a.id === id);
    if (alert) alert.status = "acknowledged";
    return Promise.resolve({ data: { message: "Acknowledged" } });
  },
  getScenarios: () => Promise.resolve({ data: MOCK_SCENARIOS }),
  simulateTraffic: () => Promise.resolve({ data: { session_id: 2, message: "Simulation complete" } }),
  updateDetectionConfig: () => Promise.resolve({ data: MOCK_CONFIG }),
  generateReport: () => Promise.resolve({ data: { id: 1, message: "Report generated" } }),
  getReports: () => Promise.resolve({ data: [] }),
  login: () => Promise.resolve({
    data: { access_token: "demo-token-campusshield", username: "admin", full_name: "Demo Admin", role: "admin" },
  }),
};
