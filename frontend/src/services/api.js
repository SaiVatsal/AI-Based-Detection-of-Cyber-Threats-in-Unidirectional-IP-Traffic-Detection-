import axios from 'axios';
import { mockApi } from './mockData';

const API_BASE = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 5000,
  headers: { 'Content-Type': 'application/json' },
});

// JWT interceptor
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('campusshield_token');
  if (token && token !== 'demo-token-campusshield') {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Track demo mode — fallback when backend is unreachable
let _demoMode = false;
export const isDemoMode = () => _demoMode;

// Auto-detect: try backend once; if unreachable, switch to demo mode
let _backendChecked = false;
async function ensureMode() {
  if (_backendChecked) return;
  _backendChecked = true;
  try {
    await axios.get(`${API_BASE.replace('/api', '')}/health`, { timeout: 3000 });
    _demoMode = false;
  } catch {
    _demoMode = true;
    console.info('%c[CampusShield] Demo mode — backend unreachable, using mock data', 'color: #00d4ff');
  }
}

// Wrapper: tries real API first, falls back to mock
function withFallback(realFn, mockFn) {
  return async (...args) => {
    await ensureMode();
    if (_demoMode) return mockFn(...args);
    try {
      return await realFn(...args);
    } catch {
      _demoMode = true;
      return mockFn(...args);
    }
  };
}

// Auth
export const login = withFallback(
  (username, password) => {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);
    return api.post('/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
  },
  (username, password) => mockApi.login(username, password)
);

export const getMe = withFallback(
  () => api.get('/auth/me'),
  () => Promise.resolve({ data: { username: "2500040224", role: "admin", full_name: "Lead Security Architect (2500040224)" } })
);


// Traffic
export const simulateTraffic = withFallback(
  (scenario, packetCount = 2000) => api.post(`/traffic/simulate/${scenario}`, { packet_count: packetCount }),
  () => mockApi.simulateTraffic()
);
export const inspectUrl = withFallback(
  (data) => api.post('/traffic/inspect-url', data),
  (data) => mockApi.inspectUrl(data)
);
export const getSessions = withFallback(() => api.get('/traffic/sessions'), () => mockApi.getSessions());
export const getSession = withFallback((id) => api.get(`/traffic/sessions/${id}`), (id) => mockApi.getSession(id));
export const getScenarios = withFallback(() => api.get('/traffic/scenarios'), () => mockApi.getScenarios());

// Detection
export const getDetectionConfig = withFallback(() => api.get('/detection/config'), () => mockApi.getDetectionConfig());
export const updateDetectionConfig = withFallback((d) => api.put('/detection/config', d), () => mockApi.updateDetectionConfig());
export const getDetectionResults = withFallback((sid) => api.get(`/detection/results/${sid}`), () => mockApi.getDetectionResults());
export const getAnomalousResults = withFallback((sid) => api.get(`/detection/results/${sid}/anomalies`), () => mockApi.getAnomalousResults());
export const getContributingFactors = withFallback((did) => api.get(`/detection/factors/${did}`), () => mockApi.getContributingFactors());

// Alerts
export const getAlerts = withFallback((p = {}) => api.get('/alerts', { params: p }), (p) => mockApi.getAlerts(p));
export const getAlert = withFallback((id) => api.get(`/alerts/${id}`), (id) => mockApi.getAlert(id));
export const getAlertStats = withFallback(() => api.get('/alerts/stats'), () => mockApi.getAlertStats());
export const acknowledgeAlert = withFallback((id) => api.put(`/alerts/${id}/acknowledge`), (id) => mockApi.acknowledgeAlert(id));

// Reports
export const generateReport = withFallback((sid) => api.post(`/reports/generate/${sid}`), () => mockApi.generateReport());
export const getReports = withFallback(() => api.get('/reports'), () => mockApi.getReports());

export default api;
