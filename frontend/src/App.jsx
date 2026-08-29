import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import UrlInspector from './pages/UrlInspector';
import ReplayDemo from './pages/ReplayDemo';
import AlertsPage from './pages/AlertDetail';
import Reports from './pages/Reports';
import { useWebSocket } from './hooks/useWebSocket';
import AICopilotChat from './components/AICopilotChat';

function TopTelemetryBar({ user }) {
  const [timeStr, setTimeStr] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="top-telemetry-bar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
        <span className="telemetry-tag active">
          <span className="severity-dot" style={{ background: 'var(--accent-cyan)' }} />
          DATA DIODE: TX OPTICAL FIBER ONLY
        </span>
        <span className="telemetry-tag secure">
          🛡️ UNIDIRECTIONAL ENFORCEMENT (SIH26145)
        </span>
        <span className="telemetry-tag">
          ⚡ ISOLATION FOREST: 100 TREES (CONTAMINATION 0.05)
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
          {timeStr}
        </span>
        <span className="telemetry-tag" style={{ color: 'var(--text-primary)', background: 'var(--bg-surface)' }}>
          👤 {user?.username || '2500040224'} ({user?.role?.toUpperCase() || 'ADMIN'})
        </span>
      </div>
    </div>
  );
}

function ProtectedLayout({ user, onLogout }) {
  const { isConnected, alerts, progress } = useWebSocket();

  return (
    <div className="app-layout">
      <TopTelemetryBar user={user} />
      <Sidebar user={user} onLogout={onLogout} />
      <main className="main-content">
        <Routes>
          <Route
            path="/"
            element={<Dashboard wsAlerts={alerts} wsProgress={progress} />}
          />
          <Route
            path="/inspect"
            element={<UrlInspector wsAlerts={alerts} wsProgress={progress} />}
          />
          <Route
            path="/demo"
            element={<ReplayDemo wsAlerts={alerts} wsProgress={progress} />}
          />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      {/* Floating AI SOC Copilot Chatbot */}
      <AICopilotChat />

      {/* Live WebSocket Radar Heartbeat */}
      <div
        style={{
          position: 'fixed',
          bottom: 16,
          left: 260,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '6px 14px',
          background: 'rgba(10, 16, 36, 0.9)',
          backdropFilter: 'blur(12px)',
          border: '1px solid var(--border-cyan)',
          borderRadius: 'var(--radius-full)',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          color: isConnected ? 'var(--accent-cyan)' : 'var(--text-muted)',
          boxShadow: '0 0 16px rgba(0, 240, 255, 0.15)',
          zIndex: 1000,
        }}
      >
        <span
          style={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: isConnected ? 'var(--accent-cyan)' : 'var(--text-muted)',
            boxShadow: isConnected ? '0 0 8px var(--accent-cyan)' : 'none',
          }}
        />
        {isConnected ? 'STREAM: SYNCHRONIZED' : 'STREAM: LOCAL MODE'}
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(() => {
    const stored = localStorage.getItem('campusshield_user');
    return stored ? JSON.parse(stored) : { username: '2500040224', role: 'admin', full_name: 'Lead Security Architect' };
  });

  const isAuthenticated = !!localStorage.getItem('campusshield_token');

  const handleLogin = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('campusshield_token');
    localStorage.removeItem('campusshield_user');
    setUser(null);
  };

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/login"
          element={
            isAuthenticated ? (
              <Navigate to="/" replace />
            ) : (
              <Login onLogin={handleLogin} />
            )
          }
        />
        <Route
          path="/*"
          element={
            isAuthenticated ? (
              <ProtectedLayout user={user} onLogout={handleLogout} />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
