import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link } from 'react-router-dom';
import { Sun, Moon, Bell, CheckCircle2, AlertTriangle, ShieldAlert, X, Radio } from 'lucide-react';
import Sidebar from './components/Sidebar';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import UrlInspector from './pages/UrlInspector';
import ReplayDemo from './pages/ReplayDemo';
import AlertsPage from './pages/AlertDetail';
import Reports from './pages/Reports';
import { useWebSocket } from './hooks/useWebSocket';
import AICopilotChat from './components/AICopilotChat';

function TopTelemetryBar({ user, theme, onToggleTheme, notifications, onClearNotifications, onDismissToast, activeToast }) {
  const [timeStr, setTimeStr] = useState('');
  const [showNotifMenu, setShowNotifMenu] = useState(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <div className="top-telemetry-bar" style={{ position: 'relative' }}>
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
        {/* Light / Dark Mode Toggle Button */}
        <button
          onClick={onToggleTheme}
          className="btn btn-secondary btn-sm"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 10px',
            fontSize: '11px',
            borderColor: 'var(--border-cyan)',
            color: 'var(--text-primary)',
            background: 'var(--bg-surface)',
          }}
          title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {theme === 'dark' ? <Sun size={14} color="#ffb700" /> : <Moon size={14} color="#0284c7" />}
          <span>{theme === 'dark' ? '☀️ Light' : '🌙 Dark'}</span>
        </button>

        {/* Notification Bell with Badge */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setShowNotifMenu(!showNotifMenu)}
            className="btn btn-secondary btn-sm"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '6px 10px',
              borderColor: unreadCount > 0 ? 'var(--accent-cyan)' : 'var(--border-default)',
              color: unreadCount > 0 ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              background: 'var(--bg-surface)',
              position: 'relative',
            }}
            title="System & Inspection Notifications"
          >
            <Bell size={15} />
            {unreadCount > 0 && (
              <span
                style={{
                  position: 'absolute',
                  top: -4,
                  right: -4,
                  minWidth: 16,
                  height: 16,
                  borderRadius: 8,
                  background: 'var(--severity-critical)',
                  color: 'white',
                  fontSize: 10,
                  fontWeight: 800,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  padding: '0 4px',
                  boxShadow: '0 0 8px rgba(255,0,85,0.6)',
                }}
              >
                {unreadCount}
              </span>
            )}
          </button>

          {/* Notifications Dropdown Menu */}
          {showNotifMenu && (
            <div
              style={{
                position: 'absolute',
                top: 'calc(100% + 8px)',
                right: 0,
                width: '340px',
                maxHeight: '400px',
                background: 'var(--bg-card)',
                border: '1px solid var(--border-cyan)',
                borderRadius: '12px',
                boxShadow: 'var(--shadow-lg)',
                zIndex: 2000,
                overflow: 'hidden',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <div
                style={{
                  padding: '12px 16px',
                  background: 'var(--bg-surface)',
                  borderBottom: '1px solid var(--border-default)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Bell size={14} color="var(--accent-cyan)" />
                  <span style={{ fontSize: '13px', fontWeight: 800, color: 'var(--text-primary)' }}>
                    Notifications ({notifications.length})
                  </span>
                </div>
                {notifications.length > 0 && (
                  <button
                    onClick={onClearNotifications}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-muted)',
                      fontSize: '11px',
                      cursor: 'pointer',
                      textDecoration: 'underline',
                    }}
                  >
                    Clear All
                  </button>
                )}
              </div>

              <div style={{ overflowY: 'auto', maxHeight: '330px' }}>
                {notifications.length === 0 ? (
                  <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                    No recent notifications. Run a test inspection to generate logs.
                  </div>
                ) : (
                  notifications.map((n) => (
                    <div
                      key={n.id}
                      style={{
                        padding: '10px 14px',
                        borderBottom: '1px solid var(--border-default)',
                        borderLeft: `3px solid ${n.color || 'var(--accent-cyan)'}`,
                        background: 'var(--bg-card)',
                        fontSize: '12px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                        <span style={{ fontWeight: 800, color: n.color || 'var(--text-primary)' }}>{n.title}</span>
                        <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {n.time}
                        </span>
                      </div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '11px', lineHeight: 1.4 }}>
                        {n.message}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        <span style={{ color: 'var(--accent-cyan)', fontWeight: 600, fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
          {timeStr}
        </span>
        <span className="telemetry-tag" style={{ color: 'var(--text-primary)', background: 'var(--bg-surface)' }}>
          👤 {user?.username || '2500040224'} ({user?.role?.toUpperCase() || 'ADMIN'})
        </span>
      </div>

      {/* Floating In-App Toast Notification */}
      {activeToast && (
        <div
          style={{
            position: 'fixed',
            top: '60px',
            right: '24px',
            maxWidth: '380px',
            background: 'var(--bg-card)',
            border: `1px solid ${activeToast.color || 'var(--accent-cyan)'}`,
            borderLeft: `5px solid ${activeToast.color || 'var(--accent-cyan)'}`,
            borderRadius: '10px',
            boxShadow: `0 0 25px ${activeToast.color ? activeToast.color + '40' : 'rgba(0,240,255,0.2)'}`,
            padding: '14px 16px',
            zIndex: 3000,
            animation: 'fadeIn 0.3s ease',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
          }}
        >
          <div style={{ marginTop: 2 }}>
            {activeToast.isDanger ? (
              <ShieldAlert size={20} color={activeToast.color || 'var(--severity-critical)'} />
            ) : (
              <CheckCircle2 size={20} color={activeToast.color || 'var(--severity-low)'} />
            )}
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
              <span style={{ fontSize: '13px', fontWeight: 800, color: activeToast.color || 'var(--text-primary)' }}>
                {activeToast.title}
              </span>
              <button
                onClick={onDismissToast}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 0 }}
              >
                <X size={14} />
              </button>
            </div>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              {activeToast.message}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function ProtectedLayout({ user, onLogout, theme, onToggleTheme }) {
  const { isConnected, alerts, progress } = useWebSocket();
  const [notifications, setNotifications] = useState(() => {
    try {
      const stored = localStorage.getItem('campusshield_notifications');
      return stored ? JSON.parse(stored) : [
        { id: 1, title: 'System Initialized', message: 'CampusShield AI optical passive data diode stream online.', color: '#00f0ff', time: '09:00:00 UTC' }
      ];
    } catch (e) {
      return [];
    }
  });

  const [activeToast, setActiveToast] = useState(null);

  // Save notifications
  useEffect(() => {
    localStorage.setItem('campusshield_notifications', JSON.stringify(notifications));
  }, [notifications]);

  // Listen for custom inspection complete events from UrlInspector
  useEffect(() => {
    const handleInspectionComplete = (e) => {
      const detail = e.detail;
      if (!detail) return;

      const newNotif = {
        id: Date.now(),
        title: detail.title || `Inspection: ${detail.rate?.toLocaleString() || 1024} req/s`,
        message: `${detail.url} analyzed: ${detail.statusText || 'Completed'}. Score: ${detail.score?.toFixed(1)}/100 (${detail.severity}).`,
        color: detail.color || '#00ff88',
        time: new Date().toUTCString().slice(17, 25) + ' UTC',
        isDanger: detail.isDanger,
        read: false,
      };

      setNotifications((prev) => [newNotif, ...prev.slice(0, 49)]);
      setActiveToast(newNotif);

      // Auto dismiss toast after 6 seconds
      setTimeout(() => {
        setActiveToast((current) => (current?.id === newNotif.id ? null : current));
      }, 6000);
    };

    window.addEventListener('campusshield:inspection_complete', handleInspectionComplete);
    return () => window.removeEventListener('campusshield:inspection_complete', handleInspectionComplete);
  }, []);

  return (
    <div className="app-layout">
      <Sidebar user={user} onLogout={onLogout} />
      <main className="main-content">
        <TopTelemetryBar
          user={user}
          theme={theme}
          onToggleTheme={onToggleTheme}
          notifications={notifications}
          onClearNotifications={() => setNotifications([])}
          onDismissToast={() => setActiveToast(null)}
          activeToast={activeToast}
        />
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
          background: 'var(--bg-card)',
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
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('campusshield_theme') || 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('campusshield_theme', theme);
  }, [theme]);

  const handleToggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const [user, setUser] = useState(() => {
    const stored = localStorage.getItem('campusshield_user');
    return stored ? JSON.parse(stored) : { username: '2500040224', role: 'admin', full_name: 'Lead Security Architect' };
  });

  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return true; // Always allow immediate exploration in Hackathon demo mode
  });

  const handleLogin = (userData) => {
    setUser(userData);
    setIsAuthenticated(true);
    localStorage.setItem('campusshield_token', 'demo-jwt-token-sih26145');
    localStorage.setItem('campusshield_user', JSON.stringify(userData));
  };

  const handleLogout = () => {
    localStorage.removeItem('campusshield_token');
    localStorage.removeItem('campusshield_user');
    setUser({ username: '2500040224', role: 'admin', full_name: 'Lead Security Architect' });
  };

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/login"
          element={<Login onLogin={handleLogin} />}
        />
        <Route
          path="/*"
          element={
            <ProtectedLayout
              user={user}
              onLogout={handleLogout}
              theme={theme}
              onToggleTheme={handleToggleTheme}
            />
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
