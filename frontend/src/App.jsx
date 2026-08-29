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

function ProtectedLayout({ user, onLogout }) {
  const { isConnected, alerts, progress } = useWebSocket();

  return (
    <div className="app-layout">
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

      {/* WebSocket status indicator */}
      <div
        style={{
          position: 'fixed',
          bottom: 16,
          right: 16,
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '6px 12px',
          background: 'var(--glass-bg)',
          backdropFilter: 'blur(8px)',
          border: '1px solid var(--glass-border)',
          borderRadius: 'var(--radius-full)',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          color: isConnected ? 'var(--severity-low)' : 'var(--text-muted)',
          zIndex: 1000,
        }}
      >
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: isConnected ? 'var(--severity-low)' : 'var(--text-muted)',
          }}
        />
        {isConnected ? 'Live' : 'Disconnected'}
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(() => {
    const stored = localStorage.getItem('campusshield_user');
    return stored ? JSON.parse(stored) : null;
  });

  const isAuthenticated = !!localStorage.getItem('campusshield_token');

  const handleLogin = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
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
