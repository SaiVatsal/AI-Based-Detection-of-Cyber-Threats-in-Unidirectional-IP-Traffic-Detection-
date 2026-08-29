import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Shield,
  PlayCircle,
  Bell,
  FileText,
  LogOut,
  Globe,
  Radio,
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'SOC Dashboard' },
  { to: '/inspect', icon: Globe, label: 'URL & Rate Inspector' },
  { to: '/demo', icon: PlayCircle, label: 'Scenario Simulator' },
  { to: '/alerts', icon: Bell, label: 'Incident Feed' },
  { to: '/reports', icon: FileText, label: 'Executive Reports' },
];

export default function Sidebar({ user, onLogout }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('campusshield_token');
    localStorage.removeItem('campusshield_user');
    if (onLogout) onLogout();
    navigate('/login');
  };

  const initials = user?.full_name
    ? user.full_name.split(' ').map((n) => n[0]).join('').toUpperCase()
    : user?.username?.[0]?.toUpperCase() || 'SA';

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo-icon">🛡️</div>
        <div>
          <div className="sidebar-title">CampusShield AI</div>
          <div className="sidebar-subtitle">SIH26145 · DIODE-PASSIVE</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', padding: '0 12px 6px', fontFamily: 'var(--font-mono)' }}>
          Operational Modules
        </div>
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
          >
            <Icon size={17} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="user-badge" style={{ marginBottom: '8px' }}>
          <div
            style={{
              width: 30,
              height: 30,
              borderRadius: '6px',
              background: 'linear-gradient(135deg, var(--accent-cyan), #1e40af)',
              color: '#030712',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              flexShrink: 0,
            }}
          >
            {initials.slice(0, 2)}
          </div>
          <div style={{ overflow: 'hidden', flex: 1 }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
              {user?.full_name || user?.username || 'Sai Vatsal'}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
              {user?.role?.toUpperCase() || 'ADMIN (SUPERVISOR)'}
            </div>
          </div>
        </div>

        <button
          className="btn btn-secondary"
          onClick={handleLogout}
          style={{ width: '100%', fontSize: '12px', padding: '7px 12px' }}
        >
          <LogOut size={14} />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
}
