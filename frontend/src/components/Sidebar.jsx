import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Shield,
  PlayCircle,
  Bell,
  FileText,
  Settings,
  LogOut,
  Globe,
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/inspect', icon: Globe, label: 'URL Inspector' },
  { to: '/demo', icon: PlayCircle, label: 'Replay Demo' },
  { to: '/alerts', icon: Bell, label: 'Alerts' },
  { to: '/reports', icon: FileText, label: 'Reports' },
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
    : user?.username?.[0]?.toUpperCase() || '?';

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">🛡️</div>
        <div className="sidebar-brand">
          <h1>CampusShield</h1>
          <span>SIH26145</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `sidebar-nav-item ${isActive ? 'active' : ''}`
            }
          >
            <Icon />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-user">
          <div className="sidebar-avatar">{initials}</div>
          <div className="sidebar-user-info">
            <span className="name">{user?.full_name || user?.username}</span>
            <span className="role">{user?.role}</span>
          </div>
        </div>
        <button
          className="sidebar-nav-item"
          onClick={handleLogout}
          style={{ width: '100%', marginTop: '8px' }}
        >
          <LogOut />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
}
