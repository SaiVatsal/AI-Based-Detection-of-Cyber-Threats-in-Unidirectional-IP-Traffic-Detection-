import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, UserCheck, UserPlus, Lock, Mail, User } from 'lucide-react';
import { login, signup } from '../services/api';

export default function Login({ onLogin }) {
  const [isSignUp, setIsSignUp] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      if (isSignUp) {
        // Sign Up Flow
        const res = await signup({
          username: username.trim(),
          password: password,
          full_name: fullName.trim() || username.trim(),
          email: email.trim() || `${username.trim()}@campusshield.ai`,
          role: 'analyst',
        });
        const { access_token, ...userData } = res.data;
        localStorage.setItem('campusshield_token', access_token);
        localStorage.setItem('campusshield_user', JSON.stringify(userData));
        setSuccess('Account created successfully! Redirecting...');
        setTimeout(() => {
          if (onLogin) onLogin(userData);
          navigate('/');
        }, 600);
      } else {
        // Sign In Flow
        const res = await login(username.trim(), password);
        const { access_token, ...userData } = res.data;
        localStorage.setItem('campusshield_token', access_token);
        localStorage.setItem('campusshield_user', JSON.stringify(userData));
        if (onLogin) onLogin(userData);
        navigate('/');
      }
    } catch (err) {
      setError(err.response?.data?.detail || (isSignUp ? 'Registration failed. Username may already exist.' : 'Invalid credentials. Access restricted.'));
    }
    setLoading(false);
  };

  return (
    <div className="login-page">
      <div className="login-card animate-in" style={{ maxWidth: '440px' }}>
        <div style={{ textAlign: 'center', marginBottom: '8px' }}>
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 14,
              background: 'linear-gradient(135deg, #00d4ff, #3b82f6)',
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 28,
              marginBottom: 12,
              boxShadow: '0 8px 24px rgba(0, 212, 255, 0.25)',
            }}
          >
            🛡️
          </div>
        </div>

        <h1>CampusShield AI</h1>
        <p className="subtitle">Unidirectional Traffic Threat Detection & Defense</p>

        {/* Tab Switcher */}
        <div
          style={{
            display: 'flex',
            background: 'var(--bg-input)',
            borderRadius: '8px',
            padding: '4px',
            marginBottom: '20px',
            border: '1px solid var(--border-default)',
          }}
        >
          <button
            type="button"
            onClick={() => { setIsSignUp(false); setError(''); setSuccess(''); }}
            style={{
              flex: 1,
              padding: '8px 12px',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: '13px',
              transition: 'all 0.2s ease',
              background: !isSignUp ? 'var(--accent-cyan)' : 'transparent',
              color: !isSignUp ? '#000000' : 'var(--text-secondary)',
            }}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setIsSignUp(true); setError(''); setSuccess(''); }}
            style={{
              flex: 1,
              padding: '8px 12px',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: '13px',
              transition: 'all 0.2s ease',
              background: isSignUp ? 'var(--accent-cyan)' : 'transparent',
              color: isSignUp ? '#000000' : 'var(--text-secondary)',
            }}
          >
            Sign Up
          </button>
        </div>

        {error && <div className="error-msg" style={{ marginBottom: '16px' }}>{error}</div>}
        {success && (
          <div style={{ padding: '10px 14px', background: 'rgba(0, 230, 118, 0.12)', border: '1px solid rgba(0, 230, 118, 0.3)', borderRadius: '6px', color: '#00e676', fontSize: '12px', marginBottom: '16px' }}>
            ✓ {success}
          </div>
        )}

        <form className="login-form" onSubmit={handleSubmit}>
          {isSignUp && (
            <>
              <div className="input-group">
                <label className="input-label">Full Name</label>
                <input
                  className="input"
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Enter your full name"
                  autoComplete="name"
                  required
                />
              </div>

              <div className="input-group">
                <label className="input-label">Email Address</label>
                <input
                  className="input"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@campusshield.ai"
                  autoComplete="email"
                  required
                />
              </div>
            </>
          )}

          <div className="input-group">
            <label className="input-label">User ID / Username</label>
            <input
              className="input"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={isSignUp ? "Create a unique user ID" : "Enter your user ID"}
              autoComplete="username"
              required
            />
          </div>

          <div className="input-group">
            <label className="input-label">Password</label>
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              autoComplete={isSignUp ? "new-password" : "current-password"}
              required
            />
          </div>

          <button className="btn btn-primary" type="submit" disabled={loading} style={{ width: '100%', marginTop: '8px' }}>
            {loading ? (isSignUp ? 'Creating Account...' : 'Authenticating...') : (isSignUp ? 'Create Analyst Account' : 'Sign In')}
          </button>
        </form>
      </div>
    </div>
  );
}
