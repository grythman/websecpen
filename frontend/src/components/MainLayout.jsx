import React, { useContext } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { ThemeContext } from '../context/ThemeContext.jsx';
import Logo from './Logo.jsx';
import '../components/ModernNavigation.css';

const MainLayout = () => {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useContext(ThemeContext);
  const navigate = useNavigate();
  const location = useLocation();

  const currentView = (() => {
    const path = location.pathname;
    if (path.startsWith('/scans')) return 'scans';
    if (path.startsWith('/vulnerabilities')) return 'vulnerabilities';
    if (path.startsWith('/reports')) return 'reports';
    if (path.startsWith('/team')) return 'team';
    if (path.startsWith('/profile')) return 'profile';
    if (path.startsWith('/admin')) return 'admin';
    return 'dashboard';
  })();

  const menuItems = [
    { key: 'dashboard', label: 'Dashboard', icon: '📊', roles: ['user', 'admin'], gradient: 'blue', path: '/' },
    { key: 'scans', label: 'Security Scans', icon: '🔍', roles: ['user', 'admin'], gradient: 'green', path: '/scans' },
    { key: 'vulnerabilities', label: 'Vulnerabilities', icon: '⚠️', roles: ['user', 'admin'], gradient: 'orange', path: '/vulnerabilities' },
    { key: 'reports', label: 'Reports', icon: '📄', roles: ['user', 'admin'], gradient: 'purple', path: '/reports' },
    { key: 'team', label: 'Team', icon: '👥', roles: ['user', 'admin'], gradient: 'teal', path: '/team' },
    { key: 'profile', label: 'Profile', icon: '👤', roles: ['user', 'admin'], gradient: 'pink', path: '/profile' },
    { key: 'admin', label: 'Admin', icon: '⚙️', roles: ['admin'], gradient: 'red', path: '/admin' }
  ];

  const userRole = user?.role || 'user';
  const filteredMenuItems = menuItems.filter(item => item.roles.includes(userRole));

  return (
    <div className="app-container">
      <nav className={`modern-navigation ${theme}`}>
        <div className="nav-brand">
          <div className="brand-logo">
            <Logo size="medium" />
          </div>
          <div className="brand-info">
            <h1 className="brand-title">WebSecPen</h1>
            <span className="brand-subtitle">Security Platform</span>
          </div>
        </div>

        <div className="nav-menu">
          {filteredMenuItems.map(item => (
            <button
              key={item.key}
              className={`nav-item ${currentView === item.key ? 'active' : ''} ${item.gradient}`}
              onClick={() => navigate(item.path)}
            >
              <div className="nav-item-content">
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
              </div>
              {currentView === item.key && <div className="nav-indicator"></div>}
            </button>
          ))}
        </div>

        <div className="nav-actions">
          <div className="action-controls">
            <button onClick={toggleTheme} className="control-btn theme-toggle" title="Toggle Theme">
              <span className="control-icon">{theme === 'dark' ? '☀️' : '🌙'}</span>
            </button>
            <div className="notifications-btn" title="Notifications">
              <span className="control-icon">🔔</span>
              <span className="notification-badge">3</span>
            </div>
          </div>
          <div className="user-section">
            <div className="user-avatar">
              <span className="avatar-text">{user?.first_name?.charAt(0) || user?.email?.charAt(0) || 'A'}</span>
              <div className="status-indicator online"></div>
            </div>
            <div className="user-details">
              <span className="user-name">{user?.first_name || user?.email?.split('@')[0] || 'Admin'}</span>
              <span className="user-role">{user?.role === 'admin' ? 'Administrator' : 'Security Analyst'}</span>
            </div>
            <button onClick={logout} className="logout-btn" title="Logout">
              <span className="logout-icon">🚪</span>
            </button>
          </div>
        </div>
      </nav>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
};

export default MainLayout;
