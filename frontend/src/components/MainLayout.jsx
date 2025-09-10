import React, { useContext, useState, useEffect } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { ThemeContext } from '../context/ThemeContext.jsx';
import Logo from './Logo.jsx';
import LanguageSwitcher from './LanguageSwitcher.jsx';
import CommandPalette from './CommandPalette.jsx';
import NotificationPreferences from './NotificationPreferences.jsx';
import '../components/ModernNavigation.css';

const MainLayout = () => {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useContext(ThemeContext);
  const navigate = useNavigate();
  const location = useLocation();

  // Mobile menu state
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  
  // UI state
  const [showNotificationPanel, setShowNotificationPanel] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showCommandPalette, setShowCommandPalette] = useState(false);
  const [isNavigating, setIsNavigating] = useState(false);

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

  const userRole = user?.role || (user?.is_admin ? 'admin' : 'user');
  const filteredMenuItems = menuItems.filter(item => item.roles.includes(userRole));

  const userInitial = user?.first_name?.charAt(0) || user?.email?.charAt(0) || 'A';
  const userName = user?.first_name || user?.email?.split('@')[0] || 'Admin';
  const userEmail = user?.email || '';
  const isAdmin = user?.is_admin === true || user?.role === 'admin';

  // Enhanced navigation with loading state
  const handleNavigation = async (path) => {
    setIsNavigating(true);
    setIsMobileMenuOpen(false);
    navigate(path);
    setTimeout(() => setIsNavigating(false), 300);
  };

  // Get breadcrumbs
  const getBreadcrumbs = () => {
    const path = location.pathname;
    const segments = path.split('/').filter(Boolean);
    return [
      { label: 'Home', path: '/' },
      ...segments.map((segment, index) => ({
        label: segment.charAt(0).toUpperCase() + segment.slice(1),
        path: '/' + segments.slice(0, index + 1).join('/')
      }))
    ];
  };

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (!event.target.closest('.notifications-container')) {
        setShowNotificationPanel(false);
      }
      if (!event.target.closest('.user-section')) {
        setShowUserMenu(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Keyboard navigation support
  useEffect(() => {
    const handleKeyDown = (event) => {
      // ESC to close dropdowns
      if (event.key === 'Escape') {
        setShowNotificationPanel(false);
        setShowUserMenu(false);
        setIsMobileMenuOpen(false);
        setShowCommandPalette(false);
      }
      // Ctrl+K for command palette
      if ((event.metaKey || event.ctrlKey) && event.key === 'k') {
        event.preventDefault();
        setShowCommandPalette(true);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div className="app-container">
      {/* Navigation Loading Bar */}
      {isNavigating && (
        <div className="navigation-loading">
          <div className="loading-bar"></div>
        </div>
      )}

      {/* Command Palette */}
      {showCommandPalette && (
        <CommandPalette 
          onClose={() => setShowCommandPalette(false)}
          onNavigate={handleNavigation}
        />
      )}

      <nav className={`modern-navigation ${theme}`} role="navigation" aria-label="Main navigation">
        <div className="nav-brand" onClick={() => handleNavigation('/')}
             style={{ cursor: 'pointer' }}>
          <Logo size="medium" showText={true} />
        </div>

        {/* Mobile Menu Toggle */}
        <button 
          className="mobile-menu-toggle"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          aria-expanded={isMobileMenuOpen}
          aria-label="Toggle mobile menu"
        >
          <span></span>
          <span></span>
          <span></span>
        </button>

        {/* Desktop Navigation Menu */}
        <div className="nav-menu">
          {filteredMenuItems.map(item => (
            <button
              key={item.key}
              className={`nav-item ${currentView === item.key ? 'active' : ''} ${item.gradient}`}
              onClick={() => handleNavigation(item.path)}
              title={item.label}
              aria-current={currentView === item.key ? 'page' : undefined}
              aria-label={`Navigate to ${item.label}`}
            >
              <div className="nav-item-content">
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
              </div>
              {currentView === item.key && <div className="nav-indicator"></div>}
            </button>
          ))}
        </div>

        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="mobile-menu" role="menu">
            {filteredMenuItems.map(item => (
              <button
                key={item.key}
                className={`mobile-menu-item ${currentView === item.key ? 'active' : ''}`}
                onClick={() => handleNavigation(item.path)}
                role="menuitem"
                aria-label={`Navigate to ${item.label}`}
              >
                <span className="mobile-menu-icon">{item.icon}</span>
                <span className="mobile-menu-label">{item.label}</span>
              </button>
            ))}
          </div>
        )}

        <div className="nav-actions">
          <LanguageSwitcher position="inline" size="compact" />
          
          <div className="action-controls">
            <button 
              onClick={toggleTheme} 
              className="control-btn theme-toggle" 
              title="Toggle Theme"
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            >
              <span className="control-icon">{theme === 'dark' ? '☀️' : '🌙'}</span>
            </button>

            {/* Command Palette Trigger */}
            <button 
              className="control-btn command-palette-btn"
              onClick={() => setShowCommandPalette(true)}
              title="Open Command Palette (Ctrl+K)"
              aria-label="Open command palette"
            >
              <span className="control-icon">⌘</span>
            </button>
            
            {/* Enhanced Notifications */}
            <div className="notifications-container">
              <button 
                className="control-btn notifications-btn"
                onClick={() => setShowNotificationPanel(!showNotificationPanel)}
                aria-expanded={showNotificationPanel}
                aria-label="Notifications"
                title="Notifications"
              >
                <span className="control-icon">🔔</span>
                <span className="notification-badge">3</span>
              </button>
              
              {showNotificationPanel && (
                <NotificationPreferences 
                  isDropdown={true}
                  onClose={() => setShowNotificationPanel(false)}
                  showRecentNotifications={true}
                />
              )}
            </div>
          </div>
          
          {/* Enhanced User Section with Dropdown */}
          <div 
            className="user-section" 
            onClick={() => setShowUserMenu(!showUserMenu)}
            title={userEmail}
            role="button"
            aria-expanded={showUserMenu}
            aria-haspopup="menu"
          >
            <div className="user-avatar">
              <span className="avatar-text">{userInitial}</span>
              <div className="status-indicator online"></div>
            </div>
            <div className="user-details">
              <span className="user-name">{userName}</span>
              <span className="user-role">{isAdmin ? 'Administrator' : 'Security Analyst'}</span>
            </div>
            {isAdmin && <span className="badge-admin">Admin</span>}
            
            {/* User Dropdown Menu */}
            {showUserMenu && (
              <div className="user-dropdown" role="menu">
                <button 
                  onClick={(e) => { e.stopPropagation(); handleNavigation('/profile'); }}
                  role="menuitem"
                >
                  👤 Profile Settings
                </button>
                <button 
                  onClick={(e) => { e.stopPropagation(); handleNavigation('/preferences'); }}
                  role="menuitem"
                >
                  ⚙️ Preferences
                </button>
                <button 
                  onClick={(e) => { e.stopPropagation(); handleNavigation('/help'); }}
                  role="menuitem"
                >
                  ❓ Help & Support
                </button>
                <hr />
                <button 
                  onClick={(e) => { e.stopPropagation(); logout(); }}
                  className="logout-option"
                  role="menuitem"
                >
                  🚪 Sign Out
                </button>
              </div>
            )}
          </div>
        </div>
      </nav>

      {/* Breadcrumb Navigation */}
      {location.pathname !== '/' && (
        <div className="breadcrumb-nav" aria-label="Breadcrumb">
          <nav>
            {getBreadcrumbs().map((crumb, index) => (
              <span key={crumb.path} className="breadcrumb-item">
                <button 
                  onClick={() => handleNavigation(crumb.path)}
                  className={index === getBreadcrumbs().length - 1 ? 'current' : ''}
                  aria-current={index === getBreadcrumbs().length - 1 ? 'page' : undefined}
                >
                  {crumb.label}
                </button>
                {index < getBreadcrumbs().length - 1 && (
                  <span className="separator" aria-hidden="true">›</span>
                )}
              </span>
            ))}
          </nav>
        </div>
      )}

      <main className="main-content" role="main">
        <Outlet />
      </main>
    </div>
  );
};

export default MainLayout; 