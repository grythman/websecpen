// Enhanced WebSecPen Frontend Application - Full Integration
import React, { useState, useEffect, useContext } from 'react';
import { ErrorProvider } from './context/ErrorContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeContext, ThemeProvider } from './context/ThemeContext';

// Import existing components
import Dashboard from './components/Dashboard';
import Login from './components/Login';
import Profile from './components/Profile';
import FeedbackForm from './components/FeedbackForm';
import Onboarding from './components/Onboarding';
import Trends from './components/Trends';
import Badges from './components/Badges';
import Referral from './components/Referral';
import Upgrade from './components/Upgrade';
import StatsDashboard from './components/StatsDashboard';
import ScheduleForm from './components/ScheduleForm';
import ErrorDisplay from './components/ErrorDisplay';
import ErrorBoundary from './components/ErrorBoundary';
import Logo from './components/Logo';

// Import enhanced components if available
import EnhancedDashboard from './components/EnhancedDashboard';
import EnhancedAdminDashboard from './components/EnhancedAdminDashboard';
import AdminDashboard from './components/AdminDashboard';
import CustomScanForm from './components/CustomScanForm';
import ScanDiff from './components/ScanDiff';
import RealTimeScanProgress from './components/RealTimeScanProgress';
import VulnTrends from './components/VulnTrends';
import MfaSetup from './components/MfaSetup';
import TwoFactorAuth from './components/TwoFactorAuth';
import NotificationSettings from './components/NotificationSettings';
import NotificationPreferences from './components/NotificationPreferences';
import ApiKeyManager from './components/ApiKeyManager';
import ReportTemplate from './components/ReportTemplate';
import ReportTemplateManager from './components/ReportTemplateManager';
import AdminFeedback from './components/AdminFeedback';
import TeamAnnotations from './components/TeamAnnotations';
import Chat from './components/Chat';
import AdminHeatmap from './components/AdminHeatmap';
import VulnerabilityTagManager from './components/VulnerabilityTagManager';
import AiVulnerabilityPrioritizer from './components/AiVulnerabilityPrioritizer';

import './App.css';

// Error boundary for safe component rendering
const SafeComponent = ({ component: Component, fallback = null, ...props }) => {
  try {
    return Component ? <Component {...props} /> : fallback;
  } catch (error) {
    console.error('Component rendering error:', error);
    return <div className="error-fallback">Component failed to load</div>;
  }
};

// Navigation component
const Navigation = ({ currentView, setCurrentView, user, onLogout }) => {
  const { theme, toggleTheme } = useContext(ThemeContext);

  const menuItems = [
    { key: 'dashboard', label: 'Dashboard', icon: '📊', roles: ['user', 'admin'] },
    { key: 'scans', label: 'Security Scans', icon: '🔍', roles: ['user', 'admin'] },
    { key: 'vulnerabilities', label: 'Vulnerabilities', icon: '⚠️', roles: ['user', 'admin'] },
    { key: 'reports', label: 'Reports', icon: '📄', roles: ['user', 'admin'] },
    { key: 'team', label: 'Team', icon: '👥', roles: ['user', 'admin'] },
    { key: 'profile', label: 'Profile', icon: '👤', roles: ['user', 'admin'] },
    { key: 'admin', label: 'Admin', icon: '⚙️', roles: ['admin'] }
  ];

  const userRole = user?.role || 'user';
  const filteredMenuItems = menuItems.filter(item => 
    item.roles.includes(userRole)
  );

  return (
    <nav className="main-navigation">
      <div className="nav-brand">
        <Logo />
        <span className="brand-text">WebSecPen</span>
      </div>
      
      <div className="nav-menu">
        {filteredMenuItems.map(item => (
          <button
            key={item.key}
            className={`nav-item ${currentView === item.key ? 'active' : ''}`}
            onClick={() => setCurrentView(item.key)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
          </button>
        ))}
      </div>

      <div className="nav-actions">
        <button onClick={toggleTheme} className="theme-toggle">
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>
        <span className="user-info">
          {user?.email || 'User'}
        </span>
        <button onClick={onLogout} className="logout-button">
          Logout
        </button>
      </div>
    </nav>
  );
};

// Main App Content Component
const AppContent = () => {
  const { user, logout, isAuthenticated, isLoading } = useAuth();
  const [currentView, setCurrentView] = useState('dashboard');
  const [showOnboarding, setShowOnboarding] = useState(false);

  // Show onboarding for new users
  useEffect(() => {
    if (isAuthenticated && user && !user.preferences?.has_seen_tutorial) {
      setShowOnboarding(true);
    }
  }, [isAuthenticated, user]);

  // Show loading screen while checking authentication
  if (isLoading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading WebSecPen...</p>
        </div>
      </div>
    );
  }

  // Show login if not authenticated
  if (!isAuthenticated) {
    return (
      <div className="auth-container">
        <Login onSuccess={() => setCurrentView('dashboard')} />
      </div>
    );
  }

  // Show onboarding for new users
  if (showOnboarding) {
    return (
      <Onboarding 
        onComplete={() => {
          setShowOnboarding(false);
          setCurrentView('dashboard');
        }}
      />
    );
  }

  // Dashboard View Component
  const DashboardView = ({ user }) => (
    <div className="dashboard-container">
      <SafeComponent component={EnhancedDashboard} user={user} />
      <SafeComponent component={StatsDashboard} user={user} />
    </div>
  );

  // Scans View Component
  const ScansView = () => (
    <div className="scans-container">
      <SafeComponent component={CustomScanForm} />
      <SafeComponent component={RealTimeScanProgress} />
    </div>
  );

  // Vulnerabilities View Component
  const VulnerabilitiesView = () => (
    <div className="vulnerabilities-container">
      <SafeComponent component={VulnTrends} />
      <SafeComponent component={AiVulnerabilityPrioritizer} />
    </div>
  );

  // Reports View Component
  const ReportsView = () => (
    <div className="reports-container">
      <SafeComponent component={ReportTemplate} />
      <SafeComponent component={ReportTemplateManager} />
    </div>
  );

  // Team View Component
  const TeamView = () => (
    <div className="team-container">
      <SafeComponent component={TeamAnnotations} />
    </div>
  );

  // Profile View Component
  const ProfileView = () => (
    <div className="profile-container">
      <SafeComponent component={Profile} user={user} />
      <SafeComponent component={MfaSetup} />
      <SafeComponent component={TwoFactorAuth} />
      <SafeComponent component={NotificationSettings} />
      <SafeComponent component={NotificationPreferences} />
      <SafeComponent component={ApiKeyManager} />
    </div>
  );

  // Admin View Component
  const AdminView = () => (
    <div className="admin-container">
      <SafeComponent component={EnhancedAdminDashboard} />
      <SafeComponent component={AdminDashboard} />
      <SafeComponent component={AdminFeedback} />
      <SafeComponent component={AdminHeatmap} />
      <SafeComponent component={VulnerabilityTagManager} />
    </div>
  );

  // Render current view
  const renderCurrentView = () => {
    switch (currentView) {
      case 'dashboard':
        return <DashboardView user={user} />;
      case 'scans':
        return <ScansView />;
      case 'vulnerabilities':
        return <VulnerabilitiesView />;
      case 'reports':
        return <ReportsView />;
      case 'team':
        return <TeamView />;
      case 'profile':
        return <ProfileView />;
      case 'admin':
        return user?.role === 'admin' ? <AdminView /> : <DashboardView user={user} />;
      default:
        return <DashboardView user={user} />;
    }
  };

  return (
    <div className="app-container">
      <Navigation 
        currentView={currentView}
        setCurrentView={setCurrentView}
        user={user}
        onLogout={logout}
      />
      
      <main className="main-content">
        {renderCurrentView()}
      </main>
      
      <SafeComponent component={FeedbackForm} />
    </div>
  );
};

// Main App Component with Providers
const App = () => {
  return (
    <ErrorProvider>
      <ThemeProvider>
        <AuthProvider>
          <ErrorDisplay />
          <ErrorBoundary>
            <AppContent />
          </ErrorBoundary>
        </AuthProvider>
      </ThemeProvider>
    </ErrorProvider>
  );
};

export default App;
