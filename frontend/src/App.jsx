// Enhanced WebSecPen Frontend Application - Full Integration
import React, { useState, useEffect, useContext } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeContext, ThemeProvider } from './ThemeContext';

// Import existing components (зөвхөн байгаа components-ыг import хийх)
import Dashboard from './components/Dashboard';
import Login from './components/Login';
import ScanForm from './components/ScanForm';
import ScanHistory from './components/ScanHistory';
import ResultPreview from './components/ResultPreview';
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

// Navigation component
const Navigation = ({ currentView, setCurrentView, user, onLogout }) => {
  const { theme, toggleTheme } = useContext(ThemeContext);
  
  const navItems = [
    { key: 'dashboard', label: 'Dashboard', icon: '📊' },
    { key: 'scans', label: 'Security Scans', icon: '🔍' },
    { key: 'vulnerabilities', label: 'Vulnerabilities', icon: '⚠️' },
    { key: 'reports', label: 'Reports', icon: '📄' },
    { key: 'analytics', label: 'Analytics', icon: '📈' },
    { key: 'team', label: 'Team', icon: '👥' },
    { key: 'profile', label: 'Profile', icon: '👤' },
  ];

  if (user?.role === 'admin') {
    navItems.push({ key: 'admin', label: 'Admin', icon: '⚙️' });
  }

  return (
    <nav className={`main-navigation ${theme}`}>
      <div className="nav-brand">
        <Logo size="medium" showText={true} />
      </div>
      
      <div className="nav-menu">
        {navItems.map(item => (
          <button
            key={item.key}
            onClick={() => setCurrentView(item.key)}
            className={`nav-item ${currentView === item.key ? 'active' : ''}`}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
          </button>
        ))}
      </div>
      
      <div className="nav-actions">
        <button className="theme-toggle" onClick={toggleTheme}>
          {theme === 'light' ? '🌙' : '☀️'}
        </button>
        
        <div className="user-menu">
          <div className="user-avatar">
            {user?.name?.charAt(0) || user?.email?.charAt(0) || 'U'}
          </div>
          <span className="user-name">{user?.name || user?.email}</span>
          <button className="logout-btn" onClick={onLogout}>
            Logout
          </button>
        </div>
      </div>
    </nav>
  );
};

// Safe component wrapper
const SafeComponent = ({ component: Component, fallback, ...props }) => {
  try {
    return <Component {...props} />;
  } catch (error) {
    console.warn('Component render error:', error);
    return fallback || <div className="error-display">Component not available</div>;
  }
};

// Main dashboard view with tabs
const DashboardView = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const { user } = useAuth();

  const tabs = [
    { 
      key: 'overview', 
      label: 'Overview', 
      component: <SafeComponent component={EnhancedDashboard} fallback={<Dashboard />} />
    },
    { 
      key: 'stats', 
      label: 'Statistics', 
      component: <SafeComponent component={StatsDashboard} />
    },
    { 
      key: 'trends', 
      label: 'Trends', 
      component: <SafeComponent component={Trends} />
    },
    { 
      key: 'heatmap', 
      label: 'Heatmap', 
      component: <SafeComponent component={AdminHeatmap} />
    },
  ];

  if (user?.role === 'admin') {
    tabs.push({ 
      key: 'admin', 
      label: 'Admin Dashboard', 
      component: <SafeComponent component={EnhancedAdminDashboard} fallback={<AdminDashboard />} />
    });
  }

  return (
    <div className="dashboard-view">
      <div className="tab-navigation">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`tab-item ${activeTab === tab.key ? 'active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      
      <div className="tab-content">
        {tabs.find(tab => tab.key === activeTab)?.component}
      </div>
    </div>
  );
};

// Security scans view
const SecurityScansView = () => {
  const [activeTab, setActiveTab] = useState('new-scan');

  const tabs = [
    { 
      key: 'new-scan', 
      label: 'New Scan', 
      component: <SafeComponent component={ScanForm} />
    },
    { 
      key: 'custom-scan', 
      label: 'Custom Scan', 
      component: <SafeComponent component={CustomScanForm} fallback={<ScanForm />} />
    },
    { 
      key: 'schedule', 
      label: 'Schedule Scan', 
      component: <SafeComponent component={ScheduleForm} />
    },
    { 
      key: 'history', 
      label: 'Scan History', 
      component: <SafeComponent component={ScanHistory} />
    },
    { 
      key: 'progress', 
      label: 'Real-time Progress', 
      component: <SafeComponent component={RealTimeScanProgress} />
    },
    { 
      key: 'diff', 
      label: 'Scan Comparison', 
      component: <SafeComponent component={ScanDiff} />
    },
  ];

  return (
    <div className="security-scans-view">
      <div className="tab-navigation">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`tab-item ${activeTab === tab.key ? 'active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      
      <div className="tab-content">
        {tabs.find(tab => tab.key === activeTab)?.component}
      </div>
    </div>
  );
};

// Vulnerabilities view
const VulnerabilitiesView = () => {
  const [activeTab, setActiveTab] = useState('trends');

  const tabs = [
    { 
      key: 'trends', 
      label: 'Vulnerability Trends', 
      component: <SafeComponent component={VulnTrends} />
    },
    { 
      key: 'prioritizer', 
      label: 'AI Prioritizer', 
      component: <SafeComponent component={AiVulnerabilityPrioritizer} />
    },
    { 
      key: 'tag-manager', 
      label: 'Tag Manager', 
      component: <SafeComponent component={VulnerabilityTagManager} />
    },
    { 
      key: 'annotations', 
      label: 'Team Annotations', 
      component: <SafeComponent component={TeamAnnotations} />
    },
  ];

  return (
    <div className="vulnerabilities-view">
      <div className="tab-navigation">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`tab-item ${activeTab === tab.key ? 'active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      
      <div className="tab-content">
        {tabs.find(tab => tab.key === activeTab)?.component}
      </div>
    </div>
  );
};

// Reports view
const ReportsView = () => {
  const [activeTab, setActiveTab] = useState('templates');

  const tabs = [
    { 
      key: 'templates', 
      label: 'Report Templates', 
      component: <SafeComponent component={ReportTemplate} />
    },
    { 
      key: 'manager', 
      label: 'Template Manager', 
      component: <SafeComponent component={ReportTemplateManager} />
    },
    { 
      key: 'preview', 
      label: 'Result Preview', 
      component: <SafeComponent component={ResultPreview} />
    },
  ];

  return (
    <div className="reports-view">
      <div className="tab-navigation">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`tab-item ${activeTab === tab.key ? 'active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      
      <div className="tab-content">
        {tabs.find(tab => tab.key === activeTab)?.component}
      </div>
    </div>
  );
};

// Team view
const TeamView = () => {
  const [activeTab, setActiveTab] = useState('chat');

  const tabs = [
    { 
      key: 'chat', 
      label: 'Team Chat', 
      component: <SafeComponent component={Chat} />
    },
    { 
      key: 'annotations', 
      label: 'Annotations', 
      component: <SafeComponent component={TeamAnnotations} />
    },
    { 
      key: 'referral', 
      label: 'Referral Program', 
      component: <SafeComponent component={Referral} />
    },
    { 
      key: 'badges', 
      label: 'Team Badges', 
      component: <SafeComponent component={Badges} />
    },
  ];

  return (
    <div className="team-view">
      <div className="tab-navigation">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`tab-item ${activeTab === tab.key ? 'active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      
      <div className="tab-content">
        {tabs.find(tab => tab.key === activeTab)?.component}
      </div>
    </div>
  );
};

// Profile view
const ProfileView = () => {
  const [activeTab, setActiveTab] = useState('profile');

  const tabs = [
    { 
      key: 'profile', 
      label: 'Profile Settings', 
      component: <SafeComponent component={Profile} />
    },
    { 
      key: 'mfa', 
      label: 'MFA Setup', 
      component: <SafeComponent component={MfaSetup} />
    },
    { 
      key: 'notifications', 
      label: 'Notifications', 
      component: <SafeComponent component={NotificationSettings} />
    },
    { 
      key: 'preferences', 
      label: 'Preferences', 
      component: <SafeComponent component={NotificationPreferences} />
    },
    { 
      key: 'api-keys', 
      label: 'API Keys', 
      component: <SafeComponent component={ApiKeyManager} />
    },
    { 
      key: 'upgrade', 
      label: 'Upgrade Account', 
      component: <SafeComponent component={Upgrade} />
    },
  ];

  return (
    <div className="profile-view">
      <div className="tab-navigation">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`tab-item ${activeTab === tab.key ? 'active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      
      <div className="tab-content">
        {tabs.find(tab => tab.key === activeTab)?.component}
      </div>
    </div>
  );
};

// Admin view
const AdminView = () => {
  const [activeTab, setActiveTab] = useState('dashboard');

  const tabs = [
    { 
      key: 'dashboard', 
      label: 'Admin Dashboard', 
      component: <SafeComponent component={AdminDashboard} />
    },
    { 
      key: 'enhanced', 
      label: 'Enhanced Dashboard', 
      component: <SafeComponent component={EnhancedAdminDashboard} fallback={<AdminDashboard />} />
    },
    { 
      key: 'feedback', 
      label: 'User Feedback', 
      component: <SafeComponent component={AdminFeedback} />
    },
    { 
      key: 'heatmap', 
      label: 'System Heatmap', 
      component: <SafeComponent component={AdminHeatmap} />
    },
  ];

  return (
    <div className="admin-view">
      <div className="tab-navigation">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`tab-item ${activeTab === tab.key ? 'active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      
      <div className="tab-content">
        {tabs.find(tab => tab.key === activeTab)?.component}
      </div>
    </div>
  );
};

// Main app content
function AppContent() {
  const { isAuthenticated, isLoading, user, logout } = useAuth();
  const [currentView, setCurrentView] = useState('dashboard');
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [error, setError] = useState(null);

  // Check if user needs onboarding
  useEffect(() => {
    if (isAuthenticated && user && !user.hasSeenOnboarding) {
      setShowOnboarding(true);
    }
  }, [isAuthenticated, user]);

  // Show loading
  if (isLoading) {
    return (
      <div className="loading-screen">
        <Logo size="large" showText={true} />
        <div className="loading-spinner"></div>
        <p>Loading WebSecPen...</p>
      </div>
    );
  }

  // Show login if not authenticated
  if (!isAuthenticated) {
    return (
      <div className="auth-screen">
        <Login onSuccess={() => setCurrentView('dashboard')} />
        {/* Also show TwoFactorAuth if needed */}
        <SafeComponent component={TwoFactorAuth} />
      </div>
    );
  }

  // Show onboarding for new users
  if (showOnboarding) {
    return (
      <Onboarding onComplete={() => setShowOnboarding(false)} />
    );
  }

  // Main application
  return (
    <div className="app-container">
      {error && <ErrorDisplay error={error} onDismiss={() => setError(null)} />}
      
      <Navigation 
        currentView={currentView}
        setCurrentView={setCurrentView}
        user={user}
        onLogout={logout}
      />
      
      <main className="main-content">
        {currentView === 'dashboard' && <DashboardView />}
        {currentView === 'scans' && <SecurityScansView />}
        {currentView === 'vulnerabilities' && <VulnerabilitiesView />}
        {currentView === 'reports' && <ReportsView />}
        {currentView === 'analytics' && <SafeComponent component={StatsDashboard} />}
        {currentView === 'team' && <TeamView />}
        {currentView === 'profile' && <ProfileView />}
        {currentView === 'admin' && user?.role === 'admin' && <AdminView />}
      </main>
      
      {/* Global components */}
      <SafeComponent component={FeedbackForm} />
    </div>
  );
}

// Main App wrapper with all providers
function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
