// src/components/EnhancedDashboard.jsx
import React, { useContext, useState, useEffect } from 'react';
import { ThemeContext } from '../ThemeContext.jsx';
import Logo from './Logo.jsx';
import ScanForm from './ScanForm.jsx';
import ScanHistory from './ScanHistory.jsx';
import ResultPreview from './ResultPreview.jsx';
import FeedbackForm from './FeedbackForm.jsx';
import Onboarding from './Onboarding.jsx';
import Trends from './Trends.jsx';
import Badges from './Badges.jsx';
import Upgrade from './Upgrade.jsx';
import NotificationSettings from './NotificationSettings.jsx';
import AdminDashboard from './AdminDashboard.jsx';
import VulnTrends from './VulnTrends.jsx';
import NotificationPreferences from './NotificationPreferences.jsx';
import ApiKeyManager from './ApiKeyManager.jsx';
import './Dashboard.css';
import './EnhancedDashboard.css';

const EnhancedDashboard = ({ onLogout }) => {
  const { theme, toggleTheme } = useContext(ThemeContext);
  const [showFeedbackModal, setShowFeedbackModal] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [userRole, setUserRole] = useState('free');
  const [scanCount, setScanCount] = useState(0);
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    // Check user subscription status
    const checkSubscription = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await fetch('/api/subscription/status', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
        
        if (response.ok) {
          const data = await response.json();
          setUserRole(data.role);
        }

        // Check if user is admin (from JWT token or separate endpoint)
        const profileResponse = await fetch('/api/auth/profile', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
        
        if (profileResponse.ok) {
          const profile = await profileResponse.json();
          setIsAdmin(profile.is_admin || false);
        }
      } catch (error) {
        console.error('Failed to check subscription status:', error);
      }
    };

    checkSubscription();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('token');
    console.log('User logged out');
    
    if (onLogout) {
      onLogout();
    }
  };

  const navigationItems = [
    { id: 'dashboard', label: 'Dashboard', icon: '🏠' },
    { id: 'trends', label: 'Trends', icon: '📊' },
    { id: 'vuln-trends', label: 'Analysis', icon: '📈' },
    { id: 'badges', label: 'Achievements', icon: '🏅' },
    { id: 'notifications', label: 'Notifications', icon: '🔔' },
    { id: 'preferences', label: 'Preferences', icon: '⚙️' },
    { id: 'api-keys', label: 'API Keys', icon: '🔑' },
    ...(userRole === 'free' ? [{ id: 'upgrade', label: 'Upgrade', icon: '⭐' }] : []),
    ...(isAdmin ? [{ id: 'admin', label: 'Admin', icon: '🛠️' }] : []),
  ];

  const renderTabContent = () => {
    switch (activeTab) {
      case 'trends':
        return <Trends />;
      case 'vuln-trends':
        return <VulnTrends />;
      case 'badges':
        return <Badges />;
      case 'notifications':
        return <NotificationSettings />;
      case 'preferences':
        return <NotificationPreferences />;
      case 'api-keys':
        return <ApiKeyManager />;
      case 'admin':
        return isAdmin ? <AdminDashboard /> : null;
      case 'upgrade':
        return userRole === 'free' ? <Upgrade /> : null;
      default:
        return (
          <div className="dashboard-grid">
            {/* Scan Form Section */}
            <section className="dashboard-section scan-section">
              <div className="section-header">
                <h3>Start New Scan</h3>
                <span className="section-icon">🔍</span>
                {userRole === 'premium' && (
                  <span className="premium-badge">Premium</span>
                )}
              </div>
              <div className="section-content">
                <ScanForm userRole={userRole} />
              </div>
            </section>

            {/* Recent Scans Section */}
            <section className="dashboard-section history-section">
              <div className="section-header">
                <h3>Recent Scans</h3>
                <span className="section-icon">📊</span>
              </div>
              <div className="section-content">
                <ScanHistory />
              </div>
            </section>

            {/* Result Preview Section */}
            <section className="dashboard-section result-section">
              <div className="section-header">
                <h3>Latest Results</h3>
                <span className="section-icon">⚠️</span>
              </div>
              <div className="section-content">
                <ResultPreview />
              </div>
            </section>

            {/* Quick Stats Section */}
            <section className="dashboard-section stats-section">
              <div className="section-header">
                <h3>Quick Stats</h3>
                <span className="section-icon">📈</span>
              </div>
              <div className="section-content">
                <div className="stats-grid">
                  <div className="stat-item">
                    <div className="stat-value">{scanCount}</div>
                    <div className="stat-label">Total Scans</div>
                  </div>
                  <div className="stat-item">
                    <div className="stat-value">{userRole === 'premium' ? '∞' : '5'}</div>
                    <div className="stat-label">Scan Limit</div>
                  </div>
                  <div className="stat-item">
                    <div className="stat-value">{userRole}</div>
                    <div className="stat-label">Account Type</div>
                  </div>
                  <div className="stat-item">
                    <div className="stat-value">
                      {userRole === 'premium' ? (
                        <span className="premium-icon">👑</span>
                      ) : (
                        <button 
                          className="upgrade-mini-btn"
                          onClick={() => setActiveTab('upgrade')}
                        >
                          Upgrade
                        </button>
                      )}
                    </div>
                    <div className="stat-label">Status</div>
                  </div>
                </div>
              </div>
            </section>
          </div>
        );
    }
  };

  return (
    <div className={`enhanced-dashboard ${theme}`}>
      {/* Navigation Bar */}
      <nav className="dashboard-nav">
        <div className="nav-brand">
          <Logo size="medium" showText={true} />
          {userRole === 'premium' && (
            <span className="premium-indicator">
              <span className="crown-icon">👑</span>
              Premium
            </span>
          )}
        </div>
        <div className="nav-menu">
          {navigationItems.map(item => (
            <button 
              key={item.id}
              className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </button>
          ))}
          <button 
            className="nav-item"
            onClick={() => setShowFeedbackModal(true)}
            title="Send Feedback"
          >
            💬 Feedback
          </button>
          <button className="theme-toggle" onClick={toggleTheme}>
            {theme === 'light' ? '🌙' : '☀️'}
          </button>
          <button className="nav-item logout" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </nav>

      {/* Main Dashboard Content */}
      <main className="dashboard-main">
        <div className="dashboard-header">
          <h2>
            {activeTab === 'dashboard' && 'Security Scanning Dashboard'}
            {activeTab === 'trends' && 'Vulnerability Trends'}
            {activeTab === 'badges' && 'Your Achievements'}
            {activeTab === 'upgrade' && 'Upgrade to Premium'}
          </h2>
          <p>
            {activeTab === 'dashboard' && 'Start a new scan or review your recent security assessments'}
            {activeTab === 'trends' && 'Analyze vulnerability patterns and security improvements over time'}
            {activeTab === 'badges' && 'Track your progress and celebrate security milestones'}
            {activeTab === 'upgrade' && 'Unlock unlimited scans and advanced features'}
          </p>
        </div>

        {renderTabContent()}
      </main>
      
      {/* Feedback Modal */}
      {showFeedbackModal && (
        <FeedbackForm 
          isModal={true} 
          onClose={() => setShowFeedbackModal(false)} 
        />
      )}
      
      {/* User Onboarding Tour */}
      <Onboarding />
    </div>
  );
};

export default EnhancedDashboard;
