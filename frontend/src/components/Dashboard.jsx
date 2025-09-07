// src/components/Dashboard.jsx - Modern Dashboard (Replaced with Better Design)
import React, { useState, useEffect, useContext } from 'react';
import { useTranslation } from 'react-i18next';
import { ThemeContext } from '../context/ThemeContext.jsx';
import { useAuth } from '../context/AuthContext';
import LanguageSwitcher from './LanguageSwitcher.jsx';
import './ModernDashboard.css';
import KpiCard from './ui/KpiCard.jsx';

const Dashboard = () => {
  const { user } = useAuth();
  const { theme, toggleTheme } = useContext(ThemeContext);
  const { t, i18n } = useTranslation();
  
  const [stats, setStats] = useState({
        totalScans: 12,
    vulnerabilitiesFound: 8,
    highRiskScore: 3,
        lastScan: '2 hours ago'
      });

  const [recentScans, setRecentScans] = useState([
    { id: 1, target: 'example.com', status: 'completed', vulnerabilities: 2, date: '2025-09-06', severity: 'medium' },
    { id: 2, target: 'test.com', status: 'in_progress', vulnerabilities: 0, date: '2025-09-06', severity: 'low' },
    { id: 3, target: 'demo.com', status: 'completed', vulnerabilities: 5, date: '2025-09-05', severity: 'high' },
  ]);

  const [recentActivity, setRecentActivity] = useState([
    { id: 1, action: 'Started scan of example.com', time: '2 hours ago', type: 'scan', icon: '🔍' },
    { id: 2, action: 'Found 3 vulnerabilities in test.com', time: '4 hours ago', type: 'vulnerability', icon: '⚠️' },
    { id: 3, action: 'Completed scan of demo.com', time: '1 day ago', type: 'completed', icon: '✅' },
    { id: 4, action: 'Updated security policies', time: '2 days ago', type: 'update', icon: '🔧' },
  ]);

  const [isLoading, setIsLoading] = useState(false);

  const quickActions = [
    { id: 1, title: 'New Scan', description: 'Start a security scan', icon: '🔍', color: 'blue', action: 'scan' },
    { id: 2, title: 'View Reports', description: 'Check scan results', icon: '📊', color: 'green', action: 'reports' },
    { id: 3, title: 'Vulnerabilities', description: 'Review security issues', icon: '⚠️', color: 'orange', action: 'vulnerabilities' },
    { id: 4, title: 'Settings', description: 'Configure scanner', icon: '⚙️', color: 'purple', action: 'settings' },
  ];

  const securityStatus = [
    { label: 'Scanner Active', status: 'active', icon: '🟢' },
    { label: 'Database Connected', status: 'connected', icon: '🟢' },
    { label: 'API Connected', status: 'connected', icon: '🟢' },
    { label: 'Updates Available', status: 'warning', icon: '🟡' },
  ];

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'success';
      case 'in_progress': return 'warning';
      case 'failed': return 'error';
      default: return 'default';
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  if (isLoading) {
    return (
      <div className={`modern-dashboard ${theme}`}>
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`modern-dashboard ${theme}`}>
      {/* Language Switcher - positioned fixed */}
      <div className="dashboard-controls">
        <LanguageSwitcher position="fixed" size="small" className={theme} />
        <button className="theme-toggle-fixed" onClick={toggleTheme}>
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>
      </div>
      
      {/* Main Content */}
      <main className="dashboard-main-content">
        {/* Welcome Section */}
        <section className="welcome-section">
          <div className="welcome-content">
            <h2>{t('welcome')}, {user?.first_name || 'Admin'}! 👋</h2>
            <p>Comprehensive security monitoring and analysis</p>
          </div>
          <div className="welcome-actions">
            <button className="primary-btn">
              <span className="btn-icon">🚀</span>
              {t('scan_button')}
            </button>
          </div>
        </section>

        {/* Stats Overview */}
        <section className="stats-section">
          <div className="stats-grid">
            <KpiCard icon="🔍" label={t('total_scans')} value={stats.totalScans} delta={"+12%"} tone="primary" />
            <KpiCard icon="⚠️" label={t('vulnerabilities_found')} value={stats.vulnerabilitiesFound} delta={"-5%"} tone="warning" />
            <KpiCard icon="🚨" label={'High Risk Issues'} value={stats.highRiskScore} delta={"0%"} tone="danger" />
            <KpiCard icon="⏰" label={'Last Scan'} value={stats.lastScan} delta={""} tone="success" />
          </div>
        </section>

        {/* Main Dashboard Grid */}
        <div className="dashboard-grid">
          {/* Recent Activity */}
          <section className="dashboard-card recent-activity">
            <div className="card-header">
              <div className="header-left">
                <h3>🔍 {t('recent_activity')}</h3>
                <span className="card-subtitle">Latest security events</span>
              </div>
              <button className="header-action">View All</button>
            </div>
            <div className="card-content">
              <div className="activity-list">
                {recentScans.map((scan) => (
                  <div key={scan.id} className="activity-item">
                    <div className="activity-icon">
                      <div className={`icon-wrapper ${getStatusColor(scan.status)}`}>
                        {scan.status === 'completed' ? '✅' : scan.status === 'in_progress' ? '⏳' : '❌'}
                      </div>
                    </div>
                    <div className="activity-content">
                      <div className="activity-title">{scan.target}</div>
                      <div className="activity-meta">
                        <span className="activity-date">{scan.date}</span>
                        <span className={`status-badge ${getStatusColor(scan.status)}`}>
                          {scan.status.replace('_', ' ')}
                        </span>
                        <span className={`severity-badge ${getSeverityColor(scan.severity)}`}>
                          {scan.vulnerabilities} vulnerabilities
                        </span>
                      </div>
                    </div>
                    <button className="activity-action">→</button>
                    </div>
                  ))}
                </div>
              <button className="view-more-btn">{t('new_scan')}</button>
            </div>
          </section>

          {/* Quick Actions */}
          <section className="dashboard-card quick-actions">
            <div className="card-header">
              <div className="header-left">
              <h3>⚡ Quick Actions</h3>
                <span className="card-subtitle">Common tasks</span>
              </div>
            </div>
            <div className="card-content">
              <div className="actions-grid">
                {quickActions.map((action) => (
                  <button key={action.id} className={`action-card ${action.color}`}>
                    <div className="action-icon">{action.icon}</div>
                    <div className="action-title">{action.title}</div>
                    <div className="action-description">{action.description}</div>
                </button>
                ))}
              </div>
            </div>
          </section>

          {/* Security Status */}
          <section className="dashboard-card security-status">
            <div className="card-header">
              <div className="header-left">
              <h3>🛡️ Security Status</h3>
                <span className="card-subtitle">System health</span>
              </div>
              <div className="status-indicator all-good">All Systems Operational</div>
            </div>
            <div className="card-content">
              <div className="status-list">
                {securityStatus.map((item, index) => (
                  <div key={index} className="status-item">
                    <div className="status-icon">{item.icon}</div>
                    <div className="status-content">
                      <div className="status-label">{item.label}</div>
                      <div className={`status-value ${item.status}`}>
                        {item.status === 'active' || item.status === 'connected' ? 'Online' : 'Attention Required'}
                </div>
                </div>
                </div>
                ))}
              </div>
            </div>
          </section>

          {/* Recent Activity Timeline */}
          <section className="dashboard-card activity-timeline">
            <div className="card-header">
              <div className="header-left">
                <h3>📈 Activity Timeline</h3>
                <span className="card-subtitle">Recent events</span>
          </div>
              <button className="header-action">View History</button>
            </div>
            <div className="card-content">
              <div className="timeline">
                {recentActivity.map((activity) => (
                  <div key={activity.id} className="timeline-item">
                    <div className="timeline-icon">{activity.icon}</div>
                    <div className="timeline-content">
                      <div className="timeline-title">{activity.action}</div>
                      <div className="timeline-time">{activity.time}</div>
                </div>
                  </div>
                ))}
              </div>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
