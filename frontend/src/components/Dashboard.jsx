// src/components/Dashboard.jsx
import React, { useContext, useState } from 'react';
import { ThemeContext } from '../ThemeContext.jsx';
import Logo from './Logo.jsx';
import ScanForm from './ScanForm.jsx';
import ScanHistory from './ScanHistory.jsx';
import ResultPreview from './ResultPreview.jsx';
import FeedbackForm from './FeedbackForm.jsx';
import Onboarding from './Onboarding.jsx';
import './Dashboard.css';

const Dashboard = ({ onLogout }) => {
  const { theme, toggleTheme } = useContext(ThemeContext);
  const [showFeedbackModal, setShowFeedbackModal] = useState(false);

  const handleLogout = () => {
    localStorage.removeItem('isAuthenticated');
    console.log('User logged out');
    
    // Call the onLogout callback to update parent component
    if (onLogout) {
      onLogout();
    }
  };

  return (
    <div className={`dashboard ${theme}`}>
      {/* Navigation Bar */}
      <nav className="dashboard-nav">
        <div className="nav-brand">
          <Logo size="medium" showText={true} />
        </div>
        <div className="nav-menu">
          <button className="nav-item active">Dashboard</button>
          <button className="nav-item">Scan History</button>
          <button className="nav-item">Reports</button>
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
          <h2>Security Scanning Dashboard</h2>
          <p>Start a new scan or review your recent security assessments</p>
        </div>

        <div className="dashboard-grid">
          {/* Scan Form Section */}
          <section className="dashboard-section scan-section">
            <div className="section-header">
              <h3>Start New Scan</h3>
              <span className="section-icon">🔍</span>
            </div>
            <div className="section-content">
              <ScanForm />
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
                  <div className="stat-value">12</div>
                  <div className="stat-label">Total Scans</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">3</div>
                  <div className="stat-label">High Risk</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">7</div>
                  <div className="stat-label">Medium Risk</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">2</div>
                  <div className="stat-label">Low Risk</div>
                </div>
              </div>
            </div>
          </section>
        </div>
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

export default Dashboard; 