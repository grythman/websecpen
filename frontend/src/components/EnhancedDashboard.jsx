// src/components/EnhancedDashboard.jsx
import React, { useState, useEffect, useContext } from 'react';
import { ThemeContext } from '../context/ThemeContext.jsx';
import Dashboard from './Dashboard.jsx';
import CustomScanForm from './CustomScanForm.jsx';
import StatsDashboard from './StatsDashboard.jsx';
import './EnhancedDashboard.css';

const EnhancedDashboard = ({ userRole = 'user' }) => {
  const { theme, toggleTheme } = useContext(ThemeContext);
  const [activeSection, setActiveSection] = useState('overview');
  const [isDarkMode, setIsDarkMode] = useState(theme === 'dark');

  useEffect(() => {
    setIsDarkMode(theme === 'dark');
  }, [theme]);

  const sectionComponents = {
    overview: <Dashboard />,
    scanning: <CustomScanForm userRole={userRole} />,
    statistics: <StatsDashboard />,
    recent: <Dashboard />
  };

  const sections = [
    { key: 'overview', label: 'Overview', icon: '📊' },
    { key: 'scanning', label: 'New Scan', icon: '🔍' },
    { key: 'statistics', label: 'Statistics', icon: '📈' },
    { key: 'recent', label: 'Recent Activity', icon: '🕒' }
  ];

  return (
    <div className={`enhanced-dashboard ${theme}`}>
      <div className="dashboard-header">
        <div className="header-title">
          <h1>Enhanced Security Dashboard</h1>
          <p>Comprehensive security monitoring and analysis</p>
        </div>
        
        <div className="header-controls">
          <button 
            onClick={toggleTheme}
            className="theme-toggle-btn"
            aria-label="Toggle theme"
          >
            {isDarkMode ? '☀️' : '🌙'}
          </button>
        </div>
      </div>

      <div className="dashboard-navigation">
        {sections.map(section => (
          <button
            key={section.key}
            className={`nav-section ${activeSection === section.key ? 'active' : ''}`}
            onClick={() => setActiveSection(section.key)}
          >
            <span className="section-icon">{section.icon}</span>
            <span className="section-label">{section.label}</span>
          </button>
        ))}
      </div>

      <div className="dashboard-content">
        <div className="content-wrapper">
          {sectionComponents[activeSection] || <Dashboard />}
        </div>
      </div>

      <div className="dashboard-footer">
        <div className="footer-stats">
          <div className="stat-item">
            <span className="stat-label">Theme</span>
            <span className="stat-value">{theme === 'dark' ? 'Dark' : 'Light'} Mode</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">User Role</span>
            <span className="stat-value">{userRole}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Active Section</span>
            <span className="stat-value">{sections.find(s => s.key === activeSection)?.label}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EnhancedDashboard;
