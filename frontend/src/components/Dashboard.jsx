// src/components/Dashboard.jsx
import React from 'react';
import './Dashboard.css';

const Dashboard = () => {
  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>Security Dashboard</h2>
        <p>Welcome to WebSecPen - Your AI-Powered Security Scanner</p>
      </div>
      
      <div className="dashboard-content">
        <div className="dashboard-cards">
          <div className="dashboard-card">
            <h3>🔍 Recent Scans</h3>
            <p>View your latest security scans and results</p>
          </div>
          
          <div className="dashboard-card">
            <h3>⚠️ Vulnerabilities</h3>
            <p>Monitor detected security vulnerabilities</p>
          </div>
          
          <div className="dashboard-card">
            <h3>📊 Statistics</h3>
            <p>Analyze your security posture trends</p>
          </div>
          
          <div className="dashboard-card">
            <h3>🛡️ Protection Status</h3>
            <p>Current security protection level</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard; 