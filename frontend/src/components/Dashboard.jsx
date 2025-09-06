// src/components/Dashboard.jsx
import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import './Dashboard.css';

const Dashboard = () => {
  const { user } = useAuth();
  const [stats, setStats] = useState({
    totalScans: 0,
    vulnerabilities: 0,
    highRisk: 0,
    lastScan: 'Never'
  });

  const [recentScans, setRecentScans] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Simulate loading
    const timer = setTimeout(() => {
      // Mock data for demonstration
      setStats({
        totalScans: 12,
        vulnerabilities: 8,
        highRisk: 3,
        lastScan: '2 hours ago'
      });

      setRecentScans([
        { id: 1, target: 'example.com', status: 'Completed', vulnerabilities: 2, date: '2025-09-06' },
        { id: 2, target: 'test.com', status: 'In Progress', vulnerabilities: 0, date: '2025-09-06' },
        { id: 3, target: 'demo.com', status: 'Completed', vulnerabilities: 5, date: '2025-09-05' },
        { id: 4, target: 'sample.com', status: 'Completed', vulnerabilities: 1, date: '2025-09-05' }
      ]);
      
      setIsLoading(false);
    }, 1000);

    return () => clearTimeout(timer);
  }, []);

  if (isLoading) {
    return (
      <div className="dashboard">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>Security Dashboard</h2>
        <p>Welcome back, {user?.first_name || 'User'}! Here's your security overview.</p>
      </div>
      
      <div className="dashboard-content">
        {/* Stats Overview */}
        <div className="stats-overview">
          <div className="stat-card">
            <div className="stat-icon">🔍</div>
            <div className="stat-content">
              <h3>{stats.totalScans}</h3>
              <p>Total Scans</p>
            </div>
          </div>
          
          <div className="stat-card">
            <div className="stat-icon">⚠️</div>
            <div className="stat-content">
              <h3>{stats.vulnerabilities}</h3>
              <p>Vulnerabilities</p>
            </div>
          </div>
          
          <div className="stat-card">
            <div className="stat-icon">🚨</div>
            <div className="stat-content">
              <h3>{stats.highRisk}</h3>
              <p>High Risk</p>
            </div>
          </div>
          
          <div className="stat-card">
            <div className="stat-icon">⏰</div>
            <div className="stat-content">
              <h3>{stats.lastScan}</h3>
              <p>Last Scan</p>
            </div>
          </div>
        </div>

        {/* Main Content Grid */}
        <div className="dashboard-grid">
          {/* Recent Scans */}
          <div className="dashboard-section">
            <div className="section-header">
              <h3>🔍 Recent Scans</h3>
              <button className="btn-primary">New Scan</button>
            </div>
            <div className="section-content">
              {recentScans.length > 0 ? (
                <div className="scan-list">
                  {recentScans.map(scan => (
                    <div key={scan.id} className="scan-item">
                      <div className="scan-info">
                        <h4>{scan.target}</h4>
                        <p>{scan.date}</p>
                      </div>
                      <div className="scan-status">
                        <span className={`status-badge ${scan.status.toLowerCase().replace(' ', '-')}`}>
                          {scan.status}
                        </span>
                        <span className="vuln-count">
                          {scan.vulnerabilities} vulnerabilities
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <p>No scans yet. Start your first security scan!</p>
                  <button className="btn-primary">Start Scan</button>
                </div>
              )}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="dashboard-section">
            <div className="section-header">
              <h3>⚡ Quick Actions</h3>
            </div>
            <div className="section-content">
              <div className="action-grid">
                <button className="action-card">
                  <div className="action-icon">🔍</div>
                  <h4>New Scan</h4>
                  <p>Start a security scan</p>
                </button>
                
                <button className="action-card">
                  <div className="action-icon">📊</div>
                  <h4>View Reports</h4>
                  <p>Check scan results</p>
                </button>
                
                <button className="action-card">
                  <div className="action-icon">⚠️</div>
                  <h4>Vulnerabilities</h4>
                  <p>Review security issues</p>
                </button>
                
                <button className="action-card">
                  <div className="action-icon">⚙️</div>
                  <h4>Settings</h4>
                  <p>Configure scanner</p>
                </button>
              </div>
            </div>
          </div>

          {/* Security Status */}
          <div className="dashboard-section">
            <div className="section-header">
              <h3>🛡️ Security Status</h3>
            </div>
            <div className="section-content">
              <div className="security-status">
                <div className="status-indicator">
                  <div className="status-dot active"></div>
                  <span>Scanner Active</span>
                </div>
                <div className="status-indicator">
                  <div className="status-dot warning"></div>
                  <span>Updates Available</span>
                </div>
                <div className="status-indicator">
                  <div className="status-dot success"></div>
                  <span>Database Connected</span>
                </div>
                <div className="status-indicator">
                  <div className="status-dot active"></div>
                  <span>API Connected</span>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Activity */}
          <div className="dashboard-section">
            <div className="section-header">
              <h3>📈 Recent Activity</h3>
            </div>
            <div className="section-content">
              <div className="activity-list">
                <div className="activity-item">
                  <div className="activity-icon">🔍</div>
                  <div className="activity-content">
                    <p>Started scan of example.com</p>
                    <span>2 hours ago</span>
                  </div>
                </div>
                <div className="activity-item">
                  <div className="activity-icon">⚠️</div>
                  <div className="activity-content">
                    <p>Found 3 vulnerabilities in test.com</p>
                    <span>4 hours ago</span>
                  </div>
                </div>
                <div className="activity-item">
                  <div className="activity-icon">✅</div>
                  <div className="activity-content">
                    <p>Completed scan of demo.com</p>
                    <span>1 day ago</span>
                  </div>
                </div>
                <div className="activity-item">
                  <div className="activity-icon">🔧</div>
                  <div className="activity-content">
                    <p>Updated security policies</p>
                    <span>2 days ago</span>
                  </div>
                </div>
                <div className="activity-item">
                  <div className="activity-icon">🔐</div>
                  <div className="activity-content">
                    <p>User logged in successfully</p>
                    <span>Just now</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
