// src/components/StatsDashboard.jsx - Advanced Analytics Dashboard
import { useEffect, useState, useContext } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import { ThemeContext } from '../ThemeContext.jsx';
import { useError } from '../context/ErrorContext.jsx';
import apiService from '../utils/api.js';
import './StatsDashboard.css';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

const StatsDashboard = () => {
  const { theme } = useContext(ThemeContext);
  const { showError, loading, setLoadingState } = useError();
  
  const [analytics, setAnalytics] = useState({
    user_activity: [],
    recent_scans: [],
    scan_statistics: {},
    vulnerability_statistics: {},
    feedback_statistics: {},
    performance_metrics: {},
    generated_at: null
  });

  const [dashboardSummary, setDashboardSummary] = useState({
    summary: {},
    recent_users: []
  });

  useEffect(() => {
    fetchAnalytics();
    fetchDashboardSummary();
  }, []);

  const fetchAnalytics = async () => {
    setLoadingState(true);
    try {
      const response = await apiService.request('/admin/analytics');
      setAnalytics(response);
    } catch (error) {
      showError('Failed to fetch analytics data');
      console.error('Analytics error:', error);
    } finally {
      setLoadingState(false);
    }
  };

  const fetchDashboardSummary = async () => {
    try {
      const response = await apiService.request('/admin/dashboard');
      setDashboardSummary(response);
    } catch (error) {
      showError('Failed to fetch dashboard summary');
      console.error('Dashboard summary error:', error);
    }
  };

  // Chart color schemes based on theme
  const getChartColors = () => {
    if (theme === 'dark') {
      return {
        primary: '#667eea',
        secondary: '#764ba2',
        success: '#48bb78',
        warning: '#ed8936',
        danger: '#f56565',
        info: '#4299e1',
        background: ['#667eea', '#764ba2', '#48bb78', '#ed8936', '#f56565', '#4299e1'],
        text: '#e2e8f0'
      };
    }
    return {
      primary: '#667eea',
      secondary: '#764ba2',
      success: '#38a169',
      warning: '#d69e2e',
      danger: '#e53e3e',
      info: '#3182ce',
      background: ['#667eea', '#764ba2', '#38a169', '#d69e2e', '#e53e3e', '#3182ce'],
      text: '#2d3748'
    };
  };

  const colors = getChartColors();

  // User Activity Bar Chart
  const userActivityData = {
    labels: analytics.user_activity.slice(0, 10).map(user => 
      user.email.length > 15 ? user.email.substring(0, 15) + '...' : user.email
    ),
    datasets: [
      {
        label: 'Scans per User',
        data: analytics.user_activity.slice(0, 10).map(user => user.scan_count),
        backgroundColor: colors.primary,
        borderColor: colors.primary,
        borderWidth: 1,
        borderRadius: 4,
      },
    ],
  };

  // Scan Types Doughnut Chart
  const scanTypesData = {
    labels: Object.keys(analytics.scan_statistics.scan_types || {}),
    datasets: [
      {
        label: 'Scan Types',
        data: Object.values(analytics.scan_statistics.scan_types || {}),
        backgroundColor: colors.background,
        borderWidth: 2,
        borderColor: theme === 'dark' ? '#2d3748' : '#ffffff',
      },
    ],
  };

  // Vulnerability Severity Doughnut Chart
  const vulnerabilitySeverityData = {
    labels: ['High Severity', 'Medium Severity', 'Low Severity'],
    datasets: [
      {
        label: 'Vulnerabilities by Severity',
        data: [
          analytics.vulnerability_statistics.high_severity || 0,
          analytics.vulnerability_statistics.medium_severity || 0,
          analytics.vulnerability_statistics.low_severity || 0,
        ],
        backgroundColor: [colors.danger, colors.warning, colors.info],
        borderWidth: 2,
        borderColor: theme === 'dark' ? '#2d3748' : '#ffffff',
      },
    ],
  };

  // Chart options
  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: colors.text,
          font: {
            family: 'Inter, system-ui, sans-serif',
          },
        },
      },
      title: {
        display: false,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          color: colors.text,
        },
        grid: {
          color: theme === 'dark' ? '#4a5568' : '#e2e8f0',
        },
      },
      x: {
        ticks: {
          color: colors.text,
        },
        grid: {
          color: theme === 'dark' ? '#4a5568' : '#e2e8f0',
        },
      },
    },
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: colors.text,
          font: {
            family: 'Inter, system-ui, sans-serif',
          },
          padding: 15,
        },
      },
    },
  };

  if (loading) {
    return (
      <div className={`stats-dashboard ${theme}`}>
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading analytics...</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`stats-dashboard ${theme}`}>
      <div className="dashboard-header">
        <h2>📊 Analytics Dashboard</h2>
        <p>Comprehensive insights into WebSecPen usage and performance</p>
        {analytics.generated_at && (
          <div className="last-updated">
            Last updated: {new Date(analytics.generated_at).toLocaleString()}
          </div>
        )}
      </div>

      {/* Summary Cards */}
      <div className="summary-cards">
        <div className="summary-card">
          <div className="card-icon">👥</div>
          <div className="card-content">
            <h3>{dashboardSummary.summary.total_users || 0}</h3>
            <p>Total Users</p>
          </div>
        </div>
        <div className="summary-card">
          <div className="card-icon">🔍</div>
          <div className="card-content">
            <h3>{dashboardSummary.summary.total_scans || 0}</h3>
            <p>Total Scans</p>
          </div>
        </div>
        <div className="summary-card">
          <div className="card-icon">⚠️</div>
          <div className="card-content">
            <h3>{dashboardSummary.summary.critical_vulnerabilities || 0}</h3>
            <p>Critical Issues</p>
          </div>
        </div>
        <div className="summary-card">
          <div className="card-icon">💬</div>
          <div className="card-content">
            <h3>{dashboardSummary.summary.new_feedback || 0}</h3>
            <p>New Feedback</p>
          </div>
        </div>
        <div className="summary-card">
          <div className="card-icon">⏱️</div>
          <div className="card-content">
            <h3>{analytics.performance_metrics.avg_scan_duration || 0}s</h3>
            <p>Avg Scan Time</p>
          </div>
        </div>
        <div className="summary-card">
          <div className="card-icon">🎯</div>
          <div className="card-content">
            <h3>{Math.round(analytics.vulnerability_statistics.avg_risk_score || 0)}/10</h3>
            <p>Avg Risk Score</p>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="charts-grid">
        {/* User Activity Chart */}
        <div className="chart-container">
          <div className="chart-header">
            <h3>👤 User Activity</h3>
            <p>Number of scans per user (top 10)</p>
          </div>
          <div className="chart-wrapper">
            <Bar data={userActivityData} options={chartOptions} />
          </div>
        </div>

        {/* Scan Types Distribution */}
        <div className="chart-container">
          <div className="chart-header">
            <h3>🔍 Scan Types</h3>
            <p>Distribution of scan types</p>
          </div>
          <div className="chart-wrapper">
            <Doughnut data={scanTypesData} options={doughnutOptions} />
          </div>
        </div>

        {/* Vulnerability Severity */}
        <div className="chart-container">
          <div className="chart-header">
            <h3>⚠️ Vulnerability Severity</h3>
            <p>Breakdown by risk level</p>
          </div>
          <div className="chart-wrapper">
            <Doughnut data={vulnerabilitySeverityData} options={doughnutOptions} />
          </div>
        </div>

        {/* Performance Metrics */}
        <div className="chart-container">
          <div className="chart-header">
            <h3>📈 Performance Metrics</h3>
            <p>System performance overview</p>
          </div>
          <div className="metrics-grid">
            <div className="metric-item">
              <span className="metric-value">{analytics.scan_statistics.recent_scans_30d || 0}</span>
              <span className="metric-label">Scans (30 days)</span>
            </div>
            <div className="metric-item">
              <span className="metric-value">{analytics.scan_statistics.active_users_30d || 0}</span>
              <span className="metric-label">Active Users</span>
            </div>
            <div className="metric-item">
              <span className="metric-value">{Math.round(analytics.performance_metrics.total_scan_time / 3600 || 0)}h</span>
              <span className="metric-label">Total Scan Time</span>
            </div>
            <div className="metric-item">
              <span className="metric-value">{analytics.vulnerability_statistics.total_vulnerabilities || 0}</span>
              <span className="metric-label">Total Vulnerabilities</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity Tables */}
      <div className="tables-grid">
        {/* Recent Scans */}
        <div className="table-container">
          <div className="table-header">
            <h3>🔍 Recent Scans</h3>
            <p>Latest security scans performed</p>
          </div>
          <div className="table-wrapper">
            <table className="analytics-table">
              <thead>
                <tr>
                  <th>Target URL</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>User</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {analytics.recent_scans.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <span className="url-cell" title={scan.target_url}>
                        {scan.target_url.length > 30 ? 
                          scan.target_url.substring(0, 30) + '...' : 
                          scan.target_url
                        }
                      </span>
                    </td>
                    <td>
                      <span className={`scan-type-badge ${scan.scan_type.toLowerCase()}`}>
                        {scan.scan_type}
                      </span>
                    </td>
                    <td>
                      <span className={`status-badge ${scan.status}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td>{scan.user_email}</td>
                    <td>{scan.created_at ? new Date(scan.created_at).toLocaleDateString() : 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Users */}
        <div className="table-container">
          <div className="table-header">
            <h3>👥 Recent Users</h3>
            <p>Latest user registrations</p>
          </div>
          <div className="table-wrapper">
            <table className="analytics-table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Registration Date</th>
                  <th>Scans</th>
                </tr>
              </thead>
              <tbody>
                {dashboardSummary.recent_users.map((user) => {
                  const userActivity = analytics.user_activity.find(u => u.user_id === user.id);
                  return (
                    <tr key={user.id}>
                      <td>{user.email}</td>
                      <td>{user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}</td>
                      <td>{userActivity?.scan_count || 0}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Refresh Button */}
      <div className="dashboard-actions">
        <button 
          className="btn btn-primary" 
          onClick={() => {
            fetchAnalytics();
            fetchDashboardSummary();
          }}
          disabled={loading}
        >
          {loading ? (
            <>
              <span className="loading-spinner"></span>
              Refreshing...
            </>
          ) : (
            <>
              <span className="btn-icon">🔄</span>
              Refresh Data
            </>
          )}
        </button>
      </div>
    </div>
  );
};

export default StatsDashboard; 