// src/components/StatsDashboard.jsx - Real-time Statistics Dashboard with AI Analysis
import React, { useState, useEffect, useRef, useMemo, useCallback, useContext } from 'react';
import { useError } from '../context/ErrorContext.jsx';
import { useTranslation } from 'react-i18next';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  RadialLinearScale,
  Filler
} from 'chart.js';
import { ThemeContext } from '../context/ThemeContext.jsx';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import apiService from '../services/api.js';
import AdminGuard from './AdminGuard.jsx';
import './AdminGuard.css';
import './AdminGuard.css';
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
  return (
    <AdminGuard>
      <StatsDashboardContent />
    </AdminGuard>
  );
};

const StatsDashboardContent = () => {
  const { theme } = useContext(ThemeContext);
  const { addError } = useError();
  const [loading, setLoadingState] = useState(false);
  
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
      addError('Failed to fetch analytics data');
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
      addError('Failed to fetch dashboard summary');
      console.error('Dashboard summary error:', error);
    }
  };

  // Chart color schemes based on theme
  const getChartColors = useCallback(() => {
    const isDark = theme === 'dark';
    return {
      primary: isDark ? '#3b82f6' : '#2563eb',
      secondary: isDark ? '#10b981' : '#059669',
      accent: isDark ? '#f59e0b' : '#d97706',
      danger: isDark ? '#ef4444' : '#dc2626',
      warning: isDark ? '#f59e0b' : '#d97706',
      info: isDark ? '#06b6d4' : '#0891b2',
      success: isDark ? '#10b981' : '#059669',
      background: isDark ? '#1f2937' : '#f9fafb',
      text: isDark ? '#f9fafb' : '#1f2937',
      grid: isDark ? '#374151' : '#e5e7eb'
    };
  }, [theme]);

  const colors = getChartColors();

  // User Activity Chart Data
  const userActivityData = useMemo(() => {
    const users = analytics.user_activity || [];
    const labels = users.map(user => user.email.split('@')[0]);
    const scanCounts = users.map(user => user.scan_count);
    
    return {
      labels,
      datasets: [
        {
          label: 'Scans per User',
          data: scanCounts,
          backgroundColor: colors.primary,
          borderColor: colors.primary,
          borderWidth: 1
        }
      ]
    };
  }, [analytics.user_activity, colors]);

  // Scan Statistics Chart Data
  const scanStatsData = useMemo(() => {
    const stats = analytics.scan_statistics || {};
    const scanTypes = stats.scan_types || {};
    const scanStatuses = stats.scan_statuses || {};
    
    return {
      types: {
        labels: Object.keys(scanTypes),
        datasets: [{
          data: Object.values(scanTypes),
          backgroundColor: [colors.primary, colors.secondary, colors.accent, colors.danger],
          borderWidth: 0
        }]
      },
      statuses: {
        labels: Object.keys(scanStatuses),
        datasets: [{
          data: Object.values(scanStatuses),
          backgroundColor: [colors.success, colors.warning, colors.danger, colors.info],
          borderWidth: 0
        }]
      }
    };
  }, [analytics.scan_statistics, colors]);

  // Vulnerability Statistics Chart Data
  const vulnStatsData = useMemo(() => {
    const stats = analytics.vulnerability_statistics || {};
    return {
      labels: ['Low', 'Medium', 'High', 'Critical'],
      datasets: [{
        data: [
          stats.low_severity || 0,
          stats.medium_severity || 0,
          stats.high_severity || 0,
          stats.critical_severity || 0
        ],
        backgroundColor: [colors.info, colors.warning, colors.danger, colors.danger],
        borderWidth: 0
      }]
    };
  }, [analytics.vulnerability_statistics, colors]);

  // Chart options
  const chartOptions = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: colors.text
        }
      }
    },
    scales: {
      x: {
        ticks: { color: colors.text },
        grid: { color: colors.grid }
      },
      y: {
        ticks: { color: colors.text },
        grid: { color: colors.grid }
      }
    }
  }), [colors]);

  if (loading) {
    return (
      <div className="stats-dashboard-loading">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading analytics...</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`stats-dashboard ${theme}`}>
      <div className="stats-header">
        <h2>📊 Analytics Dashboard</h2>
        <p>Real-time insights and performance metrics</p>
      </div>

      {/* Summary Cards */}
      <div className="stats-summary">
        <div className="summary-card">
          <h3>Total Users</h3>
          <span className="summary-number">{dashboardSummary.summary.total_users || 0}</span>
        </div>
        <div className="summary-card">
          <h3>Total Scans</h3>
          <span className="summary-number">{dashboardSummary.summary.total_scans || 0}</span>
        </div>
        <div className="summary-card">
          <h3>Pending Scans</h3>
          <span className="summary-number">{dashboardSummary.summary.pending_scans || 0}</span>
        </div>
        <div className="summary-card">
          <h3>Critical Issues</h3>
          <span className="summary-number">{dashboardSummary.summary.critical_vulnerabilities || 0}</span>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="charts-grid">
        {/* User Activity Chart */}
        <div className="chart-container">
          <h3>User Activity</h3>
          <div className="chart-wrapper">
            <Bar data={userActivityData} options={chartOptions} />
          </div>
        </div>

        {/* Scan Types Chart */}
        <div className="chart-container">
          <h3>Scan Types</h3>
          <div className="chart-wrapper">
            <Doughnut data={scanStatsData.types} options={chartOptions} />
          </div>
        </div>

        {/* Vulnerability Severity Chart */}
        <div className="chart-container">
          <h3>Vulnerability Severity</h3>
          <div className="chart-wrapper">
            <Doughnut data={vulnStatsData} options={chartOptions} />
          </div>
        </div>

        {/* Recent Activity */}
        <div className="chart-container">
          <h3>Recent Users</h3>
          <div className="recent-users">
            {dashboardSummary.recent_users?.map(user => (
              <div key={user.id} className="user-item">
                <span className="user-email">{user.email}</span>
                <span className="user-date">
                  {new Date(user.created_at).toLocaleDateString()}
                </span>
              </div>
            )) || <p>No recent users</p>}
          </div>
        </div>
      </div>

      {/* Performance Metrics */}
      <div className="performance-metrics">
        <h3>Performance Metrics</h3>
        <div className="metrics-grid">
          <div className="metric-item">
            <span className="metric-label">Average Scan Duration</span>
            <span className="metric-value">
              {analytics.performance_metrics.avg_scan_duration || 0}s
            </span>
          </div>
          <div className="metric-item">
            <span className="metric-label">Total Scan Time</span>
            <span className="metric-value">
              {analytics.performance_metrics.total_scan_time || 0}s
            </span>
          </div>
          <div className="metric-item">
            <span className="metric-label">Active Users (30d)</span>
            <span className="metric-value">
              {analytics.scan_statistics.active_users_30d || 0}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StatsDashboard;
