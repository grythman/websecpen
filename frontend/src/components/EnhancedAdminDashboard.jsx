import React, { useState, useEffect } from 'react';
import './EnhancedAdminDashboard.css';

const EnhancedAdminDashboard = () => {
  const [activeTab, setActiveTab] = useState('users');
  const [users, setUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [feedbackAnalysis, setFeedbackAnalysis] = useState([]);
  const [snykResults, setSnykResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const [pagination, setPagination] = useState({
    users: { page: 1, total: 0, pages: 0 },
    auditLogs: { page: 1, total: 0, pages: 0 }
  });

  useEffect(() => {
    switch (activeTab) {
      case 'users':
        fetchUsers();
        break;
      case 'audit':
        fetchAuditLogs();
        break;
      case 'feedback':
        fetchFeedbackAnalysis();
        break;
      case 'snyk':
        fetchSnykResults();
        break;
    }
  }, [activeTab]);

  const fetchUsers = async (page = 1) => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch(`/api/admin/users?page=${page}&per_page=20`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setUsers(data.users || []);
        setPagination(prev => ({
          ...prev,
          users: {
            page: data.current_page || 1,
            total: data.total || 0,
            pages: data.pages || 1
          }
        }));
      }
    } catch (error) {
      console.error('Error fetching users:', error);
    }
  };

  const fetchAuditLogs = async (page = 1) => {
    try {
      setLoading(true);
      const token = localStorage.getItem('auth_token');
      const response = await fetch(`/api/admin/audit-logs?page=${page}&per_page=50`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setAuditLogs(data.logs || []);
        setPagination(prev => ({
          ...prev,
          auditLogs: {
            page: data.current_page || 1,
            total: data.total || 0,
            pages: data.pages || 1
          }
        }));
      }
    } catch (error) {
      console.error('Error fetching audit logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchFeedbackAnalysis = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/admin/feedback/analyze', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setFeedbackAnalysis(data);
      } else {
        const errorData = await response.json();
        setMessage(errorData.error || 'Failed to fetch feedback analysis');
      }
    } catch (error) {
      setMessage('Error fetching feedback analysis');
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchSnykResults = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/admin/snyk-results', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setSnykResults(data.vulnerabilities || []);
      } else {
        const errorData = await response.json();
        setMessage(errorData.error || 'Failed to fetch Snyk results');
      }
    } catch (error) {
      setMessage('Error fetching Snyk results');
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleBanUser = async (userId, isCurrentlyBanned) => {
    const action = isCurrentlyBanned ? 'unban' : 'ban';
    if (!window.confirm(`Are you sure you want to ${action} this user?`)) {
      return;
    }

    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch(`/api/admin/user/${userId}/${action}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      const data = await response.json();

      if (response.ok) {
        setMessage(data.message);
        fetchUsers(pagination.users.page); // Refresh current page
      } else {
        setMessage(data.error || `Failed to ${action} user`);
      }
    } catch (error) {
      setMessage(`Error ${action}ning user`);
      console.error('Error:', error);
    }
  };

  const getSentimentColor = (sentiment) => {
    const colors = {
      'POSITIVE': '#28a745',
      'NEGATIVE': '#dc3545',
      'NEUTRAL': '#6c757d',
      'UNKNOWN': '#ffc107'
    };
    return colors[sentiment] || colors['UNKNOWN'];
  };

  const getSentimentIcon = (sentiment) => {
    const icons = {
      'POSITIVE': '😊',
      'NEGATIVE': '😞',
      'NEUTRAL': '😐',
      'UNKNOWN': '❓'
    };
    return icons[sentiment] || icons['UNKNOWN'];
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getUserRoleBadge = (role) => {
    const roleConfig = {
      'free': { class: 'role-free', label: 'Free' },
      'premium': { class: 'role-premium', label: 'Premium' },
      'admin': { class: 'role-admin', label: 'Admin' }
    };
    const config = roleConfig[role] || roleConfig['free'];
    return <span className={`role-badge ${config.class}`}>{config.label}</span>;
  };

  return (
    <div className="admin-dashboard">
      <div className="admin-header">
        <h2>🛠️ Admin Dashboard</h2>
        <p>System management and monitoring</p>
      </div>

      <div className="admin-tabs">
        <button
          className={`tab ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          👥 Users
        </button>
        <button
          className={`tab ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          📋 Audit Logs
        </button>
        <button
          className={`tab ${activeTab === 'feedback' ? 'active' : ''}`}
          onClick={() => setActiveTab('feedback')}
        >
          💬 Feedback Analysis
        </button>
        <button
          className={`tab ${activeTab === 'snyk' ? 'active' : ''}`}
          onClick={() => setActiveTab('snyk')}
        >
          🔍 Security (Snyk)
        </button>
      </div>

      {message && (
        <div className={`message ${message.includes('Error') || message.includes('Failed') ? 'error' : 'success'}`}>
          {message}
        </div>
      )}

      {loading && (
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading...</p>
        </div>
      )}

      {activeTab === 'users' && (
        <div className="admin-content">
          <div className="content-header">
            <h3>User Management</h3>
            <div className="stats">
              <span>Total Users: {pagination.users.total}</span>
            </div>
          </div>

          <div className="users-table">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Email</th>
                  <th>Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Scans</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id} className={!user.is_active ? 'banned-user' : ''}>
                    <td>{user.id}</td>
                    <td>{user.email}</td>
                    <td>{user.first_name} {user.last_name}</td>
                    <td>{getUserRoleBadge(user.role)}</td>
                    <td>
                      <span className={`status ${user.is_active ? 'active' : 'banned'}`}>
                        {user.is_active ? '✅ Active' : '❌ Banned'}
                      </span>
                    </td>
                    <td>{user.scan_limit}</td>
                    <td>{formatDate(user.created_at)}</td>
                    <td>
                      <button
                        onClick={() => handleBanUser(user.id, !user.is_active)}
                        className={`btn ${user.is_active ? 'btn-danger' : 'btn-success'}`}
                      >
                        {user.is_active ? 'Ban' : 'Unban'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {pagination.users.pages > 1 && (
            <div className="pagination">
              <button
                onClick={() => fetchUsers(pagination.users.page - 1)}
                disabled={pagination.users.page <= 1}
              >
                Previous
              </button>
              <span>Page {pagination.users.page} of {pagination.users.pages}</span>
              <button
                onClick={() => fetchUsers(pagination.users.page + 1)}
                disabled={pagination.users.page >= pagination.users.pages}
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}

      {activeTab === 'audit' && (
        <div className="admin-content">
          <div className="content-header">
            <h3>Audit Logs</h3>
            <div className="stats">
              <span>Total Logs: {pagination.auditLogs.total}</span>
            </div>
          </div>

          <div className="audit-table">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Admin</th>
                  <th>Action</th>
                  <th>Details</th>
                  <th>IP Address</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => (
                  <tr key={log.id}>
                    <td>{formatDate(log.timestamp)}</td>
                    <td>Admin #{log.admin_id}</td>
                    <td>
                      <span className="action-badge">{log.action}</span>
                    </td>
                    <td>
                      <details>
                        <summary>View Details</summary>
                        <pre>{JSON.stringify(log.details, null, 2)}</pre>
                      </details>
                    </td>
                    <td>{log.ip_address || 'Unknown'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {pagination.auditLogs.pages > 1 && (
            <div className="pagination">
              <button
                onClick={() => fetchAuditLogs(pagination.auditLogs.page - 1)}
                disabled={pagination.auditLogs.page <= 1}
              >
                Previous
              </button>
              <span>Page {pagination.auditLogs.page} of {pagination.auditLogs.pages}</span>
              <button
                onClick={() => fetchAuditLogs(pagination.auditLogs.page + 1)}
                disabled={pagination.auditLogs.page >= pagination.auditLogs.pages}
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}

      {activeTab === 'feedback' && (
        <div className="admin-content">
          <div className="content-header">
            <h3>Feedback Sentiment Analysis</h3>
            <div className="stats">
              <span>Total Feedback: {feedbackAnalysis.length}</span>
            </div>
          </div>

          <div className="sentiment-summary">
            <div className="sentiment-stats">
              {['POSITIVE', 'NEGATIVE', 'NEUTRAL'].map(sentiment => {
                const count = feedbackAnalysis.filter(f => f.sentiment.label === sentiment).length;
                const percentage = feedbackAnalysis.length > 0 ? Math.round((count / feedbackAnalysis.length) * 100) : 0;
                return (
                  <div key={sentiment} className="sentiment-stat">
                    <span className="sentiment-icon" style={{color: getSentimentColor(sentiment)}}>
                      {getSentimentIcon(sentiment)}
                    </span>
                    <div>
                      <strong>{sentiment}</strong>
                      <br />
                      {count} ({percentage}%)
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="feedback-table">
            <table>
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Type</th>
                  <th>Subject</th>
                  <th>Message</th>
                  <th>Sentiment</th>
                  <th>Score</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {feedbackAnalysis.map((feedback) => (
                  <tr key={feedback.id}>
                    <td>{formatDate(feedback.created_at)}</td>
                    <td>
                      <span className={`type-badge type-${feedback.type}`}>
                        {feedback.type}
                      </span>
                    </td>
                    <td>{feedback.subject}</td>
                    <td title={feedback.message}>
                      {feedback.message.substring(0, 50)}...
                    </td>
                    <td>
                      <span
                        className="sentiment-label"
                        style={{color: getSentimentColor(feedback.sentiment.label)}}
                      >
                        {getSentimentIcon(feedback.sentiment.label)} {feedback.sentiment.label}
                      </span>
                    </td>
                    <td>{feedback.sentiment.score}</td>
                    <td>
                      <span className={`status-badge status-${feedback.status}`}>
                        {feedback.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'snyk' && (
        <div className="admin-content">
          <div className="content-header">
            <h3>Snyk Security Scan Results</h3>
            <div className="stats">
              <span>Vulnerabilities Found: {snykResults.length}</span>
            </div>
          </div>

          {snykResults.length === 0 ? (
            <div className="empty-state">
              <p>No Snyk scan results available.</p>
              <p>Run a Snyk scan in your CI/CD pipeline to see dependency vulnerabilities.</p>
            </div>
          ) : (
            <div className="snyk-table">
              <table>
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Version</th>
                    <th>Fix Available</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {snykResults.map((vuln, index) => (
                    <tr key={index}>
                      <td><code>{vuln.package}</code></td>
                      <td>{vuln.title}</td>
                      <td>
                        <span className={`severity severity-${vuln.severity}`}>
                          {vuln.severity}
                        </span>
                      </td>
                      <td>{vuln.version}</td>
                      <td>
                        {vuln.fixAvailable ? (
                          <span className="fix-available">✅ Yes</span>
                        ) : (
                          <span className="fix-unavailable">❌ No</span>
                        )}
                      </td>
                      <td title={vuln.description}>
                        {vuln.description?.substring(0, 100)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default EnhancedAdminDashboard; 