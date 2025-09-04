import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import './AdminDashboard.css';

const AdminDashboard = () => {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState('overview');
  const [snykResults, setSnykResults] = useState([]);
  const [feedbackAnalysis, setFeedbackAnalysis] = useState([]);
  const [feedbackSummary, setFeedbackSummary] = useState({});
  const [loading, setLoading] = useState({
    snyk: false,
    feedback: false,
    overview: false
  });
  const [error, setError] = useState('');

  useEffect(() => {
    fetchSnykResults();
    fetchFeedbackAnalysis();
    fetchFeedbackSummary();
  }, []);

  const fetchSnykResults = async () => {
    setLoading(prev => ({ ...prev, snyk: true }));
    try {
      const response = await fetch('/api/admin/snyk-results', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setSnykResults(data.vulnerabilities || []);
      } else {
        throw new Error('Failed to fetch Snyk results');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(prev => ({ ...prev, snyk: false }));
    }
  };

  const fetchFeedbackAnalysis = async () => {
    setLoading(prev => ({ ...prev, feedback: true }));
    try {
      const response = await fetch('/api/admin/feedback/analyze', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setFeedbackAnalysis(data.analysis || []);
      } else {
        throw new Error('Failed to fetch feedback analysis');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(prev => ({ ...prev, feedback: false }));
    }
  };

  const fetchFeedbackSummary = async () => {
    try {
      const response = await fetch('/api/admin/feedback/summary', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setFeedbackSummary(data);
      }
    } catch (err) {
      console.error('Failed to fetch feedback summary:', err);
    }
  };

  const runSnykScan = async () => {
    setLoading(prev => ({ ...prev, snyk: true }));
    try {
      const response = await fetch('/api/scan/snyk', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ project_path: './frontend' }),
      });

      const data = await response.json();
      
      if (response.ok) {
        setSnykResults(data.vulnerabilities || []);
        setError('');
      } else {
        setError(data.error || 'Failed to run Snyk scan');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(prev => ({ ...prev, snyk: false }));
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
      case 'high':
        return '#dc3545';
      case 'medium':
        return '#fd7e14';
      case 'low':
        return '#ffc107';
      default:
        return '#6c757d';
    }
  };

  const getSentimentIcon = (sentiment) => {
    switch (sentiment) {
      case 'POSITIVE':
        return '😊';
      case 'NEGATIVE':
        return '😟';
      default:
        return '😐';
    }
  };

  const renderOverview = () => (
    <div className="admin-overview">
      <div className="overview-grid">
        <div className="overview-card">
          <div className="card-header">
            <h3>🔐 Security Overview</h3>
          </div>
          <div className="card-content">
            <div className="stat-row">
              <span>Snyk Vulnerabilities:</span>
              <span className="stat-value">{snykResults.length}</span>
            </div>
            <div className="stat-row">
              <span>Critical Issues:</span>
              <span className="stat-value critical">
                {snykResults.filter(v => v.severity === 'critical').length}
              </span>
            </div>
            <div className="stat-row">
              <span>High Severity:</span>
              <span className="stat-value high">
                {snykResults.filter(v => v.severity === 'high').length}
              </span>
            </div>
          </div>
        </div>

        <div className="overview-card">
          <div className="card-header">
            <h3>📝 Feedback Overview</h3>
          </div>
          <div className="card-content">
            <div className="stat-row">
              <span>Total Feedback:</span>
              <span className="stat-value">{feedbackSummary.total_feedback || 0}</span>
            </div>
            <div className="stat-row">
              <span>Recent (30 days):</span>
              <span className="stat-value">{feedbackSummary.recent_feedback || 0}</span>
            </div>
            <div className="feedback-types">
              {Object.entries(feedbackSummary.by_type || {}).map(([type, count]) => (
                <div key={type} className="type-stat">
                  <span>{type}:</span>
                  <span>{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderSnykResults = () => (
    <div className="snyk-section">
      <div className="section-header">
        <h3>🔍 Snyk Dependency Scan</h3>
        <button 
          className="scan-btn"
          onClick={runSnykScan}
          disabled={loading.snyk}
        >
          {loading.snyk ? 'Scanning...' : 'Run New Scan'}
        </button>
      </div>

      {loading.snyk && (
        <div className="loading-state">
          <div className="loading-spinner"></div>
          <p>Running Snyk dependency scan...</p>
        </div>
      )}

      {!loading.snyk && snykResults.length === 0 && (
        <div className="no-results">
          <p>No vulnerabilities found or scan not run yet.</p>
        </div>
      )}

      {!loading.snyk && snykResults.length > 0 && (
        <div className="vulnerabilities-list">
          {snykResults.map((vuln, index) => (
            <div key={index} className="vulnerability-card">
              <div className="vuln-header">
                <h4>{vuln.title}</h4>
                <span 
                  className="severity-badge"
                  style={{ backgroundColor: getSeverityColor(vuln.severity) }}
                >
                  {vuln.severity}
                </span>
              </div>
              <div className="vuln-details">
                <p><strong>Package:</strong> {vuln.packageName}@{vuln.version}</p>
                <p><strong>Description:</strong> {vuln.description}</p>
                {vuln.fixedIn && (
                  <p><strong>Fixed in:</strong> {vuln.fixedIn.join(', ')}</p>
                )}
                {vuln.references && vuln.references.length > 0 && (
                  <div className="vuln-references">
                    <strong>References:</strong>
                    {vuln.references.map((ref, i) => (
                      <a key={i} href={ref.url} target="_blank" rel="noopener noreferrer">
                        {ref.title}
                      </a>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  const renderFeedbackAnalysis = () => (
    <div className="feedback-section">
      <div className="section-header">
        <h3>💭 Feedback Sentiment Analysis</h3>
        <button 
          className="refresh-btn"
          onClick={fetchFeedbackAnalysis}
          disabled={loading.feedback}
        >
          {loading.feedback ? 'Analyzing...' : 'Refresh Analysis'}
        </button>
      </div>

      {loading.feedback && (
        <div className="loading-state">
          <div className="loading-spinner"></div>
          <p>Analyzing feedback sentiment...</p>
        </div>
      )}

      {!loading.feedback && feedbackAnalysis.length === 0 && (
        <div className="no-results">
          <p>No feedback available for analysis.</p>
        </div>
      )}

      {!loading.feedback && feedbackAnalysis.length > 0 && (
        <div className="feedback-analysis">
          <div className="sentiment-summary">
            <div className="sentiment-card positive">
              <span className="sentiment-icon">😊</span>
              <div>
                <div className="sentiment-count">
                  {feedbackAnalysis.filter(f => f.sentiment.label === 'POSITIVE').length}
                </div>
                <div className="sentiment-label">Positive</div>
              </div>
            </div>
            <div className="sentiment-card neutral">
              <span className="sentiment-icon">😐</span>
              <div>
                <div className="sentiment-count">
                  {feedbackAnalysis.filter(f => f.sentiment.label === 'NEUTRAL').length}
                </div>
                <div className="sentiment-label">Neutral</div>
              </div>
            </div>
            <div className="sentiment-card negative">
              <span className="sentiment-icon">😟</span>
              <div>
                <div className="sentiment-count">
                  {feedbackAnalysis.filter(f => f.sentiment.label === 'NEGATIVE').length}
                </div>
                <div className="sentiment-label">Negative</div>
              </div>
            </div>
          </div>

          <div className="feedback-table">
            <table>
              <thead>
                <tr>
                  <th>Feedback</th>
                  <th>Type</th>
                  <th>Sentiment</th>
                  <th>Confidence</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {feedbackAnalysis.slice(0, 20).map((feedback) => (
                  <tr key={feedback.id}>
                    <td className="feedback-text">{feedback.feedback}</td>
                    <td>
                      <span className="feedback-type">{feedback.type}</span>
                    </td>
                    <td>
                      <div className="sentiment-cell">
                        <span className="sentiment-icon">
                          {getSentimentIcon(feedback.sentiment.label)}
                        </span>
                        <span className={`sentiment-label ${feedback.sentiment.label.toLowerCase()}`}>
                          {feedback.sentiment.label}
                        </span>
                      </div>
                    </td>
                    <td>
                      <div className="confidence-bar">
                        <div 
                          className="confidence-fill"
                          style={{ width: `${feedback.sentiment.confidence * 100}%` }}
                        ></div>
                        <span className="confidence-text">
                          {(feedback.sentiment.confidence * 100).toFixed(1)}%
                        </span>
                      </div>
                    </td>
                    <td>{new Date(feedback.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'snyk', label: 'Security Scan', icon: '🔍' },
    { id: 'feedback', label: 'Feedback Analysis', icon: '💭' },
  ];

  return (
    <div className="admin-dashboard">
      <div className="admin-header">
        <h1>🛠️ Admin Dashboard</h1>
        <p>System monitoring and analysis tools</p>
      </div>

      <div className="admin-tabs">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="tab-icon">{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      <div className="admin-content">
        {error && (
          <div className="error-message">
            <p>Error: {error}</p>
            <button onClick={() => setError('')}>Dismiss</button>
          </div>
        )}

        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'snyk' && renderSnykResults()}
        {activeTab === 'feedback' && renderFeedbackAnalysis()}
      </div>
    </div>
  );
};

export default AdminDashboard; 