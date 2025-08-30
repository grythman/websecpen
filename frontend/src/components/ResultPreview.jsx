// src/components/ResultPreview.jsx
import React, { useContext } from 'react';
import { ThemeContext } from '../ThemeContext.jsx';
import './ResultPreview.css';

// Mock data with more detailed results
const mockResult = {
  scan_id: 1,
  target_url: 'https://example.com',
  scan_type: 'XSS',
  scan_date: '2025-07-26',
  status: 'Completed',
  duration: '3m 45s',
  vulnerabilities: [
    {
      id: 1,
      type: 'XSS',
  severity: 'High',
      title: 'Stored Cross-Site Scripting in Contact Form',
      description: 'User input is not properly sanitized before being stored and displayed.',
      location: '/contact.php',
      confidence: 95
    },
    {
      id: 2,
      type: 'XSS',
      severity: 'Medium',
      title: 'Reflected XSS in Search Parameter',
      description: 'Search query parameter is reflected without proper encoding.',
      location: '/search?q=<script>alert(1)</script>',
      confidence: 88
    },
    {
      id: 3,
      type: 'XSS',
      severity: 'Low',
      title: 'DOM-based XSS Vulnerability',
      description: 'Client-side JavaScript processes user input unsafely.',
      location: '/dashboard.html',
      confidence: 72
    }
  ],
  summary: {
    total_pages_scanned: 45,
    total_requests: 128,
    high_severity: 1,
    medium_severity: 1,
    low_severity: 1,
    info_severity: 2
  }
};

const ResultPreview = () => {
  const { theme } = useContext(ThemeContext);

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'high': return 'severity-high';
      case 'medium': return 'severity-medium';
      case 'low': return 'severity-low';
      default: return 'severity-info';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity.toLowerCase()) {
      case 'high': return '🔴';
      case 'medium': return '🟡';
      case 'low': return '🔵';
      default: return '⚪';
    }
  };

  const getOverallRisk = () => {
    const { high_severity, medium_severity } = mockResult.summary;
    if (high_severity > 0) return { level: 'High', color: 'severity-high', icon: '🔴' };
    if (medium_severity > 0) return { level: 'Medium', color: 'severity-medium', icon: '🟡' };
    return { level: 'Low', color: 'severity-low', icon: '🔵' };
  };

  const overallRisk = getOverallRisk();

  return (
    <div className={`result-preview ${theme}`}>
      {/* Scan Overview */}
      <div className="scan-overview">
        <div className="overview-header">
          <div className="scan-meta">
            <h4>Scan #{mockResult.scan_id}</h4>
            <span className="scan-type-badge">
              {mockResult.scan_type}
            </span>
          </div>
          <div className={`overall-risk ${overallRisk.color}`}>
            <span className="risk-icon">{overallRisk.icon}</span>
            <span className="risk-level">{overallRisk.level} Risk</span>
          </div>
        </div>

        <div className="scan-details">
          <div className="detail-item">
            <span className="detail-label">Target:</span>
            <span className="detail-value">{mockResult.target_url}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Duration:</span>
            <span className="detail-value">{mockResult.duration}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Pages Scanned:</span>
            <span className="detail-value">{mockResult.summary.total_pages_scanned}</span>
          </div>
        </div>
      </div>

      {/* Vulnerability Summary */}
      <div className="vulnerability-summary">
        <h5>Vulnerability Summary</h5>
        <div className="summary-stats">
          <div className="stat-card high">
            <div className="stat-number">{mockResult.summary.high_severity}</div>
            <div className="stat-label">High</div>
          </div>
          <div className="stat-card medium">
            <div className="stat-number">{mockResult.summary.medium_severity}</div>
            <div className="stat-label">Medium</div>
          </div>
          <div className="stat-card low">
            <div className="stat-number">{mockResult.summary.low_severity}</div>
            <div className="stat-label">Low</div>
          </div>
          <div className="stat-card info">
            <div className="stat-number">{mockResult.summary.info_severity}</div>
            <div className="stat-label">Info</div>
          </div>
        </div>
      </div>

      {/* Top Vulnerabilities */}
      <div className="top-vulnerabilities">
        <h5>Critical Findings</h5>
        <div className="vulnerabilities-list">
          {mockResult.vulnerabilities.slice(0, 3).map(vuln => (
            <div key={vuln.id} className="vulnerability-item">
              <div className="vuln-header">
                <span className={`severity-badge ${getSeverityColor(vuln.severity)}`}>
                  {getSeverityIcon(vuln.severity)} {vuln.severity}
                </span>
                <span className="confidence-badge">
                  {vuln.confidence}% confidence
                </span>
              </div>
              <div className="vuln-content">
                <h6 className="vuln-title">{vuln.title}</h6>
                <p className="vuln-description">{vuln.description}</p>
                <code className="vuln-location">{vuln.location}</code>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="result-actions">
        <button className="action-btn primary">
          📄 View Full Report
        </button>
        <button className="action-btn secondary">
          ⬇️ Download PDF
        </button>
        <button className="action-btn secondary">
          📤 Export JSON
        </button>
      </div>
    </div>
  );
};

export default ResultPreview; 