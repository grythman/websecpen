import React, { useState, useEffect } from 'react';
import './ScanDiff.css';

const ScanDiff = ({ scanId, onClose }) => {
  const [diffData, setDiffData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const [viewMode, setViewMode] = useState('summary'); // 'summary', 'diff', 'detailed'

  useEffect(() => {
    if (scanId) {
      fetchDiffData();
      fetchDiffSummary();
    }
  }, [scanId]);

  const fetchDiffData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/scan/${scanId}/diff`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setDiffData(data);
      } else {
        console.error('Failed to fetch scan diff');
      }
    } catch (error) {
      console.error('Error fetching scan diff:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchDiffSummary = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/scan/${scanId}/diff/summary`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setSummary(data);
      }
    } catch (error) {
      console.error('Error fetching scan summary:', error);
    }
  };

  const formatDiffLine = (line, index) => {
    let className = 'diff-line';
    let prefix = '';
    
    if (line.startsWith('+++') || line.startsWith('---')) {
      className += ' diff-header';
    } else if (line.startsWith('@@')) {
      className += ' diff-location';
    } else if (line.startsWith('+')) {
      className += ' diff-added';
      prefix = '+ ';
    } else if (line.startsWith('-')) {
      className += ' diff-removed';
      prefix = '- ';
    } else {
      className += ' diff-context';
      prefix = '  ';
    }

    return (
      <div key={index} className={className}>
        <span className="diff-line-number">{index + 1}</span>
        <span className="diff-prefix">{prefix}</span>
        <span className="diff-content">{line.substring(1)}</span>
      </div>
    );
  };

  const renderSummaryView = () => {
    if (!diffData || !diffData.comparison_available) {
      return (
        <div className="no-comparison">
          <div className="no-comparison-icon">🔍</div>
          <h3>No Previous Scan Available</h3>
          <p>This is the first scan for this URL, so there's nothing to compare it with.</p>
          <p>Run another scan later to see the differences!</p>
        </div>
      );
    }

    const changes = diffData.changes_summary;
    
    return (
      <div className="summary-view">
        <div className="scan-comparison-header">
          <h3>📊 Scan Comparison Summary</h3>
          <div className="scan-dates">
            <div className="scan-date">
              <span className="label">Previous Scan:</span>
              <span className="date">{new Date(diffData.previous_scan_date).toLocaleString()}</span>
              <span className="scan-id">ID: {diffData.previous_scan_id}</span>
            </div>
            <div className="scan-date">
              <span className="label">Current Scan:</span>
              <span className="date">{new Date(diffData.current_scan_date).toLocaleString()}</span>
              <span className="scan-id">ID: {scanId}</span>
            </div>
          </div>
        </div>

        <div className="changes-grid">
          <div className="change-card new-vulnerabilities">
            <div className="change-icon">🆕</div>
            <div className="change-content">
              <h4>New Vulnerabilities</h4>
              <div className="change-number">{changes.new_vulnerabilities}</div>
              <p>Newly discovered issues</p>
            </div>
          </div>

          <div className="change-card fixed-vulnerabilities">
            <div className="change-icon">✅</div>
            <div className="change-content">
              <h4>Fixed Vulnerabilities</h4>
              <div className="change-number">{changes.fixed_vulnerabilities}</div>
              <p>Issues that were resolved</p>
            </div>
          </div>

          <div className="change-card persistent-vulnerabilities">
            <div className="change-icon">⚠️</div>
            <div className="change-content">
              <h4>Persistent Issues</h4>
              <div className="change-number">{changes.persistent_vulnerabilities}</div>
              <p>Still present from last scan</p>
            </div>
          </div>

          <div className="change-card total-change">
            <div className="change-icon">📈</div>
            <div className="change-content">
              <h4>Overall Change</h4>
              <div className={`change-number ${changes.change_percentage >= 0 ? 'positive' : 'negative'}`}>
                {changes.change_percentage >= 0 ? '+' : ''}{changes.change_percentage}%
              </div>
              <p>Total vulnerability change</p>
            </div>
          </div>
        </div>

        <div className="change-analysis">
          <h4>🔍 Analysis</h4>
          <div className="analysis-content">
            {changes.new_vulnerabilities > 0 && (
              <div className="analysis-item warning">
                <strong>⚠️ Security Alert:</strong> {changes.new_vulnerabilities} new vulnerabilities were discovered. 
                Review these immediately and consider retesting after fixes.
              </div>
            )}
            {changes.fixed_vulnerabilities > 0 && (
              <div className="analysis-item success">
                <strong>✅ Good News:</strong> {changes.fixed_vulnerabilities} vulnerabilities were fixed since the last scan. 
                Great work on improving security!
              </div>
            )}
            {changes.persistent_vulnerabilities > 0 && (
              <div className="analysis-item info">
                <strong>📋 Note:</strong> {changes.persistent_vulnerabilities} vulnerabilities remain from the previous scan. 
                These may need additional attention.
              </div>
            )}
            {changes.new_vulnerabilities === 0 && changes.fixed_vulnerabilities === 0 && (
              <div className="analysis-item neutral">
                <strong>📊 Status:</strong> No significant changes detected between scans. 
                Security posture remains consistent.
              </div>
            )}
          </div>
        </div>

        {summary && summary.trend_data && summary.trend_data.length > 1 && (
          <div className="trend-history">
            <h4>📈 Historical Trend</h4>
            <div className="trend-chart">
              {summary.trend_data.map((scan, index) => (
                <div key={scan.scan_id} className="trend-point">
                  <div className="trend-bar-container">
                    <div 
                      className="trend-bar"
                      style={{ 
                        height: `${(scan.total_vulnerabilities / Math.max(...summary.trend_data.map(s => s.total_vulnerabilities))) * 100}%`,
                        backgroundColor: scan.scan_id === scanId ? '#007bff' : '#e9ecef'
                      }}
                    ></div>
                  </div>
                  <div className="trend-label">
                    <span className="trend-count">{scan.total_vulnerabilities}</span>
                    <span className="trend-date">{new Date(scan.scan_date).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderDiffView = () => {
    if (!diffData || !diffData.comparison_available || !diffData.diff.length) {
      return (
        <div className="no-diff">
          <p>No detailed differences to display.</p>
        </div>
      );
    }

    return (
      <div className="diff-view">
        <div className="diff-header">
          <h4>📝 Detailed Scan Diff</h4>
          <p>Line-by-line comparison of scan results</p>
        </div>
        
        <div className="diff-content">
          <pre className="diff-container">
            {diffData.diff.map((line, index) => formatDiffLine(line, index))}
          </pre>
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="scan-diff-modal">
        <div className="scan-diff-content loading">
          <div className="loading-spinner">
            <div className="spinner"></div>
            <p>Analyzing scan differences...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="scan-diff-modal">
      <div className="scan-diff-content">
        <div className="scan-diff-header">
          <h2>🔄 Scan Comparison</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="view-mode-tabs">
          <button
            className={`tab-btn ${viewMode === 'summary' ? 'active' : ''}`}
            onClick={() => setViewMode('summary')}
          >
            📊 Summary
          </button>
          <button
            className={`tab-btn ${viewMode === 'diff' ? 'active' : ''}`}
            onClick={() => setViewMode('diff')}
            disabled={!diffData || !diffData.comparison_available}
          >
            📝 Raw Diff
          </button>
        </div>

        <div className="scan-diff-body">
          {viewMode === 'summary' && renderSummaryView()}
          {viewMode === 'diff' && renderDiffView()}
        </div>

        <div className="scan-diff-footer">
          <div className="footer-actions">
            <button onClick={onClose} className="close-footer-btn">
              Close Comparison
            </button>
            {diffData && diffData.comparison_available && (
              <button 
                onClick={() => window.open(`/api/scan/${scanId}/diff`, '_blank')}
                className="download-btn"
              >
                📄 Download Diff
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanDiff; 