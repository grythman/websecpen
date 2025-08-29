// src/components/ScanForm.jsx - Enhanced with Error Handling & Session Management
import { useState, useContext } from 'react';
import { ThemeContext } from '../ThemeContext.jsx';
import { useError } from '../context/ErrorContext.jsx';
import apiService from '../utils/api.js';
import './ScanForm.css';

const ScanForm = () => {
  const { theme } = useContext(ThemeContext);
  const { showError, showSuccess, loading, setLoadingState } = useError();
  const [url, setUrl] = useState('');
  const [scanType, setScanType] = useState('XSS');
  const [scanId, setScanId] = useState(null);

  const scanTypes = [
    { value: 'XSS', label: 'Cross-Site Scripting (XSS)', description: 'Detects XSS vulnerabilities' },
    { value: 'SQLi', label: 'SQL Injection (SQLi)', description: 'Identifies SQL injection flaws' },
    { value: 'CSRF', label: 'Cross-Site Request Forgery (CSRF)', description: 'Checks for CSRF vulnerabilities' },
    { value: 'Directory', label: 'Directory Traversal', description: 'Scans for directory traversal issues' },
    { value: 'comprehensive', label: 'Comprehensive Scan', description: 'Runs all vulnerability checks' }
  ];

  const validateUrl = (url) => {
    const urlRegex = /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&=]*)$/;
    return urlRegex.test(url);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Client-side validation
    if (!url.trim()) {
      showError('Please enter a target URL');
      return;
    }

    if (!validateUrl(url.trim())) {
      showError('Please enter a valid URL (e.g., https://example.com)');
      return;
    }

    if (!scanType) {
      showError('Please select a scan type');
      return;
    }

    setLoadingState(true);

    try {
      // Call backend API through our centralized service
      const data = await apiService.startScan({
        url: url.trim(),
        scan_type: scanType
      });

      setScanId(data.scan_id);
      showSuccess(`🚀 Scan started successfully! Scan ID: ${data.scan_id} - Monitor progress in the dashboard.`);
      
      // Reset form after successful submission
      setUrl('');
      setScanType('XSS');
    } catch (error) {
      showError(error.message || 'Failed to start scan');
    } finally {
      setLoadingState(false);
    }
  };

  return (
    <div className={`scan-form ${theme}`}>
      <div className="form-header">
        <h2>🔍 Security Scan</h2>
        <p>Start a comprehensive security assessment of your web application</p>
      </div>

      <form onSubmit={handleSubmit} className="scan-form-container">
        <div className="form-group">
          <label htmlFor="url" className="form-label">
            Target URL *
          </label>
          <input
            type="url"
            id="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="form-input"
            disabled={loading}
            required
          />
          <div className="form-hint">
            Enter the full URL including protocol (http:// or https://)
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="scanType" className="form-label">
            Scan Type *
          </label>
          <select
            id="scanType"
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="form-select"
            disabled={loading}
            required
          >
            <option value="">Select scan type...</option>
            {scanTypes.map((type) => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
          <div className="form-hint">
            {scanTypes.find(t => t.value === scanType)?.description || 'Choose the type of security scan to perform'}
          </div>
        </div>

        <div className="form-actions">
          <button 
            type="submit" 
            className={`btn btn-primary ${loading ? 'loading' : ''}`}
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="loading-spinner"></span>
                Starting Scan...
              </>
            ) : (
              <>
                <span className="btn-icon">🚀</span>
                Start Security Scan
              </>
            )}
          </button>
        </div>

        {scanId && (
          <div className="scan-info">
            <div className="info-card">
              <h4>✅ Scan Initiated</h4>
              <p><strong>Scan ID:</strong> {scanId}</p>
              <p><strong>Target:</strong> {url}</p>
              <p><strong>Type:</strong> {scanTypes.find(t => t.value === scanType)?.label}</p>
              <div className="info-actions">
                <button 
                  type="button" 
                  className="btn btn-secondary"
                  onClick={() => window.location.reload()}
                >
                  View Progress
                </button>
              </div>
            </div>
          </div>
        )}
      </form>
    </div>
  );
};

export default ScanForm; 