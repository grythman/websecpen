// src/components/ScanForm.jsx
import { useState, useContext } from 'react';
import { ThemeContext } from '../ThemeContext.jsx';
import './ScanForm.css';

const ScanForm = () => {
  const [url, setUrl] = useState('');
  const [scanType, setScanType] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { theme } = useContext(ThemeContext);

  const scanTypes = [
    { value: 'XSS', label: 'Cross-Site Scripting (XSS)', description: 'Detects XSS vulnerabilities' },
    { value: 'SQLi', label: 'SQL Injection (SQLi)', description: 'Identifies SQL injection flaws' },
    { value: 'CSRF', label: 'Cross-Site Request Forgery (CSRF)', description: 'Checks for CSRF vulnerabilities' },
    { value: 'Directory', label: 'Directory Traversal', description: 'Scans for directory traversal issues' }
  ];

  const validateUrl = (url) => {
    const urlRegex = /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&=]*)$/;
    return urlRegex.test(url);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Validation
    if (!url.trim()) {
      setError('Please enter a target URL');
      return;
    }

    if (!validateUrl(url)) {
      setError('Please enter a valid URL (e.g., https://example.com)');
      return;
    }

    if (!scanType) {
      setError('Please select a scan type');
      return;
    }

    setIsLoading(true);

    try {
      // Call backend API
      const response = await fetch('http://localhost:5000/scan/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url.trim(),
          scan_type: scanType
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess(`Scan started successfully! Scan ID: ${data.scan_id}`);
        setUrl('');
        setScanType('');
      } else {
        setError(data.error || 'Failed to start scan');
      }
    } catch (err) {
      console.error('Scan error:', err);
      setError('Network error. Please check if the backend is running.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={`scan-form ${theme}`}>
      <form onSubmit={handleSubmit} className="form">
        <div className="form-group">
          <label htmlFor="url" className="form-label">
            Target URL *
          </label>
          <input
            id="url"
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="form-input"
            disabled={isLoading}
          />
          <small className="form-hint">
            Enter the complete URL including protocol (http:// or https://)
          </small>
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
            disabled={isLoading}
          >
            <option value="">Select a scan type</option>
            {scanTypes.map((type) => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
          {scanType && (
            <small className="form-hint">
              {scanTypes.find(t => t.value === scanType)?.description}
            </small>
          )}
        </div>

        {error && (
          <div className="alert alert-error">
            <span className="alert-icon">⚠️</span>
            {error}
          </div>
        )}

        {success && (
          <div className="alert alert-success">
            <span className="alert-icon">✅</span>
            {success}
          </div>
        )}

        <button
          type="submit"
          className="submit-button"
          disabled={isLoading}
        >
          {isLoading ? (
            <>
              <span className="loading-spinner"></span>
              Starting Scan...
            </>
          ) : (
            <>
              <span className="button-icon">🔍</span>
              Start Security Scan
            </>
          )}
        </button>
      </form>
    </div>
  );
};

export default ScanForm; 