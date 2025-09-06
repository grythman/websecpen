import React, { useState, useEffect } from 'react';
import './CustomScanForm.css';

const CustomScanForm = ({ onScanStart }) => {
  const [url, setUrl] = useState('');
  const [selectedPreset, setSelectedPreset] = useState('');
  const [customConfig, setCustomConfig] = useState({
    scan_type: 'spider',
    max_depth: 10,
    ajax_spider: false,
    scan_policy: 'default',
    include_alpha: false,
    include_beta: false,
    custom_headers: {},
    authentication: null,
    exclusion_patterns: []
  });
  const [presets, setPresets] = useState({});
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [customHeaders, setCustomHeaders] = useState('');
  const [exclusionPatterns, setExclusionPatterns] = useState('');

  useEffect(() => {
    fetchPresets();
  }, []);

  const fetchPresets = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/scan/presets', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setPresets(data.presets);
      }
    } catch (error) {
      console.error('Error fetching presets:', error);
    }
  };

  const handlePresetChange = (presetName) => {
    setSelectedPreset(presetName);
    if (presetName && presets[presetName]) {
      setCustomConfig({...customConfig, ...presets[presetName].config});
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setMessage('');

    try {
      // Parse custom headers
      let parsedHeaders = {};
      if (customHeaders.trim()) {
        const headerLines = customHeaders.split('\n');
        headerLines.forEach(line => {
          const [key, value] = line.split(':').map(s => s.trim());
          if (key && value) {
            parsedHeaders[key] = value;
          }
        });
      }

      // Parse exclusion patterns
      let parsedPatterns = [];
      if (exclusionPatterns.trim()) {
        parsedPatterns = exclusionPatterns.split('\n').map(p => p.trim()).filter(p => p);
      }

      const scanConfig = {
        ...customConfig,
        custom_headers: parsedHeaders,
        exclusion_patterns: parsedPatterns
      };

      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/scan/start', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url,
          config: scanConfig
        })
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Scan started successfully!');
        if (onScanStart) {
          onScanStart(data);
        }
        // Reset form
        setUrl('');
        setSelectedPreset('');
        setCustomHeaders('');
        setExclusionPatterns('');
      } else {
        setMessage(data.error || 'Failed to start scan');
      }
    } catch (error) {
      setMessage('Error starting scan');
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const getScanTypeDescription = (type) => {
    const descriptions = {
      'spider': 'Crawls the website to discover pages and forms',
      'active': 'Performs active vulnerability scanning with attack payloads',
      'passive': 'Passive scanning without sending attack payloads',
      'baseline': 'Quick baseline scan for immediate security insights'
    };
    return descriptions[type] || '';
  };

  const getScanPolicyDescription = (policy) => {
    const descriptions = {
      'default': 'Standard security scanning policy',
      'comprehensive': 'Extensive scanning with all vulnerability checks',
      'modern_web': 'Optimized for modern web applications and SPAs'
    };
    return descriptions[policy] || '';
  };

  return (
    <div className="custom-scan-form">
      <div className="form-header">
        <h3>🔍 Custom Security Scan</h3>
        <p>Configure advanced scan parameters for comprehensive security testing</p>
      </div>

      <form onSubmit={handleSubmit}>
        {/* URL Input */}
        <div className="form-section">
          <div className="form-group">
            <label htmlFor="url">Target URL *</label>
            <input
              id="url"
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              required
              disabled={loading}
            />
          </div>
        </div>

        {/* Preset Selection */}
        <div className="form-section">
          <h4>Quick Presets</h4>
          <div className="preset-grid">
            {Object.entries(presets).map(([key, preset]) => (
              <div
                key={key}
                className={`preset-card ${selectedPreset === key ? 'selected' : ''}`}
                onClick={() => handlePresetChange(key)}
              >
                <h5>{preset.name}</h5>
                <p>{preset.description}</p>
                <div className="preset-config">
                  <span>Type: {preset.config.scan_type}</span>
                  <span>Depth: {preset.config.max_depth}</span>
                </div>
              </div>
            ))}
            <div
              className={`preset-card ${selectedPreset === 'custom' ? 'selected' : ''}`}
              onClick={() => handlePresetChange('custom')}
            >
              <h5>Custom</h5>
              <p>Create your own scan configuration</p>
              <div className="preset-config">
                <span>Manual setup</span>
              </div>
            </div>
          </div>
        </div>

        {/* Basic Configuration */}
        <div className="form-section">
          <h4>Scan Configuration</h4>
          <div className="form-grid">
            <div className="form-group">
              <label htmlFor="scan_type">Scan Type</label>
              <select
                id="scan_type"
                value={customConfig.scan_type}
                onChange={(e) => setCustomConfig({...customConfig, scan_type: e.target.value})}
                disabled={loading}
              >
                <option value="spider">Spider Scan</option>
                <option value="active">Active Scan</option>
                <option value="passive">Passive Scan</option>
                <option value="baseline">Baseline Scan</option>
              </select>
              <small>{getScanTypeDescription(customConfig.scan_type)}</small>
            </div>

            <div className="form-group">
              <label htmlFor="max_depth">Maximum Depth</label>
              <input
                id="max_depth"
                type="number"
                min="1"
                max="20"
                value={customConfig.max_depth}
                onChange={(e) => setCustomConfig({...customConfig, max_depth: parseInt(e.target.value)})}
                disabled={loading}
              />
              <small>How deep to crawl the website (1-20 levels)</small>
            </div>

            <div className="form-group">
              <label htmlFor="scan_policy">Scan Policy</label>
              <select
                id="scan_policy"
                value={customConfig.scan_policy}
                onChange={(e) => setCustomConfig({...customConfig, scan_policy: e.target.value})}
                disabled={loading}
              >
                <option value="default">Default Policy</option>
                <option value="comprehensive">Comprehensive</option>
                <option value="modern_web">Modern Web Apps</option>
              </select>
              <small>{getScanPolicyDescription(customConfig.scan_policy)}</small>
            </div>
          </div>

          <div className="checkbox-group">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={customConfig.ajax_spider}
                onChange={(e) => setCustomConfig({...customConfig, ajax_spider: e.target.checked})}
                disabled={loading}
              />
              <span>Enable AJAX Spider</span>
              <small>Scan modern JavaScript applications</small>
            </label>

            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={customConfig.include_alpha}
                onChange={(e) => setCustomConfig({...customConfig, include_alpha: e.target.checked})}
                disabled={loading}
              />
              <span>Include Alpha Rules</span>
              <small>Experimental vulnerability detection</small>
            </label>

            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={customConfig.include_beta}
                onChange={(e) => setCustomConfig({...customConfig, include_beta: e.target.checked})}
                disabled={loading}
              />
              <span>Include Beta Rules</span>
              <small>Latest vulnerability checks</small>
            </label>
          </div>
        </div>

        {/* Advanced Configuration */}
        <div className="form-section">
          <div className="advanced-toggle">
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="toggle-button"
            >
              {showAdvanced ? '⬆️' : '⬇️'} Advanced Configuration
            </button>
          </div>

          {showAdvanced && (
            <div className="advanced-config">
              <div className="form-group">
                <label htmlFor="custom_headers">Custom Headers</label>
                <textarea
                  id="custom_headers"
                  value={customHeaders}
                  onChange={(e) => setCustomHeaders(e.target.value)}
                  placeholder="Authorization: Bearer token&#10;User-Agent: Custom Agent&#10;X-Custom-Header: value"
                  rows="4"
                  disabled={loading}
                />
                <small>One header per line in format "Header: Value"</small>
              </div>

              <div className="form-group">
                <label htmlFor="exclusion_patterns">Exclusion Patterns</label>
                <textarea
                  id="exclusion_patterns"
                  value={exclusionPatterns}
                  onChange={(e) => setExclusionPatterns(e.target.value)}
                  placeholder="/admin/*&#10;/private/*&#10;*.pdf"
                  rows="4"
                  disabled={loading}
                />
                <small>URL patterns to exclude from scanning (one per line)</small>
              </div>
            </div>
          )}
        </div>

        {/* Submit Button */}
        <div className="form-actions">
          <button
            type="submit"
            disabled={loading || !url}
            className="scan-button"
          >
            {loading ? (
              <>
                <span className="button-spinner"></span>
                Starting Scan...
              </>
            ) : (
              <>
                🚀 Start Scan
              </>
            )}
          </button>
        </div>

        {message && (
          <div className={`message ${message.includes('Error') || message.includes('Failed') ? 'error' : 'success'}`}>
            {message}
          </div>
        )}
      </form>

      {/* Configuration Summary */}
      <div className="config-summary">
        <h4>Scan Summary</h4>
        <div className="summary-grid">
          <div className="summary-item">
            <span className="label">Type:</span>
            <span className="value">{customConfig.scan_type}</span>
          </div>
          <div className="summary-item">
            <span className="label">Depth:</span>
            <span className="value">{customConfig.max_depth}</span>
          </div>
          <div className="summary-item">
            <span className="label">Policy:</span>
            <span className="value">{customConfig.scan_policy}</span>
          </div>
          <div className="summary-item">
            <span className="label">AJAX:</span>
            <span className="value">{customConfig.ajax_spider ? 'Enabled' : 'Disabled'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CustomScanForm; 