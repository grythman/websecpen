import React, { useState, useEffect } from 'react';
import './CustomScanForm.css';
import apiService from '../services/api.js';

const steps = [
  { key: 'target', label: 'Target' },
  { key: 'config', label: 'Configuration' },
  { key: 'review', label: 'Review' }
];

const CustomScanForm = ({ onScanStart }) => {
  const [stepIdx, setStepIdx] = useState(0);
  const [url, setUrl] = useState('');
  const [selectedPreset, setSelectedPreset] = useState('');
  const [customConfig, setCustomConfig] = useState({
    scan_type: 'XSS',
    max_depth: 3,
    include_sql: true,
    include_xss: true,
    include_csrf: false,
    include_directory: false,
    scan_delay: 1,
    aggressive_mode: false,
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
      const data = await apiService.getScanPresets();
      setPresets(data.presets || {});
    } catch (error) {
      console.error('Error fetching presets:', error);
    }
  };

  const handlePresetChange = (presetKey) => {
    setSelectedPreset(presetKey);
    if (presetKey && presets[presetKey]) {
      setCustomConfig({ ...customConfig, ...presets[presetKey].config });
    }
  };

  const nextStep = () => setStepIdx((i) => Math.min(i + 1, steps.length - 1));
  const prevStep = () => setStepIdx((i) => Math.max(i - 1, 0));

  const handleSubmit = async (e) => {
    e?.preventDefault?.();
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

      const payload = {
        url,
        scan_type: customConfig.scan_type,
        max_depth: customConfig.max_depth,
        include_sql: customConfig.include_sql,
        include_xss: customConfig.include_xss,
        include_csrf: customConfig.include_csrf,
        include_directory: customConfig.include_directory,
        scan_delay: customConfig.scan_delay,
        aggressive_mode: customConfig.aggressive_mode,
        custom_headers: parsedHeaders
      };

      const response = await apiService.startScan(payload);

      setMessage('Scan started successfully!');
      if (onScanStart) onScanStart(response);
      // Reset form
      setUrl('');
      setSelectedPreset('');
      setCustomHeaders('');
      setExclusionPatterns('');
      setStepIdx(0);
    } catch (error) {
      setMessage(error.message || 'Failed to start scan');
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

      {/* Wizard steps indicator */}
      <div className="wizard-steps">
        {steps.map((s, i) => (
          <div key={s.key} className={`wizard-step ${i === stepIdx ? 'active' : ''} ${i < stepIdx ? 'done' : ''}`}>
            <span className="step-index">{i + 1}</span>
            <span className="step-label">{s.label}</span>
          </div>
        ))}
      </div>

      <form onSubmit={handleSubmit}>
        {/* Step 1: URL */}
        {stepIdx === 0 && (
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
            <div className="form-actions">
              <button type="button" className="scan-button" disabled={!url} onClick={nextStep}>
                Next →
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Preset + Config */}
        {stepIdx === 1 && (
          <>
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

            <div className="form-section">
              <h4>Scan Configuration</h4>
              <div className="form-grid">
                <div className="form-group">
                  <label htmlFor="scan_type">Scan Type</label>
                  <select
                    id="scan_type"
                    value={customConfig.scan_type}
                    onChange={(e) => setCustomConfig({ ...customConfig, scan_type: e.target.value })}
                    disabled={loading}
                  >
                    <option value="XSS">XSS</option>
                    <option value="SQLi">SQL Injection</option>
                    <option value="CSRF">CSRF</option>
                    <option value="Directory">Directory</option>
                  </select>
                </div>

                <div className="form-group">
                  <label htmlFor="max_depth">Maximum Depth</label>
                  <input
                    id="max_depth"
                    type="number"
                    min="1"
                    max="20"
                    value={customConfig.max_depth}
                    onChange={(e) => setCustomConfig({ ...customConfig, max_depth: parseInt(e.target.value) })}
                    disabled={loading}
                  />
                  <small>How deep to crawl the website (1-20 levels)</small>
                </div>

                <div className="form-group">
                  <label htmlFor="scan_delay">Scan Delay (sec)</label>
                  <input
                    id="scan_delay"
                    type="number"
                    min="0.5"
                    max="10"
                    step="0.5"
                    value={customConfig.scan_delay}
                    onChange={(e) => setCustomConfig({ ...customConfig, scan_delay: parseFloat(e.target.value) })}
                    disabled={loading}
                  />
                  <small>Delay between requests (0.5 - 10s)</small>
                </div>
              </div>

              <div className="checkbox-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={customConfig.include_sql}
                    onChange={(e) => setCustomConfig({ ...customConfig, include_sql: e.target.checked })}
                    disabled={loading}
                  />
                  <span>Include SQLi checks</span>
                  <small>SQL injection patterns</small>
                </label>

                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={customConfig.include_xss}
                    onChange={(e) => setCustomConfig({ ...customConfig, include_xss: e.target.checked })}
                    disabled={loading}
                  />
                  <span>Include XSS checks</span>
                  <small>Cross-site scripting</small>
                </label>

                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={customConfig.include_csrf}
                    onChange={(e) => setCustomConfig({ ...customConfig, include_csrf: e.target.checked })}
                    disabled={loading}
                  />
                  <span>Include CSRF checks</span>
                  <small>Cross-site request forgery</small>
                </label>

                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={customConfig.include_directory}
                    onChange={(e) => setCustomConfig({ ...customConfig, include_directory: e.target.checked })}
                    disabled={loading}
                  />
                  <span>Include Directory checks</span>
                  <small>Path traversal and exposure</small>
                </label>

                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={customConfig.aggressive_mode}
                    onChange={(e) => setCustomConfig({ ...customConfig, aggressive_mode: e.target.checked })}
                    disabled={loading}
                  />
                  <span>Aggressive mode</span>
                  <small>More thorough but slower</small>
                </label>
              </div>

              <div className="form-actions">
                <button type="button" className="scan-button" onClick={prevStep}>← Back</button>
                <button type="button" className="scan-button" onClick={nextStep}>Next →</button>
              </div>
            </div>
          </>
        )}

        {/* Step 3: Advanced + Review */}
        {stepIdx === 2 && (
          <>
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

            {/* Review Summary */}
            <div className="config-summary">
              <h4>Scan Summary</h4>
              <div className="summary-grid">
                <div className="summary-item">
                  <span className="label">Target:</span>
                  <span className="value">{url || '-'}</span>
                </div>
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
              <div className="form-actions">
                <button type="button" className="scan-button" onClick={prevStep}>← Back</button>
                <button type="submit" disabled={loading || !url} className="scan-button">
                  {loading ? (
                    <>
                      <span className="button-spinner"></span>
                      Starting Scan...
                    </>
                  ) : (
                    <>🚀 Start Scan</>
                  )}
                </button>
              </div>
            </div>

            {message && (
              <div className={`message ${message.includes('Error') || message.includes('Failed') ? 'error' : 'success'}`}>
                {message}
              </div>
            )}
          </>
        )}
      </form>
    </div>
  );
};

export default CustomScanForm; 