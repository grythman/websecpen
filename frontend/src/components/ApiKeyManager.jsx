import React, { useState, useEffect } from 'react';
import './ApiKeyManager.css';

const ApiKeyManager = () => {
  const [apiKeys, setApiKeys] = useState([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newKeyData, setNewKeyData] = useState({
    name: '',
    expires_days: 365
  });
  const [message, setMessage] = useState('');
  const [createdKey, setCreatedKey] = useState(null);

  useEffect(() => {
    fetchApiKeys();
  }, []);

  const fetchApiKeys = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/apikey', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setApiKeys(data.api_keys || []);
      } else {
        setMessage('❌ Failed to load API keys');
      }
    } catch (error) {
      console.error('Error fetching API keys:', error);
      setMessage('❌ Error loading API keys');
    } finally {
      setLoading(false);
    }
  };

  const createApiKey = async () => {
    if (!newKeyData.name.trim()) {
      setMessage('❌ API key name is required');
      return;
    }

    setCreating(true);
    setMessage('');

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/apikey', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newKeyData)
      });

      if (response.ok) {
        const data = await response.json();
        setCreatedKey(data.api_key);
        setMessage('✅ API key created successfully!');
        setNewKeyData({ name: '', expires_days: 365 });
        setShowCreateForm(false);
        fetchApiKeys(); // Refresh the list
      } else {
        const errorData = await response.json();
        setMessage(`❌ ${errorData.error || 'Failed to create API key'}`);
      }
    } catch (error) {
      console.error('Error creating API key:', error);
      setMessage('❌ Error creating API key');
    } finally {
      setCreating(false);
    }
  };

  const revokeApiKey = async (keyId, keyName) => {
    if (!window.confirm(`Are you sure you want to revoke the API key "${keyName}"? This action cannot be undone.`)) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/apikey/${keyId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        setMessage('✅ API key revoked successfully');
        fetchApiKeys(); // Refresh the list
      } else {
        setMessage('❌ Failed to revoke API key');
      }
    } catch (error) {
      console.error('Error revoking API key:', error);
      setMessage('❌ Error revoking API key');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setMessage('✅ API key copied to clipboard');
      setTimeout(() => setMessage(''), 3000);
    }).catch(() => {
      setMessage('❌ Failed to copy to clipboard');
    });
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getKeyStatus = (key) => {
    if (!key.is_active) return 'inactive';
    if (key.is_expired) return 'expired';
    if (key.expires_at) {
      const expiryDate = new Date(key.expires_at);
      const now = new Date();
      const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
      if (daysUntilExpiry <= 7) return 'expiring';
    }
    return 'active';
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return '#28a745';
      case 'expiring': return '#ffc107';
      case 'expired': return '#dc3545';
      case 'inactive': return '#6c757d';
      default: return '#6c757d';
    }
  };

  const getStatusText = (status) => {
    switch (status) {
      case 'active': return 'Active';
      case 'expiring': return 'Expiring Soon';
      case 'expired': return 'Expired';
      case 'inactive': return 'Inactive';
      default: return 'Unknown';
    }
  };

  return (
    <div className="api-key-manager">
      <div className="manager-header">
        <h3>🔑 API Key Management</h3>
        <p>Create and manage API keys for programmatic access</p>
      </div>

      {message && (
        <div className={`message ${message.includes('✅') ? 'success' : 'error'}`}>
          {message}
        </div>
      )}

      {/* New API Key Display */}
      {createdKey && (
        <div className="created-key-display">
          <div className="key-created-header">
            <h4>🎉 New API Key Created</h4>
            <p>Please copy and save this key securely. You won't be able to see it again.</p>
          </div>
          <div className="key-display">
            <div className="key-info">
              <span className="key-label">Name:</span>
              <span className="key-value">{createdKey.name}</span>
            </div>
            <div className="key-info">
              <span className="key-label">Key:</span>
              <div className="key-value-container">
                <span className="key-value monospace">{createdKey.key}</span>
                <button
                  onClick={() => copyToClipboard(createdKey.key)}
                  className="copy-btn"
                  title="Copy to clipboard"
                >
                  📋
                </button>
              </div>
            </div>
            {createdKey.expires_at && (
              <div className="key-info">
                <span className="key-label">Expires:</span>
                <span className="key-value">{formatDate(createdKey.expires_at)}</span>
              </div>
            )}
          </div>
          <button
            onClick={() => setCreatedKey(null)}
            className="dismiss-btn"
          >
            ✅ I've saved the key securely
          </button>
        </div>
      )}

      {/* Create New API Key */}
      <div className="create-section">
        {!showCreateForm ? (
          <button
            onClick={() => setShowCreateForm(true)}
            className="create-key-btn"
          >
            ➕ Create New API Key
          </button>
        ) : (
          <div className="create-form">
            <h4>Create New API Key</h4>
            <div className="form-row">
              <div className="form-group">
                <label>Key Name *</label>
                <input
                  type="text"
                  value={newKeyData.name}
                  onChange={(e) => setNewKeyData({...newKeyData, name: e.target.value})}
                  placeholder="e.g., CI/CD Pipeline, Mobile App"
                  maxLength={50}
                />
              </div>
              <div className="form-group">
                <label>Expires After</label>
                <select
                  value={newKeyData.expires_days}
                  onChange={(e) => setNewKeyData({...newKeyData, expires_days: parseInt(e.target.value)})}
                >
                  <option value={30}>30 days</option>
                  <option value={90}>90 days</option>
                  <option value={180}>6 months</option>
                  <option value={365}>1 year</option>
                  <option value={0}>Never expires</option>
                </select>
              </div>
            </div>
            <div className="form-actions">
              <button
                onClick={() => {
                  setShowCreateForm(false);
                  setNewKeyData({ name: '', expires_days: 365 });
                }}
                className="cancel-btn"
              >
                Cancel
              </button>
              <button
                onClick={createApiKey}
                disabled={creating || !newKeyData.name.trim()}
                className="create-btn"
              >
                {creating ? (
                  <>
                    <span className="btn-spinner"></span>
                    Creating...
                  </>
                ) : (
                  '🔑 Create API Key'
                )}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* API Keys List */}
      <div className="keys-section">
        <div className="section-header">
          <h4>Your API Keys ({apiKeys.length})</h4>
          <button onClick={fetchApiKeys} className="refresh-btn" disabled={loading}>
            🔄 Refresh
          </button>
        </div>

        {loading ? (
          <div className="loading-state">
            <div className="spinner"></div>
            <p>Loading API keys...</p>
          </div>
        ) : apiKeys.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">🔑</div>
            <h4>No API Keys Created</h4>
            <p>Create your first API key to start using the WebSecPen API programmatically.</p>
          </div>
        ) : (
          <div className="keys-list">
            {apiKeys.map((key) => {
              const status = getKeyStatus(key);
              return (
                <div key={key.id} className={`key-item ${status}`}>
                  <div className="key-header">
                    <div className="key-name">
                      <span className="name">{key.name}</span>
                      <span 
                        className="status-badge"
                        style={{ backgroundColor: getStatusColor(status) }}
                      >
                        {getStatusText(status)}
                      </span>
                    </div>
                    <div className="key-actions">
                      <button
                        onClick={() => revokeApiKey(key.id, key.name)}
                        className="revoke-btn"
                        title="Revoke API key"
                      >
                        🗑️
                      </button>
                    </div>
                  </div>
                  
                  <div className="key-details">
                    <div className="detail-item">
                      <span className="detail-label">Key:</span>
                      <span className="detail-value monospace">{key.key}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Created:</span>
                      <span className="detail-value">{formatDate(key.created_at)}</span>
                    </div>
                    {key.expires_at && (
                      <div className="detail-item">
                        <span className="detail-label">Expires:</span>
                        <span className="detail-value">{formatDate(key.expires_at)}</span>
                      </div>
                    )}
                    {key.last_used && (
                      <div className="detail-item">
                        <span className="detail-label">Last Used:</span>
                        <span className="detail-value">{formatDate(key.last_used)}</span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Usage Information */}
      <div className="usage-info">
        <h4>📚 API Usage Examples</h4>
        <div className="examples">
          <div className="example">
            <h5>Start a Scan</h5>
            <pre className="code-block">
{`curl -X POST https://your-app.com/api/scan/start \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://example.com"}'`}
            </pre>
          </div>
          <div className="example">
            <h5>Get Scan Results</h5>
            <pre className="code-block">
{`curl -X GET https://your-app.com/api/scan/result/123 \\
  -H "X-API-Key: YOUR_API_KEY"`}
            </pre>
          </div>
          <div className="example">
            <h5>JavaScript/Node.js</h5>
            <pre className="code-block">
{`const response = await fetch('/api/scan/start', {
  method: 'POST',
  headers: {
    'X-API-Key': 'YOUR_API_KEY',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ url: 'https://example.com' })
});`}
            </pre>
          </div>
        </div>
        
        <div className="security-note">
          <h5>🔒 Security Best Practices</h5>
          <ul>
            <li>Store API keys securely and never commit them to version control</li>
            <li>Use environment variables or secure key management systems</li>
            <li>Rotate keys regularly and revoke unused keys</li>
            <li>Use HTTPS for all API requests</li>
            <li>Monitor API key usage for suspicious activity</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default ApiKeyManager; 