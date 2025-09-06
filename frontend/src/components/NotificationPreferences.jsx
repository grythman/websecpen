import React, { useState, useEffect } from 'react';
import './NotificationPreferences.css';

const NotificationPreferences = () => {
  const [settings, setSettings] = useState({
    email: true,
    in_app: true,
    slack: false,
    sms: false,
    high_severity_only: false
  });
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/notification/settings', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setSettings(data);
      } else {
        setMessage('Failed to load notification settings');
      }
    } catch (error) {
      console.error('Error fetching settings:', error);
      setMessage('Error loading settings');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = async () => {
    setSaving(true);
    setMessage('');
    
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/notification/settings', {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(settings)
      });

      if (response.ok) {
        const data = await response.json();
        setSettings(data.settings);
        setMessage('✅ Notification preferences updated successfully!');
        setTimeout(() => setMessage(''), 3000);
      } else {
        setMessage('❌ Failed to update preferences');
      }
    } catch (error) {
      console.error('Error updating settings:', error);
      setMessage('❌ Error updating preferences');
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = (key) => {
    setSettings(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const handleReset = () => {
    setSettings({
      email: true,
      in_app: true,
      slack: false,
      sms: false,
      high_severity_only: false
    });
  };

  if (loading) {
    return (
      <div className="notification-preferences loading">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading notification preferences...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="notification-preferences">
      <div className="preferences-header">
        <h3>🔔 Notification Preferences</h3>
        <p>Customize how you want to receive security scan notifications</p>
      </div>

      {message && (
        <div className={`message ${message.includes('✅') ? 'success' : 'error'}`}>
          {message}
        </div>
      )}

      <div className="preferences-form">
        {/* Email Notifications */}
        <div className="preference-group">
          <div className="preference-header">
            <h4>📧 Email Notifications</h4>
            <p>Receive notifications via email</p>
          </div>
          <div className="preference-item">
            <label className="toggle-switch">
              <input
                type="checkbox"
                checked={settings.email}
                onChange={() => handleToggle('email')}
              />
              <span className="slider"></span>
            </label>
            <div className="preference-info">
              <span className="preference-title">Email alerts</span>
              <span className="preference-description">
                Get notified when scans complete or encounter issues
              </span>
            </div>
          </div>
        </div>

        {/* In-App Notifications */}
        <div className="preference-group">
          <div className="preference-header">
            <h4>🔔 In-App Notifications</h4>
            <p>Real-time notifications within the application</p>
          </div>
          <div className="preference-item">
            <label className="toggle-switch">
              <input
                type="checkbox"
                checked={settings.in_app}
                onChange={() => handleToggle('in_app')}
              />
              <span className="slider"></span>
            </label>
            <div className="preference-info">
              <span className="preference-title">Push notifications</span>
              <span className="preference-description">
                Instant notifications while using the application
              </span>
            </div>
          </div>
        </div>

        {/* Slack Integration */}
        <div className="preference-group">
          <div className="preference-header">
            <h4>💬 Slack Integration</h4>
            <p>Send notifications to your Slack workspace</p>
          </div>
          <div className="preference-item">
            <label className="toggle-switch">
              <input
                type="checkbox"
                checked={settings.slack}
                onChange={() => handleToggle('slack')}
              />
              <span className="slider"></span>
            </label>
            <div className="preference-info">
              <span className="preference-title">Slack webhooks</span>
              <span className="preference-description">
                Integrate with Slack channels for team notifications
              </span>
            </div>
          </div>
          {settings.slack && (
            <div className="integration-note">
              <p>💡 <strong>Note:</strong> Configure webhook URLs in your profile settings to enable Slack notifications.</p>
            </div>
          )}
        </div>

        {/* SMS Notifications */}
        <div className="preference-group">
          <div className="preference-header">
            <h4>📱 SMS Notifications</h4>
            <p>Critical alerts via text message</p>
          </div>
          <div className="preference-item">
            <label className="toggle-switch">
              <input
                type="checkbox"
                checked={settings.sms}
                onChange={() => handleToggle('sms')}
              />
              <span className="slider"></span>
            </label>
            <div className="preference-info">
              <span className="preference-title">SMS alerts</span>
              <span className="preference-description">
                Urgent notifications for high-severity findings
              </span>
            </div>
          </div>
          {settings.sms && (
            <div className="integration-note">
              <p>💡 <strong>Note:</strong> SMS notifications require phone number verification in your profile.</p>
            </div>
          )}
        </div>

        {/* Filter Preferences */}
        <div className="preference-group">
          <div className="preference-header">
            <h4>🎯 Notification Filters</h4>
            <p>Control when you receive notifications</p>
          </div>
          <div className="preference-item">
            <label className="toggle-switch">
              <input
                type="checkbox"
                checked={settings.high_severity_only}
                onChange={() => handleToggle('high_severity_only')}
              />
              <span className="slider"></span>
            </label>
            <div className="preference-info">
              <span className="preference-title">High severity only</span>
              <span className="preference-description">
                Only notify for high and critical severity vulnerabilities
              </span>
            </div>
          </div>
        </div>

        {/* Notification Summary */}
        <div className="notification-summary">
          <h4>📊 Current Configuration</h4>
          <div className="summary-grid">
            <div className={`summary-item ${settings.email ? 'enabled' : 'disabled'}`}>
              <span className="summary-icon">📧</span>
              <span className="summary-text">Email</span>
              <span className={`summary-status ${settings.email ? 'enabled' : 'disabled'}`}>
                {settings.email ? 'ON' : 'OFF'}
              </span>
            </div>
            <div className={`summary-item ${settings.in_app ? 'enabled' : 'disabled'}`}>
              <span className="summary-icon">🔔</span>
              <span className="summary-text">In-App</span>
              <span className={`summary-status ${settings.in_app ? 'enabled' : 'disabled'}`}>
                {settings.in_app ? 'ON' : 'OFF'}
              </span>
            </div>
            <div className={`summary-item ${settings.slack ? 'enabled' : 'disabled'}`}>
              <span className="summary-icon">💬</span>
              <span className="summary-text">Slack</span>
              <span className={`summary-status ${settings.slack ? 'enabled' : 'disabled'}`}>
                {settings.slack ? 'ON' : 'OFF'}
              </span>
            </div>
            <div className={`summary-item ${settings.sms ? 'enabled' : 'disabled'}`}>
              <span className="summary-icon">📱</span>
              <span className="summary-text">SMS</span>
              <span className={`summary-status ${settings.sms ? 'enabled' : 'disabled'}`}>
                {settings.sms ? 'ON' : 'OFF'}
              </span>
            </div>
          </div>
          {settings.high_severity_only && (
            <div className="filter-notice">
              <span className="filter-icon">🎯</span>
              <span>Only high severity notifications enabled</span>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="preferences-actions">
          <button
            onClick={handleReset}
            className="reset-btn"
            disabled={saving}
          >
            🔄 Reset to Defaults
          </button>
          <button
            onClick={handleUpdate}
            className="save-btn"
            disabled={saving}
          >
            {saving ? (
              <>
                <span className="btn-spinner"></span>
                Saving...
              </>
            ) : (
              '💾 Save Preferences'
            )}
          </button>
        </div>

        {/* Help Section */}
        <div className="preferences-help">
          <h4>❓ Need Help?</h4>
          <div className="help-items">
            <div className="help-item">
              <strong>Email notifications</strong> are sent to your registered email address
            </div>
            <div className="help-item">
              <strong>In-app notifications</strong> appear as browser notifications and in the app
            </div>
            <div className="help-item">
              <strong>Slack integration</strong> requires webhook URL configuration
            </div>
            <div className="help-item">
              <strong>SMS notifications</strong> are available for premium users only
            </div>
            <div className="help-item">
              <strong>High severity filter</strong> reduces notification volume to critical issues only
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NotificationPreferences; 