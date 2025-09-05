import React, { useState, useEffect } from 'react';
import { 
  requestNotificationPermission, 
  disableNotifications, 
  sendTestNotification,
  getNotificationStatus,
  isNotificationSupported 
} from '../firebase';
import './NotificationSettings.css';

const NotificationSettings = () => {
  const [notificationStatus, setNotificationStatus] = useState('unsupported');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    updateStatus();
  }, []);

  const updateStatus = () => {
    const status = getNotificationStatus();
    setNotificationStatus(status);
  };

  const handleEnableNotifications = async () => {
    setLoading(true);
    setError('');
    setMessage('');

    try {
      await requestNotificationPermission();
      setMessage('Notifications enabled successfully!');
      updateStatus();
    } catch (error) {
      setError(error.message || 'Failed to enable notifications');
    } finally {
      setLoading(false);
    }
  };

  const handleDisableNotifications = async () => {
    setLoading(true);
    setError('');
    setMessage('');

    try {
      await disableNotifications();
      setMessage('Notifications disabled successfully');
      updateStatus();
    } catch (error) {
      setError(error.message || 'Failed to disable notifications');
    } finally {
      setLoading(false);
    }
  };

  const handleTestNotification = async () => {
    setLoading(true);
    setError('');
    setMessage('');

    try {
      const result = await sendTestNotification();
      if (result.success) {
        setMessage('Test notification sent! Check your device.');
      } else {
        setError('Failed to send test notification');
      }
    } catch (error) {
      setError(error.message || 'Failed to send test notification');
    } finally {
      setLoading(false);
    }
  };

  const renderStatus = () => {
    if (!isNotificationSupported()) {
      return (
        <div className="notification-status unsupported">
          <span className="status-icon">❌</span>
          <span>Push notifications are not supported in this browser</span>
        </div>
      );
    }

    const status = notificationStatus;
    
    if (status.permission === 'denied') {
      return (
        <div className="notification-status denied">
          <span className="status-icon">🚫</span>
          <span>Notifications are blocked. Please enable them in your browser settings.</span>
        </div>
      );
    }

    if (status.permission === 'granted' && status.enabled) {
      return (
        <div className="notification-status enabled">
          <span className="status-icon">✅</span>
          <span>Notifications are enabled</span>
        </div>
      );
    }

    return (
      <div className="notification-status disabled">
        <span className="status-icon">🔔</span>
        <span>Notifications are available but not enabled</span>
      </div>
    );
  };

  const canEnable = isNotificationSupported() && 
    notificationStatus.permission !== 'denied' && 
    !notificationStatus.enabled;

  const canDisable = isNotificationSupported() && 
    notificationStatus.permission === 'granted' && 
    notificationStatus.enabled;

  const canTest = isNotificationSupported() && 
    notificationStatus.permission === 'granted' && 
    notificationStatus.enabled;

  return (
    <div className="notification-settings">
      <div className="settings-header">
        <h3>🔔 Push Notifications</h3>
        <p>Get notified when your security scans complete</p>
      </div>

      {renderStatus()}

      <div className="notification-features">
        <h4>What you'll receive:</h4>
        <ul>
          <li>✅ Scan completion notifications</li>
          <li>🚨 Critical vulnerability alerts</li>
          <li>📊 Weekly security summaries</li>
          <li>🎯 Achievement unlock notifications</li>
        </ul>
      </div>

      <div className="notification-actions">
        {canEnable && (
          <button 
            className="btn btn-primary"
            onClick={handleEnableNotifications}
            disabled={loading}
          >
            {loading ? 'Enabling...' : 'Enable Notifications'}
          </button>
        )}

        {canDisable && (
          <button 
            className="btn btn-secondary"
            onClick={handleDisableNotifications}
            disabled={loading}
          >
            {loading ? 'Disabling...' : 'Disable Notifications'}
          </button>
        )}

        {canTest && (
          <button 
            className="btn btn-outline"
            onClick={handleTestNotification}
            disabled={loading}
          >
            {loading ? 'Sending...' : 'Send Test Notification'}
          </button>
        )}
      </div>

      {message && (
        <div className="notification-message success">
          {message}
        </div>
      )}

      {error && (
        <div className="notification-message error">
          {error}
        </div>
      )}

      <div className="notification-info">
        <h4>About Push Notifications:</h4>
        <ul>
          <li>Notifications work even when the app is closed</li>
          <li>You can disable them anytime in settings</li>
          <li>We respect your privacy and only send relevant security updates</li>
          <li>Notifications are delivered via Firebase Cloud Messaging</li>
        </ul>
      </div>
    </div>
  );
};

export default NotificationSettings; 