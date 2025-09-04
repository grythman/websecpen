import React, { useState, useEffect } from 'react';
import QRCode from 'qrcode.react';
import './TwoFactorAuth.css';

const TwoFactorAuth = ({ user, onUpdate }) => {
  const [step, setStep] = useState('check'); // check, setup, verify, manage
  const [qrData, setQrData] = useState(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [backupCodes, setBackupCodes] = useState([]);
  const [currentPassword, setCurrentPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showBackupCodes, setShowBackupCodes] = useState(false);

  useEffect(() => {
    checkTwoFactorStatus();
  }, []);

  const checkTwoFactorStatus = () => {
    if (user && user['2fa_enabled']) {
      setStep('manage');
    } else {
      setStep('check');
    }
  };

  const initializeSetup = async () => {
    setLoading(true);
    setError('');
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/2fa/setup', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setQrData(data);
        setStep('setup');
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Failed to initialize 2FA setup');
      }
    } catch (error) {
      setError('Network error occurred');
    } finally {
      setLoading(false);
    }
  };

  const verifyAndEnable = async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      setError('Please enter a valid 6-digit code');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/2fa/verify', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ code: verificationCode })
      });

      if (response.ok) {
        const data = await response.json();
        setBackupCodes(data.backup_codes || []);
        setSuccess('2FA enabled successfully!');
        setStep('backup-codes');
        if (onUpdate) {
          onUpdate({ ...user, '2fa_enabled': true });
        }
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Invalid verification code');
      }
    } catch (error) {
      setError('Network error occurred');
    } finally {
      setLoading(false);
    }
  };

  const disable2FA = async () => {
    if (!currentPassword || !verificationCode) {
      setError('Please enter your current password and 2FA code');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/2fa/disable', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          password: currentPassword,
          code: verificationCode
        })
      });

      if (response.ok) {
        setSuccess('2FA disabled successfully');
        setStep('check');
        setCurrentPassword('');
        setVerificationCode('');
        if (onUpdate) {
          onUpdate({ ...user, '2fa_enabled': false });
        }
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Failed to disable 2FA');
      }
    } catch (error) {
      setError('Network error occurred');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setSuccess('Copied to clipboard!');
      setTimeout(() => setSuccess(''), 2000);
    });
  };

  const downloadBackupCodes = () => {
    const content = `WebSecPen 2FA Backup Codes\nGenerated: ${new Date().toISOString()}\n\n${backupCodes.join('\n')}\n\nKeep these codes safe! Each can only be used once.`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `websecpen-backup-codes-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const renderCheckStep = () => (
    <div className="two-factor-check">
      <div className="feature-header">
        <div className="feature-icon">🔐</div>
        <h3>Two-Factor Authentication</h3>
        <p>Add an extra layer of security to your account</p>
      </div>

      <div className="security-benefits">
        <h4>🛡️ Why enable 2FA?</h4>
        <ul>
          <li>✅ Protects against password breaches</li>
          <li>✅ Prevents unauthorized access</li>
          <li>✅ Industry standard security practice</li>
          <li>✅ Works with popular authenticator apps</li>
        </ul>
      </div>

      <div className="compatible-apps">
        <h4>📱 Compatible Apps</h4>
        <div className="app-list">
          <div className="app-item">
            <span className="app-icon">🔑</span>
            <span>Google Authenticator</span>
          </div>
          <div className="app-item">
            <span className="app-icon">🔒</span>
            <span>Authy</span>
          </div>
          <div className="app-item">
            <span className="app-icon">🔐</span>
            <span>Microsoft Authenticator</span>
          </div>
          <div className="app-item">
            <span className="app-icon">🛡️</span>
            <span>1Password</span>
          </div>
        </div>
      </div>

      <div className="action-buttons">
        <button
          className="btn btn-primary btn-lg"
          onClick={initializeSetup}
          disabled={loading}
        >
          {loading ? '⏳ Setting up...' : '🚀 Enable 2FA'}
        </button>
      </div>
    </div>
  );

  const renderSetupStep = () => (
    <div className="two-factor-setup">
      <div className="setup-header">
        <h3>🔐 Set Up Two-Factor Authentication</h3>
        <div className="step-indicator">
          <span className="step active">1. Scan QR Code</span>
          <span className="step">2. Verify Setup</span>
        </div>
      </div>

      <div className="setup-content">
        <div className="qr-section">
          <div className="qr-container">
            {qrData && qrData.qr_code_image ? (
              <img 
                src={qrData.qr_code_image} 
                alt="2FA QR Code"
                className="qr-code-image"
              />
            ) : (
              <QRCode 
                value={qrData?.qr_code_uri || ''} 
                size={200}
                level="M"
                includeMargin={true}
              />
            )}
          </div>
          
          <div className="manual-entry">
            <h5>📝 Manual Entry</h5>
            <p>Can't scan? Enter this code manually:</p>
            <div className="secret-code">
              <code>{qrData?.secret}</code>
              <button
                className="btn-copy"
                onClick={() => copyToClipboard(qrData?.secret)}
                title="Copy to clipboard"
              >
                📋
              </button>
            </div>
          </div>
        </div>

        <div className="instructions">
          <h5>📱 Instructions</h5>
          <ol>
            <li>Open your authenticator app</li>
            <li>Tap "Add account" or "+" button</li>
            <li>Scan the QR code or enter the code manually</li>
            <li>Enter the 6-digit code below to verify</li>
          </ol>
        </div>
      </div>

      <div className="verification-section">
        <h5>🔢 Enter Verification Code</h5>
        <div className="code-input-group">
          <input
            type="text"
            value={verificationCode}
            onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            placeholder="000000"
            className="verification-input"
            maxLength="6"
          />
          <button
            className="btn btn-primary"
            onClick={verifyAndEnable}
            disabled={loading || verificationCode.length !== 6}
          >
            {loading ? '⏳ Verifying...' : '✅ Verify & Enable'}
          </button>
        </div>
        <small className="input-help">
          Enter the 6-digit code from your authenticator app
        </small>
      </div>

      <div className="setup-actions">
        <button
          className="btn btn-secondary"
          onClick={() => setStep('check')}
          disabled={loading}
        >
          ⬅️ Back
        </button>
      </div>
    </div>
  );

  const renderBackupCodesStep = () => (
    <div className="backup-codes-step">
      <div className="success-header">
        <div className="success-icon">🎉</div>
        <h3>2FA Enabled Successfully!</h3>
        <p>Your account is now protected with two-factor authentication</p>
      </div>

      <div className="backup-codes-section">
        <div className="backup-header">
          <h4>🔑 Backup Codes</h4>
          <p>Save these backup codes in a safe place. Each code can only be used once if you lose access to your authenticator app.</p>
        </div>

        <div className="backup-codes-container">
          <div className="codes-grid">
            {backupCodes.map((code, index) => (
              <div key={index} className="backup-code">
                <span className="code-number">{index + 1}.</span>
                <code className="code-value">{code}</code>
                <button
                  className="btn-copy-code"
                  onClick={() => copyToClipboard(code)}
                  title="Copy code"
                >
                  📋
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className="backup-actions">
          <button
            className="btn btn-primary"
            onClick={downloadBackupCodes}
          >
            💾 Download Codes
          </button>
          <button
            className="btn btn-outline-primary"
            onClick={() => copyToClipboard(backupCodes.join('\n'))}
          >
            📋 Copy All
          </button>
        </div>

        <div className="backup-warning">
          <div className="warning-icon">⚠️</div>
          <div className="warning-content">
            <strong>Important:</strong> Store these codes securely. They are your only way to access your account if you lose your authenticator device.
          </div>
        </div>
      </div>

      <div className="completion-actions">
        <button
          className="btn btn-success btn-lg"
          onClick={() => setStep('manage')}
        >
          ✅ Continue to Security Settings
        </button>
      </div>
    </div>
  );

  const renderManageStep = () => (
    <div className="two-factor-manage">
      <div className="manage-header">
        <div className="status-indicator enabled">
          <span className="status-icon">✅</span>
          <div className="status-content">
            <h3>Two-Factor Authentication Enabled</h3>
            <p>Your account is protected with 2FA</p>
          </div>
        </div>
      </div>

      <div className="manage-sections">
        <div className="section backup-codes-management">
          <h4>🔑 Backup Codes</h4>
          <p>Manage your backup codes for emergency access</p>
          <div className="section-actions">
            <button
              className="btn btn-outline-primary"
              onClick={() => setShowBackupCodes(!showBackupCodes)}
            >
              {showBackupCodes ? '🙈 Hide' : '👁️ View'} Backup Codes
            </button>
            <button className="btn btn-outline-secondary">
              🔄 Generate New Codes
            </button>
          </div>
          
          {showBackupCodes && (
            <div className="backup-codes-display">
              <p><strong>Note:</strong> These are placeholder codes. Implement backup code retrieval API.</p>
              <div className="codes-list">
                {['XXXX-XXXX', 'XXXX-XXXX', 'XXXX-XXXX'].map((code, index) => (
                  <div key={index} className="backup-code-item">
                    <code>{code}</code>
                    <span className="code-status unused">Unused</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="section device-management">
          <h4>📱 Authenticator App</h4>
          <p>Your 2FA is configured with an authenticator app</p>
          <div className="device-info">
            <div className="device-item">
              <span className="device-icon">📱</span>
              <div className="device-details">
                <strong>Authenticator App</strong>
                <small>Last used: Recently</small>
              </div>
              <span className="device-status active">Active</span>
            </div>
          </div>
        </div>

        <div className="section danger-zone">
          <h4>⚠️ Disable Two-Factor Authentication</h4>
          <p>This will make your account less secure. Only disable if necessary.</p>
          
          <div className="disable-form">
            <div className="form-group">
              <label htmlFor="current-password">Current Password:</label>
              <input
                id="current-password"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter your current password"
                className="form-control"
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="disable-code">2FA Code:</label>
              <input
                id="disable-code"
                type="text"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                className="form-control"
                maxLength="6"
              />
            </div>

            <button
              className="btn btn-danger"
              onClick={disable2FA}
              disabled={loading || !currentPassword || verificationCode.length !== 6}
            >
              {loading ? '⏳ Disabling...' : '🚫 Disable 2FA'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="two-factor-auth">
      {error && (
        <div className="alert alert-danger">
          <span className="alert-icon">❌</span>
          {error}
          <button
            className="alert-close"
            onClick={() => setError('')}
          >
            ✕
          </button>
        </div>
      )}

      {success && (
        <div className="alert alert-success">
          <span className="alert-icon">✅</span>
          {success}
          <button
            className="alert-close"
            onClick={() => setSuccess('')}
          >
            ✕
          </button>
        </div>
      )}

      <div className="two-factor-content">
        {step === 'check' && renderCheckStep()}
        {step === 'setup' && renderSetupStep()}
        {step === 'backup-codes' && renderBackupCodesStep()}
        {step === 'manage' && renderManageStep()}
      </div>
    </div>
  );
};

export default TwoFactorAuth; 