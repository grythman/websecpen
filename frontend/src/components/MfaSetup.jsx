import React, { useState, useEffect } from 'react';
import QRCode from 'qrcode.react';
import './MfaSetup.css';

const MfaSetup = () => {
  const [mfaStatus, setMfaStatus] = useState({ enabled: false });
  const [setupData, setSetupData] = useState(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [step, setStep] = useState('status'); // 'status', 'setup', 'verify', 'complete'

  useEffect(() => {
    fetchMfaStatus();
  }, []);

  const fetchMfaStatus = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/mfa/status', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setMfaStatus(data);
      }
    } catch (error) {
      console.error('Error fetching MFA status:', error);
    }
  };

  const handleSetupMfa = async () => {
    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/mfa/setup', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      const data = await response.json();

      if (response.ok) {
        setSetupData(data);
        setStep('setup');
        setMessage('Scan the QR code with your authenticator app');
      } else {
        setMessage(data.error || 'Failed to setup MFA');
      }
    } catch (error) {
      setMessage('Error setting up MFA');
      console.error('MFA setup error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyMfa = async (e) => {
    e.preventDefault();
    
    if (!verificationCode || verificationCode.length !== 6) {
      setMessage('Please enter a 6-digit verification code');
      return;
    }

    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/mfa/verify', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ code: verificationCode })
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('MFA enabled successfully!');
        setStep('complete');
        setShowBackupCodes(true);
        setMfaStatus({ enabled: true });
      } else {
        setMessage(data.error || 'Invalid verification code');
      }
    } catch (error) {
      setMessage('Error verifying MFA code');
      console.error('MFA verification error:', error);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setMessage('Copied to clipboard!');
      setTimeout(() => setMessage(''), 2000);
    });
  };

  const downloadBackupCodes = () => {
    if (!setupData?.backup_codes) return;

    const codes = setupData.backup_codes.join('\n');
    const blob = new Blob([codes], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'websecpen-backup-codes.txt';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const formatSecret = (secret) => {
    return secret.match(/.{1,4}/g)?.join(' ') || secret;
  };

  return (
    <div className="mfa-setup">
      <div className="mfa-header">
        <h3>🔐 Multi-Factor Authentication</h3>
        <p>Add an extra layer of security to your account</p>
      </div>

      {message && (
        <div className={`mfa-message ${message.includes('successfully') || message.includes('Copied') ? 'success' : 'error'}`}>
          {message}
        </div>
      )}

      {/* MFA Status */}
      {step === 'status' && (
        <div className="mfa-status">
          <div className="status-card">
            <div className="status-info">
              <div className={`status-indicator ${mfaStatus.enabled ? 'enabled' : 'disabled'}`}>
                {mfaStatus.enabled ? '✅' : '❌'}
              </div>
              <div className="status-text">
                <h4>MFA Status: {mfaStatus.enabled ? 'Enabled' : 'Disabled'}</h4>
                <p>
                  {mfaStatus.enabled 
                    ? 'Your account is protected with multi-factor authentication'
                    : 'Enable MFA to secure your account with time-based codes'
                  }
                </p>
                {mfaStatus.setup_time && (
                  <small>Setup: {new Date(mfaStatus.setup_time).toLocaleDateString()}</small>
                )}
              </div>
            </div>
            
            {!mfaStatus.enabled && (
              <div className="status-actions">
                <button
                  onClick={handleSetupMfa}
                  disabled={loading}
                  className="setup-btn"
                >
                  {loading ? 'Setting up...' : '🛡️ Enable MFA'}
                </button>
              </div>
            )}
          </div>

          {!mfaStatus.enabled && (
            <div className="mfa-benefits">
              <h4>Why enable MFA?</h4>
              <ul>
                <li>🔒 <strong>Enhanced Security:</strong> Protect against password breaches</li>
                <li>📱 <strong>Mobile Integration:</strong> Use Google Authenticator, Authy, or similar apps</li>
                <li>🔑 <strong>Backup Codes:</strong> Secure recovery options when your device isn't available</li>
                <li>✅ <strong>Industry Standard:</strong> Recommended by security experts worldwide</li>
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Setup Step */}
      {step === 'setup' && setupData && (
        <div className="mfa-setup-step">
          <div className="setup-header">
            <h4>📱 Setup Your Authenticator App</h4>
            <p>Scan the QR code or enter the secret key manually</p>
          </div>

          <div className="setup-content">
            <div className="qr-section">
              <h5>1. Scan QR Code</h5>
              <div className="qr-container">
                <QRCode 
                  value={setupData.qr_uri}
                  size={200}
                  level="M"
                  includeMargin={true}
                />
              </div>
              <p className="qr-instructions">
                Open your authenticator app and scan this QR code
              </p>
            </div>

            <div className="manual-section">
              <h5>2. Or Enter Manually</h5>
              <div className="secret-display">
                <label>Secret Key:</label>
                <div className="secret-input">
                  <code>{formatSecret(setupData.secret)}</code>
                  <button
                    onClick={() => copyToClipboard(setupData.secret)}
                    className="copy-btn"
                    title="Copy secret key"
                  >
                    📋
                  </button>
                </div>
              </div>
              <p className="manual-instructions">
                Enter this key in your authenticator app if you can't scan the QR code
              </p>
            </div>
          </div>

          <div className="setup-actions">
            <button
              onClick={() => setStep('verify')}
              className="continue-btn"
            >
              Continue to Verification
            </button>
          </div>
        </div>
      )}

      {/* Verification Step */}
      {step === 'verify' && (
        <div className="mfa-verify-step">
          <div className="verify-header">
            <h4>🔢 Verify Your Setup</h4>
            <p>Enter the 6-digit code from your authenticator app</p>
          </div>

          <form onSubmit={handleVerifyMfa} className="verify-form">
            <div className="code-input-group">
              <label htmlFor="verification-code">Verification Code</label>
              <input
                id="verification-code"
                type="text"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                disabled={loading}
                maxLength={6}
                autoComplete="one-time-code"
                className="code-input"
              />
              <small>Enter the 6-digit code shown in your authenticator app</small>
            </div>

            <div className="verify-actions">
              <button
                type="button"
                onClick={() => setStep('setup')}
                className="back-btn"
                disabled={loading}
              >
                ← Back
              </button>
              <button
                type="submit"
                disabled={loading || verificationCode.length !== 6}
                className="verify-btn"
              >
                {loading ? 'Verifying...' : 'Verify & Enable MFA'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Complete Step */}
      {step === 'complete' && setupData && (
        <div className="mfa-complete-step">
          <div className="complete-header">
            <h4>✅ MFA Successfully Enabled!</h4>
            <p>Your account is now protected with multi-factor authentication</p>
          </div>

          {showBackupCodes && setupData.backup_codes && (
            <div className="backup-codes-section">
              <h5>🔑 Save Your Backup Codes</h5>
              <p className="backup-warning">
                <strong>Important:</strong> Save these backup codes in a secure location. 
                You can use them to access your account if you lose your authenticator device.
              </p>
              
              <div className="backup-codes-container">
                <div className="backup-codes-grid">
                  {setupData.backup_codes.map((code, index) => (
                    <div key={index} className="backup-code">
                      <code>{code}</code>
                    </div>
                  ))}
                </div>
              </div>

              <div className="backup-actions">
                <button
                  onClick={downloadBackupCodes}
                  className="download-btn"
                >
                  💾 Download Codes
                </button>
                <button
                  onClick={() => copyToClipboard(setupData.backup_codes.join('\n'))}
                  className="copy-all-btn"
                >
                  📋 Copy All
                </button>
              </div>
            </div>
          )}

          <div className="complete-actions">
            <button
              onClick={() => {
                setStep('status');
                setSetupData(null);
                setVerificationCode('');
                setShowBackupCodes(false);
              }}
              className="done-btn"
            >
              Done
            </button>
          </div>
        </div>
      )}

      {/* Supported Apps */}
      <div className="supported-apps">
        <h4>📱 Supported Authenticator Apps</h4>
        <div className="apps-grid">
          <div className="app-item">
            <span className="app-name">Google Authenticator</span>
            <small>Free • iOS & Android</small>
          </div>
          <div className="app-item">
            <span className="app-name">Authy</span>
            <small>Free • Multi-device sync</small>
          </div>
          <div className="app-item">
            <span className="app-name">Microsoft Authenticator</span>
            <small>Free • Push notifications</small>
          </div>
          <div className="app-item">
            <span className="app-name">1Password</span>
            <small>Premium • Password manager</small>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MfaSetup; 