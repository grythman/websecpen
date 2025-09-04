import React, { useState, useEffect } from 'react';
import './Referral.css';

const Referral = () => {
  const [email, setEmail] = useState('');
  const [referralCode, setReferralCode] = useState('');
  const [shareUrl, setShareUrl] = useState('');
  const [referrals, setReferrals] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetchReferrals();
  }, []);

  const fetchReferrals = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/referral/list', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setReferrals(data);
      }
    } catch (error) {
      console.error('Error fetching referrals:', error);
    }
  };

  const handleCreateReferral = async (e) => {
    e.preventDefault();
    if (!email) return;

    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/referral/create', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });

      const data = await response.json();

      if (response.ok) {
        setReferralCode(data.referral_code);
        setShareUrl(data.share_url);
        setMessage('Referral link created successfully!');
        setEmail('');
        fetchReferrals(); // Refresh the list
      } else {
        setMessage(data.error || 'Failed to create referral');
      }
    } catch (error) {
      setMessage('Error creating referral');
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setMessage('Link copied to clipboard!');
      setTimeout(() => setMessage(''), 3000);
    });
  };

  const getTotalRewards = () => {
    return referrals.filter(r => r.redeemed && r.reward_granted).length * 5;
  };

  return (
    <div className="referral-container">
      <div className="referral-header">
        <h2>🎁 Refer Friends & Earn Rewards</h2>
        <p>Get 5 extra scans for each friend who joins!</p>
      </div>

      <div className="referral-stats">
        <div className="stat-item">
          <span className="stat-number">{referrals.length}</span>
          <span className="stat-label">Referrals Sent</span>
        </div>
        <div className="stat-item">
          <span className="stat-number">{referrals.filter(r => r.redeemed).length}</span>
          <span className="stat-label">Successfully Redeemed</span>
        </div>
        <div className="stat-item">
          <span className="stat-number">{getTotalRewards()}</span>
          <span className="stat-label">Extra Scans Earned</span>
        </div>
      </div>

      <div className="referral-form">
        <h3>Create New Referral</h3>
        <form onSubmit={handleCreateReferral}>
          <div className="form-group">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Friend's email address"
              required
              disabled={loading}
            />
            <button type="submit" disabled={loading || !email}>
              {loading ? 'Creating...' : 'Generate Referral Link'}
            </button>
          </div>
        </form>

        {message && (
          <div className={`message ${message.includes('Error') || message.includes('Failed') ? 'error' : 'success'}`}>
            {message}
          </div>
        )}

        {shareUrl && (
          <div className="share-link">
            <h4>Share this link:</h4>
            <div className="link-container">
              <input type="text" value={shareUrl} readOnly />
              <button onClick={() => copyToClipboard(shareUrl)}>
                📋 Copy
              </button>
            </div>
            <div className="share-buttons">
              <a
                href={`mailto:?subject=Join WebSecPen Security Scanner&body=I thought you might be interested in this security scanning tool: ${shareUrl}`}
                className="share-btn email"
              >
                📧 Email
              </a>
              <a
                href={`https://twitter.com/intent/tweet?text=Check out this security scanner&url=${encodeURIComponent(shareUrl)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="share-btn twitter"
              >
                🐦 Twitter
              </a>
            </div>
          </div>
        )}
      </div>

      <div className="referral-list">
        <h3>Your Referrals</h3>
        {referrals.length === 0 ? (
          <p className="empty-state">No referrals yet. Start by inviting a friend!</p>
        ) : (
          <div className="referrals-table">
            <table>
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Code</th>
                  <th>Status</th>
                  <th>Date Created</th>
                  <th>Reward</th>
                </tr>
              </thead>
              <tbody>
                {referrals.map((referral) => (
                  <tr key={referral.id}>
                    <td>{referral.referee_email}</td>
                    <td>
                      <code>{referral.code}</code>
                    </td>
                    <td>
                      <span className={`status ${referral.redeemed ? 'redeemed' : 'pending'}`}>
                        {referral.redeemed ? '✅ Redeemed' : '⏳ Pending'}
                      </span>
                    </td>
                    <td>{new Date(referral.created_at).toLocaleDateString()}</td>
                    <td>
                      {referral.redeemed && referral.reward_granted ? (
                        <span className="reward">+{referral.reward_amount} scans</span>
                      ) : (
                        <span className="no-reward">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Referral; 