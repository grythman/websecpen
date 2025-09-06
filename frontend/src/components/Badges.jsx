import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import './Badges.css';

const Badges = () => {
  const { t } = useTranslation();
  const [badges, setBadges] = useState([]);
  const [availableBadges, setAvailableBadges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const badgeIcons = {
    'First Scan': '🎯',
    '10 Scans': '🔟',
    '50 Scans': '🏆',
    '100 Scans': '💎',
    'Premium User': '👑',
    'Vulnerability Hunter': '🔍',
    'Security Expert': '🛡️',
  };

  const fetchBadges = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      
      // Fetch user badges
      const badgesResponse = await fetch('/api/badges', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!badgesResponse.ok) {
        throw new Error('Failed to fetch badges');
      }

      const userBadges = await badgesResponse.json();
      setBadges(userBadges);

      // Fetch available badges
      const availableResponse = await fetch('/api/badges/available', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (availableResponse.ok) {
        const available = await availableResponse.json();
        setAvailableBadges(available);
      }

    } catch (err) {
      setError(err.message || 'Failed to fetch badges');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBadges();
  }, []);

  const getBadgeIcon = (badgeName) => {
    return badgeIcons[badgeName] || '🏅';
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const isEarnedBadge = (badgeName) => {
    return badges.some(badge => badge.name === badgeName);
  };

  if (loading) {
    return (
      <div className="badges-container">
        <div className="badges-loading">
          <div className="loading-spinner"></div>
          <p>Loading badges...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="badges-container">
        <div className="badges-error">
          <p>Error: {error}</p>
          <button onClick={fetchBadges} className="retry-btn">
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="badges-container">
      <div className="badges-header">
        <h2>🏅 Your Achievements</h2>
        <div className="badges-stats">
          <span className="earned-count">{badges.length}</span>
          <span className="separator">/</span>
          <span className="total-count">{availableBadges.length}</span>
          <span className="label">Badges Earned</span>
        </div>
      </div>

      {badges.length > 0 && (
        <div className="badges-section">
          <h3>🌟 Earned Badges</h3>
          <div className="badges-grid">
            {badges.map((badge, index) => (
              <div key={index} className="badge-card earned">
                <div className="badge-icon">
                  {getBadgeIcon(badge.name)}
                </div>
                <div className="badge-info">
                  <h4>{badge.name}</h4>
                  <p className="badge-description">{badge.description}</p>
                  <p className="badge-date">Earned on {formatDate(badge.awarded_at)}</p>
                </div>
                <div className="badge-checkmark">✓</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {availableBadges.length > 0 && (
        <div className="badges-section">
          <h3>🎯 Available Badges</h3>
          <div className="badges-grid">
            {availableBadges
              .filter(badge => !isEarnedBadge(badge.name))
              .map((badge, index) => (
                <div key={index} className="badge-card available">
                  <div className="badge-icon locked">
                    {getBadgeIcon(badge.name)}
                  </div>
                  <div className="badge-info">
                    <h4>{badge.name}</h4>
                    <p className="badge-description">{badge.description}</p>
                    <p className="badge-hint">Keep scanning to unlock!</p>
                  </div>
                  <div className="badge-lock">🔒</div>
                </div>
              ))}
          </div>
        </div>
      )}

      {badges.length === 0 && availableBadges.length === 0 && (
        <div className="no-badges">
          <div className="no-badges-icon">🏅</div>
          <h3>No badges yet!</h3>
          <p>Start scanning to earn your first badge.</p>
        </div>
      )}

      <div className="badges-progress">
        <div className="progress-header">
          <span>Achievement Progress</span>
          <span>{Math.round((badges.length / Math.max(availableBadges.length, 1)) * 100)}%</span>
        </div>
        <div className="progress-bar">
          <div 
            className="progress-fill" 
            style={{ 
              width: `${(badges.length / Math.max(availableBadges.length, 1)) * 100}%` 
            }}
          ></div>
        </div>
      </div>
    </div>
  );
};

export default Badges;
