import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import './Upgrade.css';

const Upgrade = () => {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleUpgrade = async () => {
    setLoading(true);
    setError('');
    
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/subscription/create-checkout', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to create checkout session');
      }

      const data = await response.json();
      window.location.href = data.checkout_url;
      
    } catch (err) {
      setError(err.message || 'Failed to initiate checkout');
      setLoading(false);
    }
  };

  return (
    <div className="upgrade-container">
      <div className="upgrade-card">
        <div className="upgrade-header">
          <h2>🚀 Upgrade to Premium</h2>
          <p>Unlock unlimited scans and advanced features</p>
        </div>
        
        <div className="upgrade-features">
          <div className="feature">
            <span className="feature-icon">🔍</span>
            <span>Unlimited security scans</span>
          </div>
          <div className="feature">
            <span className="feature-icon">📊</span>
            <span>Advanced vulnerability trends</span>
          </div>
          <div className="feature">
            <span className="feature-icon">🎯</span>
            <span>Priority support</span>
          </div>
          <div className="feature">
            <span className="feature-icon">🔗</span>
            <span>API access for CI/CD</span>
          </div>
          <div className="feature">
            <span className="feature-icon">📈</span>
            <span>Detailed reporting</span>
          </div>
        </div>
        
        <div className="upgrade-pricing">
          <div className="price">
            <span className="currency">$</span>
            <span className="amount">29</span>
            <span className="period">/month</span>
          </div>
        </div>
        
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}
        
        <button 
          className="upgrade-btn" 
          onClick={handleUpgrade} 
          disabled={loading}
        >
          {loading ? (
            <>
              <span className="loading-spinner"></span>
              Processing...
            </>
          ) : (
            'Upgrade Now'
          )}
        </button>
        
        <p className="upgrade-note">
          Cancel anytime. Secure payment processed by Stripe.
        </p>
      </div>
    </div>
  );
};

export default Upgrade;
