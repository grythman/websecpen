import React, { useState, useEffect } from 'react';
import './Profile.css';

const Profile = () => {
  const [profile, setProfile] = useState({
    first_name: '',
    last_name: '',
    email: '',
    role: '',
    scan_limit: 0,
    avatar_url: '',
    preferences: {
      notifications: true,
      has_seen_tutorial: false
    }
  });
  const [avatar, setAvatar] = useState(null);
  const [avatarPreview, setAvatarPreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [activeTab, setActiveTab] = useState('profile');

  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/profile', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setProfile(data);
      }
    } catch (error) {
      console.error('Error fetching profile:', error);
    }
  };

  const handleAvatarChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      // Validate file size (max 5MB)
      if (file.size > 5 * 1024 * 1024) {
        setMessage('File size must be less than 5MB');
        return;
      }

      // Validate file type
      const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif'];
      if (!allowedTypes.includes(file.type)) {
        setMessage('Only PNG, JPG, JPEG, and GIF files are allowed');
        return;
      }

      setAvatar(file);
      
      // Create preview
      const reader = new FileReader();
      reader.onload = (e) => {
        setAvatarPreview(e.target.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('auth_token');
      const formData = new FormData();

      // Add avatar if selected
      if (avatar) {
        formData.append('avatar', avatar);
      }

      // Add other profile data
      formData.append('first_name', profile.first_name);
      formData.append('last_name', profile.last_name);
      formData.append('preferences', JSON.stringify(profile.preferences));

      const response = await fetch('/api/profile', {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Profile updated successfully!');
        setProfile(data.profile);
        setAvatar(null);
        setAvatarPreview(null);
      } else {
        setMessage(data.error || 'Failed to update profile');
      }
    } catch (error) {
      setMessage('Error updating profile');
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handlePreferenceChange = (key, value) => {
    setProfile({
      ...profile,
      preferences: {
        ...profile.preferences,
        [key]: value
      }
    });
  };

  const getRoleDisplayName = (role) => {
    const roleNames = {
      'free': 'Free',
      'premium': 'Premium',
      'admin': 'Administrator'
    };
    return roleNames[role] || role;
  };

  const getRoleBadgeClass = (role) => {
    const classes = {
      'free': 'role-badge-free',
      'premium': 'role-badge-premium',
      'admin': 'role-badge-admin'
    };
    return classes[role] || 'role-badge-free';
  };

  return (
    <div className="profile-container">
      <div className="profile-header">
        <h2>👤 My Profile</h2>
        <p>Manage your account settings and preferences</p>
      </div>

      <div className="profile-tabs">
        <button
          className={`tab ${activeTab === 'profile' ? 'active' : ''}`}
          onClick={() => setActiveTab('profile')}
        >
          Profile Info
        </button>
        <button
          className={`tab ${activeTab === 'preferences' ? 'active' : ''}`}
          onClick={() => setActiveTab('preferences')}
        >
          Preferences
        </button>
        <button
          className={`tab ${activeTab === 'account' ? 'active' : ''}`}
          onClick={() => setActiveTab('account')}
        >
          Account Details
        </button>
      </div>

      {message && (
        <div className={`message ${message.includes('Error') || message.includes('Failed') ? 'error' : 'success'}`}>
          {message}
        </div>
      )}

      {activeTab === 'profile' && (
        <div className="profile-form">
          <form onSubmit={handleSubmit}>
            <div className="avatar-section">
              <div className="avatar-display">
                <img
                  src={avatarPreview || profile.avatar_url || '/default-avatar.png'}
                  alt="Profile Avatar"
                  className="avatar-image"
                />
                <div className="avatar-overlay">
                  <label htmlFor="avatar-upload" className="avatar-upload-btn">
                    📷 Change Photo
                  </label>
                  <input
                    id="avatar-upload"
                    type="file"
                    accept="image/*"
                    onChange={handleAvatarChange}
                    style={{ display: 'none' }}
                  />
                </div>
              </div>
              <div className="avatar-info">
                <p>Upload a profile picture</p>
                <small>PNG, JPG, JPEG or GIF. Max size 5MB.</small>
              </div>
            </div>

            <div className="form-grid">
              <div className="form-group">
                <label htmlFor="first_name">First Name</label>
                <input
                  id="first_name"
                  type="text"
                  value={profile.first_name}
                  onChange={(e) => setProfile({...profile, first_name: e.target.value})}
                  placeholder="Enter your first name"
                />
              </div>
              
              <div className="form-group">
                <label htmlFor="last_name">Last Name</label>
                <input
                  id="last_name"
                  type="text"
                  value={profile.last_name}
                  onChange={(e) => setProfile({...profile, last_name: e.target.value})}
                  placeholder="Enter your last name"
                />
              </div>
            </div>

            <div className="form-actions">
              <button type="submit" disabled={loading} className="btn btn-primary">
                {loading ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </form>
        </div>
      )}

      {activeTab === 'preferences' && (
        <div className="preferences-form">
          <h3>Notification Preferences</h3>
          <div className="preference-item">
            <label className="preference-label">
              <input
                type="checkbox"
                checked={profile.preferences?.notifications || false}
                onChange={(e) => handlePreferenceChange('notifications', e.target.checked)}
              />
              <span>Email notifications for scan completion</span>
            </label>
            <p className="preference-description">
              Receive email notifications when your scans are completed
            </p>
          </div>

          <h3>Tutorial Settings</h3>
          <div className="preference-item">
            <label className="preference-label">
              <input
                type="checkbox"
                checked={profile.preferences?.has_seen_tutorial || false}
                onChange={(e) => handlePreferenceChange('has_seen_tutorial', e.target.checked)}
              />
              <span>I have completed the onboarding tutorial</span>
            </label>
            <p className="preference-description">
              Uncheck this to see the tutorial again on your next login
            </p>
          </div>

          <div className="form-actions">
            <button onClick={handleSubmit} disabled={loading} className="btn btn-primary">
              {loading ? 'Saving...' : 'Save Preferences'}
            </button>
          </div>
        </div>
      )}

      {activeTab === 'account' && (
        <div className="account-details">
          <div className="account-info">
            <div className="info-item">
              <span className="info-label">Email Address</span>
              <span className="info-value">{profile.email}</span>
            </div>
            
            <div className="info-item">
              <span className="info-label">Account Type</span>
              <span className={`role-badge ${getRoleBadgeClass(profile.role)}`}>
                {getRoleDisplayName(profile.role)}
              </span>
            </div>
            
            <div className="info-item">
              <span className="info-label">Monthly Scan Limit</span>
              <span className="info-value">{profile.scan_limit} scans</span>
            </div>
            
            <div className="info-item">
              <span className="info-label">Member Since</span>
              <span className="info-value">
                {profile.created_at ? new Date(profile.created_at).toLocaleDateString() : 'Unknown'}
              </span>
            </div>
            
            <div className="info-item">
              <span className="info-label">Last Login</span>
              <span className="info-value">
                {profile.last_login ? new Date(profile.last_login).toLocaleDateString() : 'Never'}
              </span>
            </div>
          </div>

          {profile.role === 'free' && (
            <div className="upgrade-prompt">
              <h3>🚀 Upgrade to Premium</h3>
              <p>Get more scans, priority support, and advanced features!</p>
              <ul>
                <li>✅ 50 scans per month (vs 5 for free)</li>
                <li>✅ Scheduled automated scans</li>
                <li>✅ Priority scanning queue</li>
                <li>✅ Advanced vulnerability reports</li>
                <li>✅ Email support</li>
              </ul>
              <button className="btn btn-premium">
                Upgrade Now
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Profile; 