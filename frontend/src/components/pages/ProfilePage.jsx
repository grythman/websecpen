import React, { useEffect, useState } from 'react';
import Section from '../ui/Section.jsx';
import Skeleton from '../ui/Skeleton.jsx';
import Profile from '../Profile.jsx';
import MfaSetup from '../MfaSetup.jsx';
import TwoFactorAuth from '../TwoFactorAuth.jsx';
import NotificationSettings from '../NotificationSettings.jsx';
import NotificationPreferences from '../NotificationPreferences.jsx';
import ApiKeyManager from '../ApiKeyManager.jsx';

const ProfilePage = () => {
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 300);
    return () => clearTimeout(t);
  }, []);

  return (
    <div className="container stack">
      <h2>Profile & Settings</h2>
      <Section title="Account">
        {loading ? <Skeleton height={220} /> : <Profile />}
      </Section>
      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <Section title="MFA Setup">
          {loading ? <Skeleton height={260} /> : <MfaSetup />}
        </Section>
        <Section title="Two-Factor Auth">
          {loading ? <Skeleton height={260} /> : <TwoFactorAuth />}
        </Section>
      </div>
      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <Section title="Notification Settings">
          {loading ? <Skeleton height={220} /> : <NotificationSettings />}
        </Section>
        <Section title="Notification Preferences">
          {loading ? <Skeleton height={220} /> : <NotificationPreferences />}
        </Section>
      </div>
      <Section title="API Keys">
        {loading ? <Skeleton height={220} /> : <ApiKeyManager />}
      </Section>
    </div>
  );
};

export default ProfilePage; 