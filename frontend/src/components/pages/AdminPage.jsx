import React, { useEffect, useState } from 'react';
import Section from '../ui/Section.jsx';
import Skeleton from '../ui/Skeleton.jsx';
import EnhancedAdminDashboard from '../EnhancedAdminDashboard.jsx';
import AdminDashboard from '../AdminDashboard.jsx';
import AdminFeedback from '../AdminFeedback.jsx';
import AdminHeatmap from '../AdminHeatmap.jsx';
import VulnerabilityTagManager from '../VulnerabilityTagManager.jsx';
import AdminEngagementMetrics from '../AdminEngagementMetrics.jsx';

const AdminPage = () => {
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 300);
    return () => clearTimeout(t);
  }, []);

  return (
    <div className="container stack">
      <h2>Admin</h2>
      <Section title="Overview">
        {loading ? <Skeleton height={260} /> : <EnhancedAdminDashboard />}
      </Section>
      <Section title="System Dashboard">
        {loading ? <Skeleton height={260} /> : <AdminDashboard />}
      </Section>
      <Section title="Engagement Metrics">
        {loading ? <Skeleton height={220} /> : <AdminEngagementMetrics />}
      </Section>
      <Section title="Feedback">
        {loading ? <Skeleton height={260} /> : <AdminFeedback />}
      </Section>
      <Section title="Usage Heatmap">
        {loading ? <Skeleton height={260} /> : <AdminHeatmap />}
      </Section>
      <Section title="Vulnerability Tags">
        {loading ? <Skeleton height={260} /> : <VulnerabilityTagManager />}
      </Section>
    </div>
  );
};

export default AdminPage; 