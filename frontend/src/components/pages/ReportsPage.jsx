import React, { useEffect, useState } from 'react';
import Section from '../ui/Section.jsx';
import Skeleton from '../ui/Skeleton.jsx';
import ReportTemplate from '../ReportTemplate.jsx';
import ReportTemplateManager from '../ReportTemplateManager.jsx';

const ReportsPage = () => {
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 300);
    return () => clearTimeout(t);
  }, []);

  return (
    <div className="container stack">
      <h2>Reports</h2>
      <Section title="Templates">
        {loading ? <Skeleton height={260} /> : <ReportTemplate />}
      </Section>
      <Section title="Template Manager">
        {loading ? <Skeleton height={320} /> : <ReportTemplateManager />}
      </Section>
    </div>
  );
};

export default ReportsPage; 
