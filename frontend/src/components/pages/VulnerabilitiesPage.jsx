import React, { useState, useEffect } from 'react';
import FilterBar from '../ui/FilterBar.jsx';
import Section from '../ui/Section.jsx';
import Skeleton from '../ui/Skeleton.jsx';
import VulnTrends from '../VulnTrends.jsx';
import AiVulnerabilityPrioritizer from '../AiVulnerabilityPrioritizer.jsx';

const VulnerabilitiesPage = () => {
  const [filters, setFilters] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 300);
    return () => clearTimeout(t);
  }, []);

  return (
    <div className="container stack">
      <h2>Vulnerabilities</h2>
      <Section>
        <FilterBar onChange={setFilters} />
      </Section>

      <Section title="Trends">
        {loading ? (
          <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <Skeleton height={220} />
            <Skeleton height={220} />
          </div>
        ) : (
          <VulnTrends />
        )}
      </Section>

      <Section title="AI Prioritization">
        {loading ? (
          <Skeleton height={240} />
        ) : (
          <AiVulnerabilityPrioritizer />
        )}
      </Section>
    </div>
  );
};

export default VulnerabilitiesPage;
