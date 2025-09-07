import React, { useEffect, useState } from 'react';
import Section from '../ui/Section.jsx';
import Skeleton from '../ui/Skeleton.jsx';
import TeamAnnotations from '../TeamAnnotations.jsx';
import Chat from '../Chat.jsx';

const TeamPage = () => {
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 300);
    return () => clearTimeout(t);
  }, []);

  return (
    <div className="container stack">
      <h2>Team</h2>
      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', alignItems: 'start' }}>
        <Section title="Annotations">
          {loading ? <Skeleton height={300} /> : <TeamAnnotations />}
        </Section>
        <Section title="Chat">
          {loading ? <Skeleton height={300} /> : <Chat />}
        </Section>
      </div>
    </div>
  );
};

export default TeamPage; 
