import React from 'react';
import './KpiCard.css';

const KpiCard = ({ icon, label, value, delta, tone = 'default' }) => {
  return (
    <div className={`kpi-card tone-${tone}`}>
      <div className="kpi-icon">{icon}</div>
      <div className="kpi-content">
        <div className="kpi-value">{value}</div>
        <div className="kpi-label">{label}</div>
        {delta && <div className={`kpi-delta ${delta.startsWith('-') ? 'negative' : 'positive'}`}>{delta}</div>}
      </div>
    </div>
  );
};

export default KpiCard; 
