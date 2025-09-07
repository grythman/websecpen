import React, { useState } from 'react';
import './FilterBar.css';

const defaultFilters = {
  severity: 'all',
  status: 'all',
  tag: '',
  query: ''
};

const FilterBar = ({ initial = defaultFilters, onChange }) => {
  const [filters, setFilters] = useState(initial);

  const update = (key, value) => {
    const next = { ...filters, [key]: value };
    setFilters(next);
    onChange && onChange(next);
  };

  const clear = () => {
    setFilters(defaultFilters);
    onChange && onChange(defaultFilters);
  };

  return (
    <div className="filterbar card">
      <input
        className="fb-input"
        placeholder="Search vulnerabilities (CWE, target, text)"
        value={filters.query}
        onChange={(e) => update('query', e.target.value)}
      />
      <select className="fb-select" value={filters.severity} onChange={(e) => update('severity', e.target.value)}>
        <option value="all">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select className="fb-select" value={filters.status} onChange={(e) => update('status', e.target.value)}>
        <option value="all">All status</option>
        <option value="open">Open</option>
        <option value="in_progress">In progress</option>
        <option value="resolved">Resolved</option>
      </select>
      <input
        className="fb-input"
        placeholder="Tag"
        value={filters.tag}
        onChange={(e) => update('tag', e.target.value)}
      />
      <button className="fb-btn" onClick={clear}>Clear</button>
    </div>
  );
};

export default FilterBar; 
