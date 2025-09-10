import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './CommandPalette.css';

const commands = [
  { id: 'dashboard', label: 'Go to Dashboard', path: '/' },
  { id: 'scans', label: 'Go to Scans', path: '/scans' },
  { id: 'vulns', label: 'Go to Vulnerabilities', path: '/vulnerabilities' },
  { id: 'reports', label: 'Go to Reports', path: '/reports' },
  { id: 'team', label: 'Go to Team', path: '/team' },
  { id: 'profile', label: 'Go to Profile', path: '/profile' },
  { id: 'admin', label: 'Go to Admin', path: '/admin' },
];

const CommandPalette = () => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const handleKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, []);

  const filtered = commands.filter(c => c.label.toLowerCase().includes(query.toLowerCase()));

  if (!open) return null;

  return (
    <div className="palette-overlay" onClick={() => setOpen(false)}>
      <div className="palette" onClick={(e) => e.stopPropagation()}>
        <input
          autoFocus
          className="palette-input"
          placeholder="Type a command..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && filtered[0]) {
              navigate(filtered[0].path);
              setOpen(false);
            }
          }}
        />
        <div className="palette-list">
          {filtered.map(c => (
            <button key={c.id} className="palette-item" onClick={() => { navigate(c.path); setOpen(false); }}>
              {c.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default CommandPalette; 