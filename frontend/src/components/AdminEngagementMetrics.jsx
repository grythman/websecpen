import React, { useEffect, useState } from 'react';
import apiService from '../services/api.js';
import './AdminEngagementMetrics.css';

const AdminEngagementMetrics = () => {
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState({ dates: [], feedback: [], scans: [] });
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const data = await apiService.request('/admin/engagement_metrics');
        setMetrics(data);
      } catch (e) {
        setError('Failed to fetch engagement metrics');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const maxVal = Math.max(1, ...(metrics.feedback || []), ...(metrics.scans || []));

  return (
    <div className="engagement-metrics">
      <div className="em-header">
        <h3>User Engagement (30 days)</h3>
      </div>
      {error && <div className="em-error">{error}</div>}
      {loading ? (
        <div className="em-placeholder">Loading metrics…</div>
      ) : (
        <div className="em-chart">
          {metrics.dates.map((d, idx) => {
            const f = metrics.feedback[idx] || 0;
            const s = metrics.scans[idx] || 0;
            const fHeight = (f / maxVal) * 100;
            const sHeight = (s / maxVal) * 100;
            return (
              <div key={d} className="em-bar-group" title={`${d}: scans ${s}, feedback ${f}`}>
                <div className="em-bar em-bar-scans" style={{ height: `${sHeight}%` }} />
                <div className="em-bar em-bar-feedback" style={{ height: `${fHeight}%` }} />
              </div>
            );
          })}
          <div className="em-legend">
            <span className="em-dot scans" /> Scans
            <span className="em-dot feedback" /> Feedback
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminEngagementMetrics; 