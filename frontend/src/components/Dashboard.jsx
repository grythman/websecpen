// src/components/Dashboard.jsx
import React from 'react';
// Placeholder for navigation bar and sections

const Dashboard = () => {
  return (
    <div className="dashboard">
      <nav>
        <ul>
          <li>Dashboard</li>
          <li>Scan History</li>
          <li>Logout</li>
        </ul>
      </nav>
      <section className="scan-form-placeholder">Scan Form Here</section>
      <section className="scan-history-placeholder">Scan History Here</section>
      <section className="result-preview-placeholder">Result Preview Here</section>
    </div>
  );
};

export default Dashboard; 