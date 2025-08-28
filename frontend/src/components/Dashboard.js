// src/components/Dashboard.jsx
import React from 'react';
import { Link, Outlet } from 'react-router-dom';
import './Dashboard.css';

const Dashboard = () => {
  return (
    <div className="dashboard">
      <aside className="sidebar">
        <h3>Menu</h3>
        <nav>
          <ul>
            <li><Link to="/dashboard/scan">New Scan</Link></li>
            <li><Link to="/dashboard/history">Scan History</Link></li>
            <li><Link to="/dashboard/settings">Settings</Link></li>
          </ul>
        </nav>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
};

export default Dashboard; 