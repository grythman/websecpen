// src/components/ScanHistory.jsx
import React from 'react';

// Mock data
const mockScans = [
  { id: 1, url: 'example.com', date: '2025-07-26', status: 'Completed' },
  { id: 2, url: 'test.com', date: '2025-07-25', status: 'Failed' },
];

const ScanHistory = () => {
  return (
    <div>
      <h2>Scan History</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>URL</th>
            <th>Date</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {mockScans.map(scan => (
            <tr key={scan.id}>
              <td>{scan.id}</td>
              <td>{scan.url}</td>
              <td>{scan.date}</td>
              <td>{scan.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ScanHistory; 