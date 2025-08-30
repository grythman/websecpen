// src/components/ScanHistory.jsx
import React, { useState, useContext } from 'react';
import { ThemeContext } from '../ThemeContext.jsx';
import './ScanHistory.css';

// Mock data with more detailed entries
const mockScans = [
  { 
    id: 1, 
    url: 'https://example.com', 
    date: '2025-07-26', 
    status: 'Completed', 
    scanType: 'XSS',
    vulnerabilities: 3,
    severity: 'High'
  },
  { 
    id: 2, 
    url: 'https://test.com', 
    date: '2025-07-25', 
    status: 'Failed', 
    scanType: 'SQLi',
    vulnerabilities: 0,
    severity: 'N/A'
  },
  { 
    id: 3, 
    url: 'https://demo.com', 
    date: '2025-07-24', 
    status: 'Completed', 
    scanType: 'CSRF',
    vulnerabilities: 1,
    severity: 'Medium'
  },
  { 
    id: 4, 
    url: 'https://sample.org', 
    date: '2025-07-23', 
    status: 'Running', 
    scanType: 'XSS',
    vulnerabilities: 0,
    severity: 'N/A'
  },
  { 
    id: 5, 
    url: 'https://website.net', 
    date: '2025-07-22', 
    status: 'Completed', 
    scanType: 'Directory',
    vulnerabilities: 2,
    severity: 'Low'
  }
];

const ScanHistory = () => {
  const [scans, setScans] = useState(mockScans);
  const [sortBy, setSortBy] = useState('date');
  const [sortOrder, setSortOrder] = useState('desc');
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterScanType, setFilterScanType] = useState('all');
  const { theme } = useContext(ThemeContext);

  // Sort and filter scans
  const filteredAndSortedScans = scans
    .filter(scan => {
      if (filterStatus !== 'all' && scan.status !== filterStatus) return false;
      if (filterScanType !== 'all' && scan.scanType !== filterScanType) return false;
      return true;
    })
    .sort((a, b) => {
      let aVal = a[sortBy];
      let bVal = b[sortBy];
      
      if (sortBy === 'date') {
        aVal = new Date(aVal);
        bVal = new Date(bVal);
      }
      
      if (sortOrder === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });

  const getStatusIcon = (status) => {
    switch (status) {
      case 'Completed': return '✅';
      case 'Failed': return '❌';
      case 'Running': return '🔄';
      default: return '❓';
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'High': return 'severity-high';
      case 'Medium': return 'severity-medium';
      case 'Low': return 'severity-low';
      default: return 'severity-none';
    }
  };

  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  const getSortIcon = (field) => {
    if (sortBy !== field) return '↕️';
    return sortOrder === 'asc' ? '↑' : '↓';
  };

  return (
    <div className={`scan-history ${theme}`}>
      {/* Filters and Controls */}
      <div className="history-controls">
        <div className="filters">
          <select 
            value={filterStatus} 
            onChange={(e) => setFilterStatus(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Status</option>
            <option value="Completed">Completed</option>
            <option value="Running">Running</option>
            <option value="Failed">Failed</option>
          </select>

          <select 
            value={filterScanType} 
            onChange={(e) => setFilterScanType(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Types</option>
            <option value="XSS">XSS</option>
            <option value="SQLi">SQLi</option>
            <option value="CSRF">CSRF</option>
            <option value="Directory">Directory</option>
          </select>
        </div>

        <div className="results-count">
          {filteredAndSortedScans.length} scan(s) found
        </div>
      </div>

      {/* Scan History Table */}
      <div className="table-container">
        <table className="history-table">
        <thead>
          <tr>
              <th onClick={() => handleSort('id')} className="sortable">
                ID {getSortIcon('id')}
              </th>
              <th onClick={() => handleSort('url')} className="sortable">
                Target URL {getSortIcon('url')}
              </th>
              <th onClick={() => handleSort('scanType')} className="sortable">
                Type {getSortIcon('scanType')}
              </th>
              <th onClick={() => handleSort('date')} className="sortable">
                Date {getSortIcon('date')}
              </th>
              <th onClick={() => handleSort('status')} className="sortable">
                Status {getSortIcon('status')}
              </th>
              <th onClick={() => handleSort('vulnerabilities')} className="sortable">
                Issues {getSortIcon('vulnerabilities')}
              </th>
              <th onClick={() => handleSort('severity')} className="sortable">
                Severity {getSortIcon('severity')}
              </th>
              <th>Actions</th>
          </tr>
        </thead>
        <tbody>
            {filteredAndSortedScans.map(scan => (
              <tr key={scan.id} className="scan-row">
                <td className="scan-id">#{scan.id}</td>
                <td className="scan-url" title={scan.url}>
                  {scan.url.length > 30 ? `${scan.url.substring(0, 30)}...` : scan.url}
                </td>
                <td className="scan-type">
                  <span className={`type-badge type-${scan.scanType.toLowerCase()}`}>
                    {scan.scanType}
                  </span>
                </td>
                <td className="scan-date">{scan.date}</td>
                <td className="scan-status">
                  <span className={`status-badge status-${scan.status.toLowerCase()}`}>
                    {getStatusIcon(scan.status)} {scan.status}
                  </span>
                </td>
                <td className="scan-vulnerabilities">
                  {scan.vulnerabilities > 0 ? scan.vulnerabilities : '-'}
                </td>
                <td className="scan-severity">
                  {scan.severity !== 'N/A' ? (
                    <span className={`severity-badge ${getSeverityColor(scan.severity)}`}>
                      {scan.severity}
                    </span>
                  ) : (
                    '-'
                  )}
                </td>
                <td className="scan-actions">
                  <button 
                    className="action-button view-btn"
                    disabled={scan.status !== 'Completed'}
                  >
                    👁️ View
                  </button>
                  <button 
                    className="action-button download-btn"
                    disabled={scan.status !== 'Completed'}
                  >
                    ⬇️ Report
                  </button>
                </td>
            </tr>
          ))}
        </tbody>
      </table>

        {filteredAndSortedScans.length === 0 && (
          <div className="no-results">
            <p>No scans match your current filters.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanHistory; 