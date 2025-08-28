// src/components/ResultPreview.jsx
import React from 'react';

// Mock data
const mockResult = {
  scan_id: 1,
  vulnerabilities: ['XSS', 'SQLi'],
  severity: 'High',
};

const ResultPreview = () => {
  return (
    <div>
      <h3>Scan Result Preview</h3>
      <p>Scan ID: {mockResult.scan_id}</p>
      <p>Vulnerabilities: {mockResult.vulnerabilities.join(', ')}</p>
      <p>Severity: {mockResult.severity}</p>
      <button>View Full Report</button>
    </div>
  );
};

export default ResultPreview; 