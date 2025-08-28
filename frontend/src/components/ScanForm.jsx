// src/components/ScanForm.jsx
import { useState } from 'react';

const ScanForm = () => {
  const [url, setUrl] = useState('');
  const [scanType, setScanType] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!url || !scanType) {
      setError('Please provide URL and scan type');
      return;
    }
    if (!/^https?:\/\/.+/.test(url)) {
      setError('Invalid URL format');
      return;
    }
    // API call placeholder
    console.log('Scan:', { url, scanType });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="Target URL"
      />
      <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
        <option value="">Select Scan Type</option>
        <option value="SQLi">SQLi</option>
        <option value="XSS">XSS</option>
      </select>
      {error && <p>{error}</p>}
      <button type="submit">Start Scan</button>
    </form>
  );
};

export default ScanForm; 