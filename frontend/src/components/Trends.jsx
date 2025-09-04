import { useEffect, useState } from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { useTranslation } from 'react-i18next';
import './Trends.css';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const Trends = () => {
  const { t } = useTranslation();
  const [chartData, setChartData] = useState({ labels: [], datasets: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [timeRange, setTimeRange] = useState(30);

  const colors = [
    { border: '#dc3545', background: 'rgba(220, 53, 69, 0.2)' },
    { border: '#007bff', background: 'rgba(0, 123, 255, 0.2)' },
    { border: '#28a745', background: 'rgba(40, 167, 69, 0.2)' },
    { border: '#ffc107', background: 'rgba(255, 193, 7, 0.2)' },
    { border: '#6f42c1', background: 'rgba(111, 66, 193, 0.2)' },
    { border: '#fd7e14', background: 'rgba(253, 126, 20, 0.2)' },
  ];

  const fetchTrends = async () => {
    setLoading(true);
    setError('');
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/scan/trends?days=${timeRange}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch trends');
      }

      const data = await response.json();
      
      // Get all unique dates and sort them
      const allDates = new Set();
      Object.values(data).forEach(vulnData => {
        vulnData.forEach(point => allDates.add(point.date));
      });
      const labels = Array.from(allDates).sort();

      // Create datasets for each vulnerability type
      const datasets = Object.keys(data).map((vulnType, index) => {
        const color = colors[index % colors.length];
        const vulnData = data[vulnType];
        
        // Map data to labels, filling missing dates with 0
        const dataPoints = labels.map(date => {
          const point = vulnData.find(d => d.date === date);
          return point ? point.count : 0;
        });

        return {
          label: vulnType,
          data: dataPoints,
          borderColor: color.border,
          backgroundColor: color.background,
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointHoverRadius: 6,
        };
      });

      setChartData({ labels, datasets });
      
    } catch (err) {
      setError(err.message || 'Failed to fetch trends');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format = 'csv') => {
    setLoading(true);
    try {
      const endpoint = format === 'json' ? '/api/scan/trends/export/json' : '/api/scan/trends/export';
      const response = await fetch(`${endpoint}?days=${timeRange}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to export trends');
      }

      // Create download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `vulnerability_trends_${timeRange}days.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
    } catch (err) {
      setError(err.message || 'Failed to export trends');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrends();
  }, [timeRange]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          usePointStyle: true,
          padding: 20,
        },
      },
      title: {
        display: true,
        text: `Vulnerability Trends (Last ${timeRange} days)`,
        font: { size: 16, weight: 'bold' },
        padding: 20,
      },
      tooltip: {
        mode: 'index',
        intersect: false,
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: '#fff',
        bodyColor: '#fff',
        borderColor: '#333',
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        title: {
          display: true,
          text: 'Date',
          font: { weight: 'bold' },
        },
        grid: {
          color: 'rgba(0, 0, 0, 0.1)',
        },
      },
      y: {
        title: {
          display: true,
          text: 'Number of Vulnerabilities',
          font: { weight: 'bold' },
        },
        beginAtZero: true,
        grid: {
          color: 'rgba(0, 0, 0, 0.1)',
        },
      },
    },
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false,
    },
  };

  const totalVulnerabilities = chartData.datasets.reduce((sum, dataset) => {
    return sum + dataset.data.reduce((dataSum, value) => dataSum + value, 0);
  }, 0);

  if (loading) {
    return (
      <div className="trends-container">
        <div className="trends-loading">
          <div className="loading-spinner"></div>
          <p>Loading vulnerability trends...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="trends-container">
        <div className="trends-error">
          <p>Error: {error}</p>
          <button onClick={fetchTrends} className="retry-btn">
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="trends-container">
      <div className="trends-header">
        <h2>📊 Vulnerability Trends</h2>
        <div className="trends-controls">
          <select 
            value={timeRange} 
            onChange={(e) => setTimeRange(Number(e.target.value))}
            className="time-range-select"
          >
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
            <option value={365}>Last year</option>
          </select>
          
          <div className="export-controls">
            <button 
              className="export-btn"
              onClick={() => handleExport('csv')}
              disabled={loading || chartData.datasets.length === 0}
              title="Export as CSV"
            >
              📊 CSV
            </button>
            <button 
              className="export-btn"
              onClick={() => handleExport('json')}
              disabled={loading || chartData.datasets.length === 0}
              title="Export as JSON"
            >
              📄 JSON
            </button>
          </div>
        </div>
      </div>

      <div className="trends-stats">
        <div className="stat-card">
          <div className="stat-value">{totalVulnerabilities}</div>
          <div className="stat-label">Total Vulnerabilities</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{chartData.datasets.length}</div>
          <div className="stat-label">Vulnerability Types</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{chartData.labels.length}</div>
          <div className="stat-label">Days Analyzed</div>
        </div>
      </div>

      <div className="trends-chart">
        {chartData.datasets.length > 0 ? (
          <Line data={chartData} options={chartOptions} />
        ) : (
          <div className="no-data">
            <p>No vulnerability data available for the selected time range.</p>
            <p>Run some scans to see trends here!</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Trends;
