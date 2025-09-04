import React, { useState, useEffect } from 'react';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
} from 'chart.js';
import './VulnTrends.css';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

const VulnTrends = () => {
  const [trends, setTrends] = useState({
    dates: [],
    vulnerability_trends: [],
    severity_trends: [],
    total_scans: 0,
    date_range: { days: 30 }
  });
  const [severityData, setSeverityData] = useState({
    labels: [],
    data: [],
    breakdown_percentages: {}
  });
  const [loading, setLoading] = useState(false);
  const [selectedDays, setSelectedDays] = useState(30);
  const [activeTab, setActiveTab] = useState('trends');

  useEffect(() => {
    fetchTrends();
    fetchSeverityBreakdown();
  }, [selectedDays]);

  const fetchTrends = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/scan/trends?days=${selectedDays}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setTrends(data);
      }
    } catch (error) {
      console.error('Error fetching trends:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchSeverityBreakdown = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/scan/severity', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setSeverityData(data);
      }
    } catch (error) {
      console.error('Error fetching severity data:', error);
    }
  };

  const vulnerabilityTrendChartData = {
    labels: trends.dates,
    datasets: trends.vulnerability_trends.map((trend, index) => ({
      label: trend.label,
      data: trend.data,
      borderColor: getColor(index),
      backgroundColor: getColor(index, 0.1),
      borderWidth: 2,
      fill: false,
      tension: 0.4
    }))
  };

  const severityTrendChartData = {
    labels: trends.dates,
    datasets: trends.severity_trends.map((trend, index) => ({
      label: trend.label,
      data: trend.data,
      borderColor: getSeverityColor(trend.label),
      backgroundColor: getSeverityColor(trend.label, 0.1),
      borderWidth: 3,
      fill: true,
      tension: 0.4
    }))
  };

  const severityBreakdownChartData = {
    labels: severityData.labels,
    datasets: [
      {
        data: severityData.data,
        backgroundColor: severityData.labels.map(label => getSeverityColor(label)),
        borderColor: severityData.labels.map(label => getSeverityColor(label)),
        borderWidth: 2,
        hoverBorderWidth: 3
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          usePointStyle: true,
          padding: 20
        }
      },
      tooltip: {
        mode: 'index',
        intersect: false,
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: 'white',
        bodyColor: 'white',
        borderColor: 'rgba(255, 255, 255, 0.2)',
        borderWidth: 1
      }
    },
    scales: {
      x: {
        display: true,
        title: {
          display: true,
          text: 'Date'
        },
        grid: {
          display: true,
          color: 'rgba(0, 0, 0, 0.1)'
        }
      },
      y: {
        display: true,
        title: {
          display: true,
          text: 'Number of Vulnerabilities'
        },
        beginAtZero: true,
        grid: {
          display: true,
          color: 'rgba(0, 0, 0, 0.1)'
        }
      }
    },
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false
    }
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          usePointStyle: true,
          padding: 20,
          generateLabels: (chart) => {
            const data = chart.data;
            if (data.labels.length && data.datasets.length) {
              return data.labels.map((label, i) => ({
                text: `${label}: ${severityData.breakdown_percentages[label] || 0}%`,
                fillStyle: data.datasets[0].backgroundColor[i],
                strokeStyle: data.datasets[0].borderColor[i],
                lineWidth: data.datasets[0].borderWidth,
                index: i
              }));
            }
            return [];
          }
        }
      },
      tooltip: {
        callbacks: {
          label: (context) => {
            const label = context.label || '';
            const value = context.parsed || 0;
            const percentage = severityData.breakdown_percentages[label] || 0;
            return `${label}: ${value} (${percentage}%)`;
          }
        }
      }
    }
  };

  function getColor(index, alpha = 1) {
    const colors = [
      `rgba(54, 162, 235, ${alpha})`,   // Blue
      `rgba(255, 99, 132, ${alpha})`,   // Red
      `rgba(255, 205, 86, ${alpha})`,   // Yellow
      `rgba(75, 192, 192, ${alpha})`,   // Teal
      `rgba(153, 102, 255, ${alpha})`,  // Purple
      `rgba(255, 159, 64, ${alpha})`,   // Orange
      `rgba(199, 199, 199, ${alpha})`,  // Grey
      `rgba(83, 102, 255, ${alpha})`,   // Indigo
      `rgba(255, 99, 255, ${alpha})`,   // Pink
      `rgba(99, 255, 132, ${alpha})`    // Green
    ];
    return colors[index % colors.length];
  }

  function getSeverityColor(severity, alpha = 1) {
    const colorMap = {
      'High': `rgba(220, 53, 69, ${alpha})`,        // Red
      'Medium': `rgba(255, 193, 7, ${alpha})`,      // Orange
      'Low': `rgba(40, 167, 69, ${alpha})`,         // Green
      'Informational': `rgba(108, 117, 125, ${alpha})` // Gray
    };
    return colorMap[severity] || `rgba(108, 117, 125, ${alpha})`;
  }

  const dayOptions = [
    { value: 7, label: '7 Days' },
    { value: 30, label: '30 Days' },
    { value: 90, label: '90 Days' },
    { value: 180, label: '6 Months' },
    { value: 365, label: '1 Year' }
  ];

  return (
    <div className="vuln-trends">
      <div className="trends-header">
        <h3>📈 Vulnerability Trends Analysis</h3>
        <div className="controls">
          <select
            value={selectedDays}
            onChange={(e) => setSelectedDays(Number(e.target.value))}
            className="time-range-select"
          >
            {dayOptions.map(option => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <button onClick={fetchTrends} className="refresh-btn">
            🔄 Refresh
          </button>
        </div>
      </div>

      <div className="trends-tabs">
        <button
          className={`tab-btn ${activeTab === 'trends' ? 'active' : ''}`}
          onClick={() => setActiveTab('trends')}
        >
          📊 Vulnerability Trends
        </button>
        <button
          className={`tab-btn ${activeTab === 'severity' ? 'active' : ''}`}
          onClick={() => setActiveTab('severity')}
        >
          🚨 Severity Analysis
        </button>
        <button
          className={`tab-btn ${activeTab === 'breakdown' ? 'active' : ''}`}
          onClick={() => setActiveTab('breakdown')}
        >
          🥧 Severity Breakdown
        </button>
      </div>

      {loading ? (
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading trends...</p>
        </div>
      ) : (
        <>
          {/* Summary Stats */}
          <div className="trends-summary">
            <div className="summary-card">
              <h4>Total Scans</h4>
              <div className="summary-number">{trends.total_scans}</div>
            </div>
            <div className="summary-card">
              <h4>Total Vulnerabilities</h4>
              <div className="summary-number">{severityData.total_vulnerabilities || 0}</div>
            </div>
            <div className="summary-card">
              <h4>High Severity</h4>
              <div className="summary-number high-severity">
                {severityData.data[severityData.labels.indexOf('High')] || 0}
              </div>
            </div>
            <div className="summary-card">
              <h4>Time Period</h4>
              <div className="summary-number">{selectedDays} days</div>
            </div>
          </div>

          {/* Chart Content */}
          <div className="chart-content">
            {activeTab === 'trends' && (
              <div className="chart-container">
                <h4>Vulnerability Types Over Time</h4>
                {trends.vulnerability_trends.length > 0 ? (
                  <div className="chart-wrapper">
                    <Line data={vulnerabilityTrendChartData} options={chartOptions} />
                  </div>
                ) : (
                  <div className="no-data">
                    <p>No vulnerability trend data available for the selected time period.</p>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'severity' && (
              <div className="chart-container">
                <h4>Severity Trends Over Time</h4>
                {trends.severity_trends.length > 0 ? (
                  <div className="chart-wrapper">
                    <Line data={severityTrendChartData} options={chartOptions} />
                  </div>
                ) : (
                  <div className="no-data">
                    <p>No severity trend data available for the selected time period.</p>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'breakdown' && (
              <div className="chart-container">
                <h4>Overall Severity Distribution</h4>
                {severityData.data.length > 0 ? (
                  <div className="chart-wrapper doughnut-wrapper">
                    <Doughnut data={severityBreakdownChartData} options={doughnutOptions} />
                  </div>
                ) : (
                  <div className="no-data">
                    <p>No severity data available.</p>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Detailed Breakdown */}
          {activeTab === 'breakdown' && severityData.data.length > 0 && (
            <div className="severity-details">
              <h4>Detailed Breakdown</h4>
              <div className="severity-grid">
                {severityData.labels.map((label, index) => (
                  <div key={label} className="severity-item">
                    <div 
                      className="severity-color" 
                      style={{ backgroundColor: getSeverityColor(label) }}
                    ></div>
                    <div className="severity-info">
                      <span className="severity-name">{label}</span>
                      <span className="severity-count">{severityData.data[index]} vulnerabilities</span>
                      <span className="severity-percentage">
                        {severityData.breakdown_percentages[label] || 0}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Insights */}
      <div className="trends-insights">
        <h4>💡 Insights</h4>
        <div className="insights-list">
          {trends.total_scans === 0 ? (
            <p>Run some scans to see trend analysis and insights.</p>
          ) : (
            <>
              <div className="insight-item">
                <strong>Scan Activity:</strong> You've performed {trends.total_scans} scans in the last {selectedDays} days.
              </div>
              {severityData.total_vulnerabilities > 0 && (
                <div className="insight-item">
                  <strong>Security Status:</strong> 
                  {severityData.breakdown_percentages.High > 50 ? (
                    <span className="status-critical"> High priority - many critical vulnerabilities found</span>
                  ) : severityData.breakdown_percentages.High > 20 ? (
                    <span className="status-warning"> Moderate priority - some high-severity issues detected</span>
                  ) : (
                    <span className="status-good"> Good security posture - mostly low-severity findings</span>
                  )}
                </div>
              )}
              <div className="insight-item">
                <strong>Recommendation:</strong> 
                {trends.total_scans < 5 ? (
                  ' Consider running more regular scans to establish better trend analysis.'
                ) : (
                  ' Continue regular scanning to monitor security improvements over time.'
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default VulnTrends; 