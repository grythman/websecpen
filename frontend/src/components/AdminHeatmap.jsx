import React, { useState, useEffect } from 'react';
import { Chart as ChartJS, CategoryScale, LinearScale, Title, Tooltip, Legend } from 'chart.js';
import './AdminHeatmap.css';

ChartJS.register(CategoryScale, LinearScale, Title, Tooltip, Legend);

const AdminHeatmap = () => {
  const [heatmapData, setHeatmapData] = useState({ days: [], hours: [], data: [] });
  const [endpointAnalytics, setEndpointAnalytics] = useState({ endpoints: [], total_requests: 0 });
  const [loading, setLoading] = useState(false);
  const [selectedDays, setSelectedDays] = useState(7);

  useEffect(() => {
    fetchHeatmapData();
    fetchEndpointAnalytics();
  }, [selectedDays]);

  const fetchHeatmapData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch(`/api/admin/heatmap?days=${selectedDays}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setHeatmapData(data);
      }
    } catch (error) {
      console.error('Error fetching heatmap data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchEndpointAnalytics = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch(`/api/admin/analytics/endpoints?days=${selectedDays}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setEndpointAnalytics(data);
      }
    } catch (error) {
      console.error('Error fetching endpoint analytics:', error);
    }
  };

  const prepareHeatmapChartData = () => {
    const data = [];
    
    heatmapData.days.forEach((day, dayIndex) => {
      heatmapData.hours.forEach((hour) => {
        const value = heatmapData.data[dayIndex] ? heatmapData.data[dayIndex][hour] : 0;
        data.push({
          x: hour,
          y: dayIndex,
          v: value
        });
      });
    });

    return {
      datasets: [{
        label: 'API Requests',
        data: data,
        backgroundColor: function(context) {
          const value = context.parsed.v;
          const max = Math.max(...heatmapData.data.flat());
          const opacity = max > 0 ? value / max : 0;
          return `rgba(52, 152, 219, ${opacity})`;
        },
        borderColor: 'rgba(52, 152, 219, 0.1)',
        borderWidth: 1,
        width: ({chart}) => (chart.chartArea || {}).width / 24,
        height: ({chart}) => (chart.chartArea || {}).height / heatmapData.days.length,
      }]
    };
  };

  const heatmapOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      title: {
        display: true,
        text: `User Activity Heatmap (Last ${selectedDays} Days)`
      },
      tooltip: {
        callbacks: {
          title: function(context) {
            const dayIndex = context[0].parsed.y;
            const hour = context[0].parsed.x;
            return `${heatmapData.days[dayIndex]} at ${hour}:00`;
          },
          label: function(context) {
            return `Requests: ${context.parsed.v}`;
          }
        }
      },
      legend: {
        display: false
      }
    },
    scales: {
      x: {
        type: 'linear',
        position: 'bottom',
        min: 0,
        max: 23,
        ticks: {
          stepSize: 1,
          callback: function(value) {
            return `${value}:00`;
          }
        },
        title: {
          display: true,
          text: 'Hour of Day'
        }
      },
      y: {
        type: 'linear',
        min: 0,
        max: heatmapData.days.length - 1,
        ticks: {
          stepSize: 1,
          callback: function(value) {
            return heatmapData.days[value] || '';
          }
        },
        title: {
          display: true,
          text: 'Date'
        }
      }
    }
  };

  const getActivityLevel = (requests) => {
    if (requests === 0) return 'no-activity';
    if (requests < 10) return 'low-activity';
    if (requests < 50) return 'medium-activity';
    return 'high-activity';
  };

  return (
    <div className="admin-heatmap">
      <div className="heatmap-header">
        <h3>📊 User Activity Analytics</h3>
        <div className="time-selector">
          <label>Time Period:</label>
          <select 
            value={selectedDays} 
            onChange={(e) => setSelectedDays(parseInt(e.target.value))}
          >
            <option value={7}>Last 7 Days</option>
            <option value={14}>Last 14 Days</option>
            <option value={30}>Last 30 Days</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading analytics...</p>
        </div>
      ) : (
        <>
          {/* Activity Heatmap Grid */}
          <div className="heatmap-grid-container">
            <h4>Activity Heatmap</h4>
            <div className="heatmap-grid">
              <div className="hour-labels">
                {Array.from({length: 24}, (_, i) => (
                  <div key={i} className="hour-label">{i}</div>
                ))}
              </div>
              <div className="heatmap-days">
                {heatmapData.days.map((day, dayIndex) => (
                  <div key={day} className="heatmap-day">
                    <div className="day-label">{day}</div>
                    <div className="day-hours">
                      {heatmapData.hours.map((hour) => {
                        const requests = heatmapData.data[dayIndex] ? heatmapData.data[dayIndex][hour] : 0;
                        return (
                          <div
                            key={hour}
                            className={`hour-cell ${getActivityLevel(requests)}`}
                            title={`${day} ${hour}:00 - ${requests} requests`}
                          >
                            {requests > 0 && <span className="request-count">{requests}</span>}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="heatmap-legend">
              <span>Less</span>
              <div className="legend-scale">
                <div className="legend-cell no-activity"></div>
                <div className="legend-cell low-activity"></div>
                <div className="legend-cell medium-activity"></div>
                <div className="legend-cell high-activity"></div>
              </div>
              <span>More</span>
            </div>
          </div>

          {/* Endpoint Analytics */}
          <div className="endpoint-analytics">
            <h4>API Endpoint Usage</h4>
            <div className="analytics-summary">
              <div className="summary-item">
                <span className="summary-number">{endpointAnalytics.total_requests}</span>
                <span className="summary-label">Total Requests</span>
              </div>
              <div className="summary-item">
                <span className="summary-number">{endpointAnalytics.total_errors}</span>
                <span className="summary-label">Total Errors</span>
              </div>
              <div className="summary-item">
                <span className="summary-number">{endpointAnalytics.endpoints.length}</span>
                <span className="summary-label">Active Endpoints</span>
              </div>
            </div>

            <div className="endpoints-table">
              <table>
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Requests</th>
                    <th>Errors</th>
                    <th>Error Rate</th>
                    <th>Usage</th>
                  </tr>
                </thead>
                <tbody>
                  {endpointAnalytics.endpoints.slice(0, 10).map((endpoint, index) => (
                    <tr key={index}>
                      <td>
                        <code>{endpoint.endpoint}</code>
                      </td>
                      <td>{endpoint.requests}</td>
                      <td>{endpoint.errors}</td>
                      <td>
                        <span className={`error-rate ${endpoint.error_rate > 5 ? 'high' : endpoint.error_rate > 1 ? 'medium' : 'low'}`}>
                          {endpoint.error_rate}%
                        </span>
                      </td>
                      <td>
                        <div className="usage-bar">
                          <div 
                            className="usage-fill"
                            style={{
                              width: `${(endpoint.requests / endpointAnalytics.total_requests) * 100}%`
                            }}
                          ></div>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Activity Statistics */}
          <div className="activity-stats">
            <h4>Activity Statistics</h4>
            <div className="stats-grid">
              <div className="stat-card">
                <h5>Peak Activity</h5>
                <p>{getPeakActivity()}</p>
              </div>
              <div className="stat-card">
                <h5>Most Active Day</h5>
                <p>{getMostActiveDay()}</p>
              </div>
              <div className="stat-card">
                <h5>Average Requests/Hour</h5>
                <p>{getAverageRequestsPerHour()}</p>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );

  function getPeakActivity() {
    let maxRequests = 0;
    let peakTime = '';
    
    heatmapData.days.forEach((day, dayIndex) => {
      heatmapData.hours.forEach((hour) => {
        const requests = heatmapData.data[dayIndex] ? heatmapData.data[dayIndex][hour] : 0;
        if (requests > maxRequests) {
          maxRequests = requests;
          peakTime = `${day} ${hour}:00`;
        }
      });
    });
    
    return `${maxRequests} requests at ${peakTime}`;
  }

  function getMostActiveDay() {
    const dayTotals = heatmapData.days.map((day, index) => ({
      day,
      total: heatmapData.data[index] ? heatmapData.data[index].reduce((sum, val) => sum + val, 0) : 0
    }));
    
    const mostActive = dayTotals.reduce((max, current) => 
      current.total > max.total ? current : max, { day: 'None', total: 0 }
    );
    
    return `${mostActive.day} (${mostActive.total} requests)`;
  }

  function getAverageRequestsPerHour() {
    const totalRequests = heatmapData.data.flat().reduce((sum, val) => sum + val, 0);
    const totalHours = heatmapData.days.length * 24;
    
    return totalHours > 0 ? Math.round(totalRequests / totalHours) : 0;
  }
};

export default AdminHeatmap; 