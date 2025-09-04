import React, { useState, useEffect } from 'react';
import { Chart as ChartJS, ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';
import './AdminFeedback.css';

ChartJS.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const AdminFeedback = () => {
  const [feedback, setFeedback] = useState([]);
  const [statistics, setStatistics] = useState({
    total: 0,
    average_rating: 0,
    rating_distribution: {},
    type_distribution: {}
  });
  const [loading, setLoading] = useState(false);
  const [selectedFeedback, setSelectedFeedback] = useState(null);
  const [filterType, setFilterType] = useState('all');
  const [sortBy, setSortBy] = useState('newest');

  useEffect(() => {
    fetchFeedback();
  }, []);

  const fetchFeedback = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/admin/feedback', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setFeedback(data.feedback || []);
        setStatistics(data.statistics || {});
      }
    } catch (error) {
      console.error('Error fetching feedback:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExportCSV = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/admin/feedback/export', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', 'feedback_export.csv');
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Error exporting feedback:', error);
    }
  };

  const filteredFeedback = feedback.filter(item => {
    if (filterType === 'all') return true;
    return item.type === filterType;
  });

  const sortedFeedback = [...filteredFeedback].sort((a, b) => {
    switch (sortBy) {
      case 'newest':
        return new Date(b.created_at) - new Date(a.created_at);
      case 'oldest':
        return new Date(a.created_at) - new Date(b.created_at);
      case 'highest_rating':
        return b.rating - a.rating;
      case 'lowest_rating':
        return a.rating - b.rating;
      default:
        return 0;
    }
  });

  const getRatingStars = (rating) => {
    return '★'.repeat(rating) + '☆'.repeat(5 - rating);
  };

  const getTypeIcon = (type) => {
    const icons = {
      general: '💬',
      bug: '🐛',
      feature: '✨'
    };
    return icons[type] || '💬';
  };

  const ratingChartData = {
    labels: ['1 Star', '2 Stars', '3 Stars', '4 Stars', '5 Stars'],
    datasets: [
      {
        data: [
          statistics.rating_distribution?.[1] || 0,
          statistics.rating_distribution?.[2] || 0,
          statistics.rating_distribution?.[3] || 0,
          statistics.rating_distribution?.[4] || 0,
          statistics.rating_distribution?.[5] || 0
        ],
        backgroundColor: [
          '#e74c3c',
          '#f39c12',
          '#f1c40f',
          '#2ecc71',
          '#27ae60'
        ],
        borderWidth: 2,
        borderColor: '#fff'
      }
    ]
  };

  const typeChartData = {
    labels: Object.keys(statistics.type_distribution || {}),
    datasets: [
      {
        label: 'Feedback Count',
        data: Object.values(statistics.type_distribution || {}),
        backgroundColor: [
          '#3498db',
          '#e74c3c',
          '#f39c12'
        ],
        borderColor: [
          '#2980b9',
          '#c0392b',
          '#e67e22'
        ],
        borderWidth: 1
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom'
      }
    }
  };

  return (
    <div className="admin-feedback">
      <div className="feedback-header">
        <h2>📝 User Feedback Dashboard</h2>
        <div className="header-actions">
          <button onClick={handleExportCSV} className="export-button">
            📊 Export CSV
          </button>
          <button onClick={fetchFeedback} className="refresh-button">
            🔄 Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading feedback...</p>
        </div>
      ) : (
        <>
          {/* Statistics Overview */}
          <div className="statistics-overview">
            <div className="stat-card">
              <h3>Total Feedback</h3>
              <div className="stat-number">{statistics.total}</div>
            </div>
            <div className="stat-card">
              <h3>Average Rating</h3>
              <div className="stat-number">{statistics.average_rating}/5</div>
              <div className="stat-stars">{getRatingStars(Math.round(statistics.average_rating))}</div>
            </div>
            <div className="stat-card">
              <h3>This Month</h3>
              <div className="stat-number">{feedback.filter(f => 
                new Date(f.created_at) > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
              ).length}</div>
            </div>
          </div>

          {/* Charts */}
          <div className="charts-container">
            <div className="chart-card">
              <h3>Rating Distribution</h3>
              <div className="chart-wrapper">
                <Doughnut data={ratingChartData} options={chartOptions} />
              </div>
            </div>
            <div className="chart-card">
              <h3>Feedback Types</h3>
              <div className="chart-wrapper">
                <Bar data={typeChartData} options={chartOptions} />
              </div>
            </div>
          </div>

          {/* Filters and Controls */}
          <div className="feedback-controls">
            <div className="filter-group">
              <label>Filter by Type:</label>
              <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
                <option value="all">All Types</option>
                <option value="general">General</option>
                <option value="bug">Bug Reports</option>
                <option value="feature">Feature Requests</option>
              </select>
            </div>
            <div className="filter-group">
              <label>Sort by:</label>
              <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="highest_rating">Highest Rating</option>
                <option value="lowest_rating">Lowest Rating</option>
              </select>
            </div>
          </div>

          {/* Feedback List */}
          <div className="feedback-list">
            {sortedFeedback.length === 0 ? (
              <div className="no-feedback">
                <p>No feedback found matching the current filters.</p>
              </div>
            ) : (
              sortedFeedback.map((item, index) => (
                <div
                  key={index}
                  className={`feedback-item ${selectedFeedback === index ? 'selected' : ''}`}
                  onClick={() => setSelectedFeedback(selectedFeedback === index ? null : index)}
                >
                  <div className="feedback-summary">
                    <div className="feedback-meta">
                      <span className="feedback-type">
                        {getTypeIcon(item.type)} {item.type}
                      </span>
                      <span className="feedback-rating">
                        {getRatingStars(item.rating)}
                      </span>
                      <span className="feedback-date">
                        {new Date(item.created_at).toLocaleDateString()}
                      </span>
                    </div>
                    <h4 className="feedback-subject">{item.subject}</h4>
                    <p className="feedback-preview">
                      {item.message.length > 100 
                        ? `${item.message.substring(0, 100)}...` 
                        : item.message}
                    </p>
                  </div>
                  
                  {selectedFeedback === index && (
                    <div className="feedback-details">
                      <div className="feedback-full-message">
                        <h5>Full Message:</h5>
                        <p>{item.message}</p>
                      </div>
                      <div className="feedback-actions">
                        <span className="user-id">User ID: {item.user_id}</span>
                        <span className="status">Status: {item.status || 'Open'}</span>
                      </div>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {/* Feedback Insights */}
          <div className="feedback-insights">
            <h3>📊 Insights</h3>
            <div className="insights-grid">
              <div className="insight-card">
                <h4>Most Common Type</h4>
                <p>{Object.entries(statistics.type_distribution || {})
                  .sort(([,a], [,b]) => b - a)[0]?.[0] || 'N/A'}</p>
              </div>
              <div className="insight-card">
                <h4>Satisfaction Rate</h4>
                <p>{Math.round((
                  ((statistics.rating_distribution?.[4] || 0) + (statistics.rating_distribution?.[5] || 0)) / 
                  (statistics.total || 1) * 100
                ))}% (4-5 stars)</p>
              </div>
              <div className="insight-card">
                <h4>Response Needed</h4>
                <p>{feedback.filter(f => f.rating <= 2).length} low-rated feedback</p>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default AdminFeedback; 