import React, { useState, useEffect } from 'react';
import './ScheduleForm.css';

const ScheduleForm = () => {
  const [schedules, setSchedules] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const [formData, setFormData] = useState({
    name: '',
    url: '',
    scan_type: 'spider',
    frequency: 'weekly',
    is_active: true
  });

  useEffect(() => {
    fetchSchedules();
  }, []);

  const fetchSchedules = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/schedule', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setSchedules(data);
      }
    } catch (error) {
      console.error('Error fetching schedules:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('auth_token');
      const url = editingSchedule ? `/api/schedule/${editingSchedule.id}` : '/api/schedule';
      const method = editingSchedule ? 'PUT' : 'POST';

      const response = await fetch(url, {
        method,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
      });

      const data = await response.json();

      if (response.ok) {
        setMessage(editingSchedule ? 'Schedule updated successfully!' : 'Schedule created successfully!');
        setShowForm(false);
        setEditingSchedule(null);
        setFormData({
          name: '',
          url: '',
          scan_type: 'spider',
          frequency: 'weekly',
          is_active: true
        });
        fetchSchedules();
      } else {
        setMessage(data.error || 'Failed to save schedule');
      }
    } catch (error) {
      setMessage('Error saving schedule');
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (schedule) => {
    setEditingSchedule(schedule);
    setFormData({
      name: schedule.name,
      url: schedule.url,
      scan_type: schedule.scan_type,
      frequency: schedule.frequency,
      is_active: schedule.is_active
    });
    setShowForm(true);
  };

  const handleDelete = async (scheduleId) => {
    if (!window.confirm('Are you sure you want to delete this schedule?')) {
      return;
    }

    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch(`/api/schedule/${scheduleId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        setMessage('Schedule deleted successfully!');
        fetchSchedules();
      } else {
        const data = await response.json();
        setMessage(data.error || 'Failed to delete schedule');
      }
    } catch (error) {
      setMessage('Error deleting schedule');
      console.error('Error:', error);
    }
  };

  const toggleSchedule = async (schedule) => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch(`/api/schedule/${schedule.id}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ...schedule,
          is_active: !schedule.is_active
        })
      });

      if (response.ok) {
        fetchSchedules();
      }
    } catch (error) {
      console.error('Error toggling schedule:', error);
    }
  };

  const getNextRunDisplay = (nextRun) => {
    if (!nextRun) return 'Not scheduled';
    const date = new Date(nextRun);
    const now = new Date();
    const diffMs = date - now;
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);

    if (diffDays > 0) {
      return `In ${diffDays} day${diffDays !== 1 ? 's' : ''}`;
    } else if (diffHours > 0) {
      return `In ${diffHours} hour${diffHours !== 1 ? 's' : ''}`;
    } else if (diffMs > 0) {
      return 'Soon';
    } else {
      return 'Overdue';
    }
  };

  const cancelForm = () => {
    setShowForm(false);
    setEditingSchedule(null);
    setFormData({
      name: '',
      url: '',
      scan_type: 'spider',
      frequency: 'weekly',
      is_active: true
    });
    setMessage('');
  };

  return (
    <div className="schedule-container">
      <div className="schedule-header">
        <h2>⏰ Scheduled Scans</h2>
        <p>Automate your security scans to run regularly</p>
        <button 
          className="btn btn-primary"
          onClick={() => setShowForm(true)}
          disabled={showForm}
        >
          + Create New Schedule
        </button>
      </div>

      {message && (
        <div className={`message ${message.includes('Error') || message.includes('Failed') ? 'error' : 'success'}`}>
          {message}
        </div>
      )}

      {showForm && (
        <div className="schedule-form">
          <h3>{editingSchedule ? 'Edit Schedule' : 'Create New Schedule'}</h3>
          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="name">Schedule Name</label>
                <input
                  id="name"
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({...formData, name: e.target.value})}
                  placeholder="e.g., Weekly Main Site Scan"
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="url">Target URL</label>
                <input
                  id="url"
                  type="url"
                  value={formData.url}
                  onChange={(e) => setFormData({...formData, url: e.target.value})}
                  placeholder="https://example.com"
                  required
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="scan_type">Scan Type</label>
                <select
                  id="scan_type"
                  value={formData.scan_type}
                  onChange={(e) => setFormData({...formData, scan_type: e.target.value})}
                >
                  <option value="spider">Spider Scan</option>
                  <option value="active">Active Scan</option>
                  <option value="passive">Passive Scan</option>
                  <option value="baseline">Baseline Scan</option>
                </select>
              </div>
              <div className="form-group">
                <label htmlFor="frequency">Frequency</label>
                <select
                  id="frequency"
                  value={formData.frequency}
                  onChange={(e) => setFormData({...formData, frequency: e.target.value})}
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={formData.is_active}
                  onChange={(e) => setFormData({...formData, is_active: e.target.checked})}
                />
                <span>Active (schedule will run automatically)</span>
              </label>
            </div>

            <div className="form-actions">
              <button type="button" onClick={cancelForm} className="btn btn-secondary">
                Cancel
              </button>
              <button type="submit" disabled={loading} className="btn btn-primary">
                {loading ? 'Saving...' : (editingSchedule ? 'Update Schedule' : 'Create Schedule')}
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="schedules-list">
        <h3>Your Schedules ({schedules.length})</h3>
        {schedules.length === 0 ? (
          <div className="empty-state">
            <p>No scheduled scans yet.</p>
            <p>Create your first schedule to automate your security testing!</p>
          </div>
        ) : (
          <div className="schedules-grid">
            {schedules.map((schedule) => (
              <div key={schedule.id} className={`schedule-card ${!schedule.is_active ? 'inactive' : ''}`}>
                <div className="schedule-header-card">
                  <h4>{schedule.name}</h4>
                  <div className="schedule-status">
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={schedule.is_active}
                        onChange={() => toggleSchedule(schedule)}
                      />
                      <span className="slider"></span>
                    </label>
                  </div>
                </div>

                <div className="schedule-details">
                  <div className="detail-row">
                    <span className="label">URL:</span>
                    <span className="value">{schedule.url}</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Type:</span>
                    <span className="value">{schedule.scan_type}</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Frequency:</span>
                    <span className="value">{schedule.frequency}</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Next Run:</span>
                    <span className="value">{getNextRunDisplay(schedule.next_run)}</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Total Runs:</span>
                    <span className="value">{schedule.run_count || 0}</span>
                  </div>
                </div>

                <div className="schedule-actions">
                  <button
                    onClick={() => handleEdit(schedule)}
                    className="btn btn-outline"
                    disabled={showForm}
                  >
                    ✏️ Edit
                  </button>
                  <button
                    onClick={() => handleDelete(schedule.id)}
                    className="btn btn-danger"
                  >
                    🗑️ Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScheduleForm; 