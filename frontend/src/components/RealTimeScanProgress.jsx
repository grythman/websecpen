import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import './RealTimeScanProgress.css';

const RealTimeScanProgress = ({ scanId, onComplete }) => {
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('starting');
  const [estimatedCompletion, setEstimatedCompletion] = useState(null);
  const [socket, setSocket] = useState(null);
  const [startTime, setStartTime] = useState(new Date());

  useEffect(() => {
    // Initialize socket connection
    const socketConnection = io(process.env.REACT_APP_API_URL || 'http://localhost:5000');
    setSocket(socketConnection);

    // Join scan room for real-time updates
    socketConnection.emit('join_scan', { scan_id: scanId });

    // Listen for progress updates
    socketConnection.on('scan_progress', (data) => {
      if (data.scan_id === scanId) {
        setProgress(data.progress);
        setStatus(data.status);
        setEstimatedCompletion(data.estimated_completion);
        
        if (data.status === 'completed' && onComplete) {
          onComplete(data);
        }
      }
    });

    // Initial progress fetch
    fetchProgress();

    // Poll for progress updates every 5 seconds
    const progressInterval = setInterval(fetchProgress, 5000);

    return () => {
      socketConnection.disconnect();
      clearInterval(progressInterval);
    };
  }, [scanId]);

  const fetchProgress = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch(`/api/scan/${scanId}/progress`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setProgress(data.progress);
        setStatus(data.status);
        setEstimatedCompletion(data.estimated_completion);
      }
    } catch (error) {
      console.error('Error fetching progress:', error);
    }
  };

  const formatElapsedTime = () => {
    const elapsed = Math.floor((new Date() - startTime) / 1000);
    const minutes = Math.floor(elapsed / 60);
    const seconds = elapsed % 60;
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  };

  const formatEstimatedCompletion = () => {
    if (!estimatedCompletion) return 'Calculating...';
    
    const completionTime = new Date(estimatedCompletion);
    const now = new Date();
    const remaining = Math.max(0, Math.floor((completionTime - now) / 1000));
    
    if (remaining === 0) return 'Almost done';
    
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    
    if (minutes > 0) {
      return `~${minutes}m ${seconds}s remaining`;
    } else {
      return `~${seconds}s remaining`;
    }
  };

  const getStatusIcon = () => {
    switch (status) {
      case 'completed':
        return '✅';
      case 'failed':
        return '❌';
      case 'running':
        return '🔄';
      case 'starting':
        return '🚀';
      default:
        return '⏳';
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case 'completed':
        return '#28a745';
      case 'failed':
        return '#dc3545';
      case 'running':
        return '#007bff';
      case 'starting':
        return '#ffc107';
      default:
        return '#6c757d';
    }
  };

  const getProgressColor = () => {
    if (progress >= 90) return '#28a745';
    if (progress >= 50) return '#007bff';
    if (progress >= 25) return '#ffc107';
    return '#dc3545';
  };

  return (
    <div className="realtime-scan-progress">
      <div className="progress-header">
        <h3>
          <span className="status-icon">{getStatusIcon()}</span>
          Scan Progress
        </h3>
        <div className="scan-info">
          <span className="scan-id">Scan #{scanId}</span>
          <span className="elapsed-time">⏱️ {formatElapsedTime()}</span>
        </div>
      </div>

      <div className="progress-container">
        <div className="progress-bar-wrapper">
          <div className="progress-bar-bg">
            <div 
              className="progress-bar-fill"
              style={{
                width: `${progress}%`,
                backgroundColor: getProgressColor(),
                transition: 'width 0.5s ease-in-out'
              }}
            />
          </div>
          <div className="progress-text">
            {progress.toFixed(1)}%
          </div>
        </div>

        <div className="progress-details">
          <div className="detail-item">
            <span className="detail-label">Status:</span>
            <span 
              className="detail-value status-value"
              style={{ color: getStatusColor() }}
            >
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </span>
          </div>
          
          <div className="detail-item">
            <span className="detail-label">Estimated Completion:</span>
            <span className="detail-value">
              {formatEstimatedCompletion()}
            </span>
          </div>
        </div>
      </div>

      <div className="progress-stages">
        <div className={`stage ${progress >= 10 ? 'completed' : progress >= 5 ? 'active' : ''}`}>
          <div className="stage-icon">🔍</div>
          <span className="stage-label">Spider Scan</span>
        </div>
        
        <div className={`stage ${progress >= 40 ? 'completed' : progress >= 20 ? 'active' : ''}`}>
          <div className="stage-icon">🎯</div>
          <span className="stage-label">Active Scan</span>
        </div>
        
        <div className={`stage ${progress >= 80 ? 'completed' : progress >= 60 ? 'active' : ''}`}>
          <div className="stage-icon">🔬</div>
          <span className="stage-label">Analysis</span>
        </div>
        
        <div className={`stage ${progress >= 100 ? 'completed' : progress >= 90 ? 'active' : ''}`}>
          <div className="stage-icon">📊</div>
          <span className="stage-label">Report</span>
        </div>
      </div>

      {status === 'running' && (
        <div className="live-indicator">
          <div className="pulse-dot"></div>
          <span>Live scanning in progress...</span>
        </div>
      )}

      {status === 'completed' && (
        <div className="completion-message">
          <div className="success-icon">🎉</div>
          <h4>Scan Completed Successfully!</h4>
          <p>Your security scan has finished. Click below to view the results.</p>
        </div>
      )}

      {status === 'failed' && (
        <div className="error-message">
          <div className="error-icon">⚠️</div>
          <h4>Scan Failed</h4>
          <p>There was an issue with your scan. Please try again or contact support.</p>
        </div>
      )}
    </div>
  );
};

export default RealTimeScanProgress; 