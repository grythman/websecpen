import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import './TeamAnnotations.css';

const TeamAnnotations = ({ scanId, vulnId, vulnName }) => {
  const [annotations, setAnnotations] = useState([]);
  const [newComment, setNewComment] = useState('');
  const [loading, setLoading] = useState(false);
  const [socket, setSocket] = useState(null);

  useEffect(() => {
    // Initialize socket connection
    const socketConnection = io(process.env.REACT_APP_API_URL || 'http://localhost:5000');
    setSocket(socketConnection);

    // Join room for real-time updates
    socketConnection.emit('join_scan', { scan_id: scanId });

    // Listen for new annotations
    socketConnection.on('new_annotation', (data) => {
      if (data.scan_id === scanId && data.vuln_id === vulnId) {
        setAnnotations(prev => [data, ...prev]);
      }
    });

    // Fetch existing annotations
    fetchAnnotations();

    return () => {
      socketConnection.disconnect();
    };
  }, [scanId, vulnId]);

  const fetchAnnotations = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/scan/${scanId}/annotations`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        // Filter annotations for this specific vulnerability
        const vulnAnnotations = data.filter(annotation => annotation.vuln_id === vulnId);
        setAnnotations(vulnAnnotations);
      } else {
        console.error('Failed to fetch annotations');
      }
    } catch (error) {
      console.error('Error fetching annotations:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddAnnotation = async (e) => {
    e.preventDefault();
    
    if (!newComment.trim()) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/scan/${scanId}/annotations`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          vuln_id: vulnId,
          comment: newComment.trim()
        })
      });

      if (response.ok) {
        setNewComment('');
        // Note: New annotation will be added via socket event
      } else {
        const errorData = await response.json();
        alert(`Failed to add annotation: ${errorData.error}`);
      }
    } catch (error) {
      console.error('Error adding annotation:', error);
      alert('Failed to add annotation. Please try again.');
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);

    if (diffInSeconds < 60) {
      return 'Just now';
    } else if (diffInSeconds < 3600) {
      const minutes = Math.floor(diffInSeconds / 60);
      return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else if (diffInSeconds < 86400) {
      const hours = Math.floor(diffInSeconds / 3600);
      return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else {
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
    }
  };

  const getUserName = (userId) => {
    // In a real app, you'd maintain a user cache or fetch user details
    return `User ${userId}`;
  };

  return (
    <div className="team-annotations">
      <div className="annotations-header">
        <h4>💬 Team Discussion</h4>
        <span className="vuln-name">{vulnName}</span>
      </div>

      <div className="annotations-list">
        {loading ? (
          <div className="loading-annotations">
            <div className="loading-spinner"></div>
            <span>Loading annotations...</span>
          </div>
        ) : annotations.length > 0 ? (
          annotations.map((annotation) => (
            <div key={annotation.id} className="annotation-item">
              <div className="annotation-header">
                <span className="annotation-user">
                  👤 {getUserName(annotation.user_id)}
                </span>
                <span className="annotation-time">
                  {formatDate(annotation.created_at)}
                </span>
              </div>
              <div className="annotation-comment">
                {annotation.comment}
              </div>
            </div>
          ))
        ) : (
          <div className="no-annotations">
            <div className="no-annotations-icon">💭</div>
            <p>No team discussion yet.</p>
            <p>Be the first to add insights about this vulnerability!</p>
          </div>
        )}
      </div>

      <form className="add-annotation-form" onSubmit={handleAddAnnotation}>
        <div className="form-group">
          <textarea
            value={newComment}
            onChange={(e) => setNewComment(e.target.value)}
            placeholder="Share your insights about this vulnerability..."
            rows={3}
            maxLength={1000}
            className="annotation-textarea"
          />
          <div className="textarea-footer">
            <span className="character-count">
              {newComment.length}/1000
            </span>
          </div>
        </div>
        <div className="form-actions">
          <button 
            type="submit" 
            className="add-annotation-btn"
            disabled={!newComment.trim()}
          >
            <span className="btn-icon">💬</span>
            Add Comment
          </button>
        </div>
      </form>

      <div className="annotations-tips">
        <h5>💡 Discussion Tips</h5>
        <ul>
          <li>Share remediation steps or workarounds</li>
          <li>Discuss impact assessment and prioritization</li>
          <li>Link to related tickets or documentation</li>
          <li>Update status when working on fixes</li>
        </ul>
      </div>
    </div>
  );
};

export default TeamAnnotations; 