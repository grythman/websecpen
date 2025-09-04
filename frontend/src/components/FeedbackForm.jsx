// src/components/FeedbackForm.jsx - User Feedback System
import React, { useState } from 'react';
import './FeedbackForm.css';

const FeedbackForm = ({ onSubmitSuccess }) => {
  const [formData, setFormData] = useState({
    type: 'general',
    subject: '',
    rating: 0,
    message: ''
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [hoveredStar, setHoveredStar] = useState(0);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleStarClick = (rating) => {
    setFormData(prev => ({
      ...prev,
      rating
    }));
  };

  const handleStarHover = (rating) => {
    setHoveredStar(rating);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (formData.rating === 0) {
      setMessage('Please provide a rating');
      return;
    }

    setLoading(true);
    setMessage('');

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/feedback', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Thank you for your feedback! We appreciate your input.');
        setFormData({
          type: 'general',
          subject: '',
          rating: 0,
          message: ''
        });
        if (onSubmitSuccess) {
          onSubmitSuccess(data);
        }
      } else {
        setMessage(data.error || 'Failed to submit feedback');
      }
    } catch (error) {
      setMessage('Error submitting feedback. Please try again.');
      console.error('Feedback submission error:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRatingText = (rating) => {
    const ratingTexts = {
      1: 'Very Poor',
      2: 'Poor', 
      3: 'Average',
      4: 'Good',
      5: 'Excellent'
    };
    return ratingTexts[rating] || '';
  };

  return (
    <div className="feedback-form">
      <div className="feedback-header">
        <h3>💬 Share Your Feedback</h3>
        <p>Help us improve WebSecPen by sharing your thoughts and suggestions</p>
      </div>

      <form onSubmit={handleSubmit}>
        {/* Feedback Type */}
        <div className="form-group">
          <label htmlFor="type">Feedback Type</label>
          <select
            id="type"
            name="type"
            value={formData.type}
            onChange={handleInputChange}
            disabled={loading}
          >
            <option value="general">General Feedback</option>
            <option value="bug">Bug Report</option>
            <option value="feature">Feature Request</option>
          </select>
        </div>

        {/* Subject */}
        <div className="form-group">
          <label htmlFor="subject">Subject *</label>
          <input
            id="subject"
            name="subject"
            type="text"
            value={formData.subject}
            onChange={handleInputChange}
            placeholder="Brief description of your feedback"
            disabled={loading}
            required
            minLength={5}
            maxLength={200}
          />
          <small>{formData.subject.length}/200 characters</small>
        </div>

        {/* Rating */}
        <div className="form-group">
          <label>Overall Rating *</label>
          <div className="rating-container">
            <div className="stars">
              {[1, 2, 3, 4, 5].map((star) => (
                <button
                  key={star}
                  type="button"
                  className={`star ${star <= (hoveredStar || formData.rating) ? 'active' : ''}`}
                  onClick={() => handleStarClick(star)}
                  onMouseEnter={() => handleStarHover(star)}
                  onMouseLeave={() => setHoveredStar(0)}
                  disabled={loading}
                  aria-label={`Rate ${star} star${star > 1 ? 's' : ''}`}
                >
                  ★
                </button>
              ))}
            </div>
            <span className="rating-text">
              {getRatingText(hoveredStar || formData.rating)}
            </span>
          </div>
        </div>

        {/* Message */}
        <div className="form-group">
          <label htmlFor="message">Your Message *</label>
          <textarea
            id="message"
            name="message"
            value={formData.message}
            onChange={handleInputChange}
            placeholder={getPlaceholderText(formData.type)}
            disabled={loading}
            required
            minLength={10}
            maxLength={1000}
            rows={5}
          />
          <small>{formData.message.length}/1000 characters</small>
        </div>

        {/* Submit Button */}
        <div className="form-actions">
          <button
            type="submit"
            disabled={loading || formData.rating === 0}
            className="submit-button"
          >
            {loading ? (
              <>
                <span className="button-spinner"></span>
                Submitting...
              </>
            ) : (
              <>
                📤 Submit Feedback
              </>
            )}
          </button>
        </div>

        {message && (
          <div className={`feedback-message ${message.includes('Thank you') ? 'success' : 'error'}`}>
            {message}
          </div>
        )}
      </form>

      {/* Feedback Guidelines */}
      <div className="feedback-guidelines">
        <h4>💡 Feedback Guidelines</h4>
        <ul>
          <li><strong>Bug Reports:</strong> Include steps to reproduce, expected vs actual behavior</li>
          <li><strong>Feature Requests:</strong> Describe the problem you're trying to solve</li>
          <li><strong>General Feedback:</strong> Share your overall experience and suggestions</li>
        </ul>
      </div>
    </div>
  );

  function getPlaceholderText(type) {
    const placeholders = {
      general: 'Share your overall experience with WebSecPen. What do you like? What could be improved?',
      bug: 'Describe the bug you encountered. Include steps to reproduce the issue and what you expected to happen.',
      feature: 'Describe the feature you would like to see. Explain how it would help you and why it would be valuable.'
    };
    return placeholders[type] || placeholders.general;
  }
};

export default FeedbackForm; 