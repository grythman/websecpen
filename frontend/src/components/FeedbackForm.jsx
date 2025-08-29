// src/components/FeedbackForm.jsx - User Feedback System
import { useState, useContext } from 'react';
import { ThemeContext } from '../ThemeContext.jsx';
import { useError } from '../context/ErrorContext.jsx';
import apiService from '../utils/api.js';
import './FeedbackForm.css';

const FeedbackForm = ({ isModal = false, onClose = null }) => {
  const { theme } = useContext(ThemeContext);
  const { showError, showSuccess, loading, setLoadingState } = useError();
  
  const [formData, setFormData] = useState({
    feedback: '',
    type: 'general'
  });

  const feedbackTypes = [
    { value: 'general', label: '💬 General Feedback', description: 'General comments and suggestions' },
    { value: 'bug', label: '🐛 Bug Report', description: 'Report a problem or error' },
    { value: 'feature', label: '✨ Feature Request', description: 'Suggest a new feature' },
    { value: 'security', label: '🔒 Security Issue', description: 'Report a security concern' },
    { value: 'performance', label: '⚡ Performance Issue', description: 'Report slow or unresponsive behavior' }
  ];

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.feedback.trim()) {
      showError('Please enter your feedback');
      return;
    }

    if (formData.feedback.length < 10) {
      showError('Please provide more detailed feedback (at least 10 characters)');
      return;
    }

    if (formData.feedback.length > 5000) {
      showError('Feedback is too long (maximum 5000 characters)');
      return;
    }

    setLoadingState(true);

    try {
      await apiService.request('/feedback', {
        method: 'POST',
        body: JSON.stringify(formData)
      });

      showSuccess('Thank you for your feedback! We appreciate your input.');
      
      // Reset form
      setFormData({
        feedback: '',
        type: 'general'
      });

      // Close modal if this is a modal
      if (isModal && onClose) {
        setTimeout(onClose, 1500);
      }

    } catch (error) {
      showError(error.message || 'Failed to submit feedback. Please try again.');
    } finally {
      setLoadingState(false);
    }
  };

  const selectedType = feedbackTypes.find(type => type.value === formData.type);

  const feedbackContent = (
    <>
      <div className="feedback-header">
        <h3>📝 Send Us Feedback</h3>
        <p>Help us improve WebSecPen by sharing your thoughts, reporting bugs, or suggesting features.</p>
      </div>

      <form onSubmit={handleSubmit} className="feedback-form-content" aria-label="Submit feedback">
        <div className="form-group">
          <label htmlFor="type" className="form-label">
            Feedback Type *
          </label>
          <select
            id="type"
            name="type"
            value={formData.type}
            onChange={handleInputChange}
            className="form-select"
            disabled={loading}
            required
          >
            {feedbackTypes.map((type) => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
          <div className="form-hint">
            {selectedType?.description}
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="feedback" className="form-label">
            Your Feedback *
          </label>
          <textarea
            id="feedback"
            name="feedback"
            value={formData.feedback}
            onChange={handleInputChange}
            placeholder="Please describe your feedback in detail..."
            className="form-textarea"
            disabled={loading}
            required
            rows={6}
            minLength={10}
            maxLength={5000}
            aria-label="Feedback details"
          />
          <div className="character-count">
            {formData.feedback.length}/5000 characters
            {formData.feedback.length < 10 && (
              <span className="count-warning"> (minimum 10 characters)</span>
            )}
          </div>
        </div>

        <div className="feedback-tips">
          <h4>💡 Tips for effective feedback:</h4>
          <ul>
            <li><strong>Be specific</strong>: Include details about what you were doing when the issue occurred</li>
            <li><strong>Include steps</strong>: Help us reproduce bugs by listing the steps you took</li>
            <li><strong>Be constructive</strong>: Suggest improvements or alternatives</li>
            <li><strong>Check first</strong>: Look for existing feedback about the same issue</li>
          </ul>
        </div>

        <div className="form-actions">
          <button 
            type="submit" 
            className={`btn btn-primary ${loading ? 'loading' : ''}`}
            disabled={loading || formData.feedback.length < 10}
          >
            {loading ? (
              <>
                <span className="loading-spinner"></span>
                Submitting...
              </>
            ) : (
              <>
                <span className="btn-icon">📤</span>
                Submit Feedback
              </>
            )}
          </button>
          
          {isModal && (
            <button 
              type="button" 
              className="btn btn-secondary"
              onClick={onClose}
              disabled={loading}
            >
              Cancel
            </button>
          )}
        </div>

        <div className="privacy-notice">
          <p>
            <span className="privacy-icon">🔒</span>
            Your feedback helps us improve WebSecPen. We don&apos;t share your feedback with third parties.
            {apiService.isAuthenticated() ? 
              ' Your feedback is linked to your account for follow-up.' : 
              ' You\'re submitting anonymous feedback.'
            }
          </p>
        </div>
      </form>
    </>
  );

  if (isModal) {
    return (
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()}>
          <button className="modal-close" onClick={onClose} aria-label="Close feedback form">
            ×
          </button>
          <div className={`feedback-form ${theme} modal`}>
            {feedbackContent}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`feedback-form ${theme}`}>
      {feedbackContent}
    </div>
  );
};

export default FeedbackForm; 