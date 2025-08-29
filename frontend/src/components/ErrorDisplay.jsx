// src/components/ErrorDisplay.jsx - Global Notification System
import { useError } from '../context/ErrorContext.jsx';
import './ErrorDisplay.css';

const ErrorDisplay = () => {
  const { error, success, clearError, clearSuccess } = useError();

  if (!error && !success) return null;

  return (
    <div className="notification-container">
      {error && (
        <div className="notification error-notification">
          <div className="notification-content">
            <span className="notification-icon">⚠️</span>
            <span className="notification-message">{error}</span>
            <button 
              className="notification-close" 
              onClick={clearError}
              aria-label="Close error"
            >
              ×
            </button>
          </div>
        </div>
      )}
      
      {success && (
        <div className="notification success-notification">
          <div className="notification-content">
            <span className="notification-icon">✅</span>
            <span className="notification-message">{success}</span>
            <button 
              className="notification-close" 
              onClick={clearSuccess}
              aria-label="Close success"
            >
              ×
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ErrorDisplay; 