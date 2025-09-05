// src/components/ErrorDisplay.jsx - Global Notification System
import React from 'react';
import { useError } from '../context/ErrorContext.jsx';
import './ErrorDisplay.css';

const ErrorDisplay = () => {
  const { errors, globalError, removeError, clearError } = useError();

  // Don't render if no errors
  if (errors.length === 0 && !globalError) return null;

  return (
    <div className="notification-container">
      {/* Render individual errors */}
      {errors.map((error) => (
        <div key={error.id} className={`notification ${error.type}-notification`}>
          <div className="notification-content">
            <span className="notification-icon">
              {error.type === 'error' ? '⚠️' : 
               error.type === 'success' ? '✅' : 
               error.type === 'warning' ? '⚠️' : 
               error.type === 'info' ? 'ℹ️' : '⚠️'}
            </span>
            <span className="notification-message">{error.message}</span>
            <button 
              className="notification-close" 
              onClick={() => removeError(error.id)}
              aria-label="Close notification"
            >
              ×
            </button>
          </div>
        </div>
      ))}
      
      {/* Render global error */}
      {globalError && (
        <div className="notification critical-notification">
          <div className="notification-content">
            <span className="notification-icon">🚨</span>
            <span className="notification-message">{globalError.message}</span>
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
    </div>
  );
};

export default ErrorDisplay;
