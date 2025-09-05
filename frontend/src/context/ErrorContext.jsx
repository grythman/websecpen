// src/context/ErrorContext.jsx - Global Error Management
import React, { createContext, useState, useContext, useCallback } from 'react';

const ErrorContext = createContext();

export const ErrorProvider = ({ children }) => {
  const [errors, setErrors] = useState([]);
  const [globalError, setGlobalError] = useState(null);

  // Add a new error
  const addError = useCallback((error) => {
    const errorObj = {
      id: Date.now() + Math.random(),
      message: typeof error === 'string' ? error : error.message || 'Unknown error occurred',
      type: error.type || 'error',
      timestamp: new Date(),
      details: error.details || null,
      code: error.code || null
    };

    setErrors(prev => [...prev, errorObj]);

    // Auto remove after 5 seconds unless it's a critical error
    if (errorObj.type !== 'critical') {
      setTimeout(() => {
        removeError(errorObj.id);
      }, 5000);
    }

    return errorObj.id;
  }, []);

  // Remove a specific error
  const removeError = useCallback((errorId) => {
    setErrors(prev => prev.filter(error => error.id !== errorId));
  }, []);

  // Clear all errors
  const clearErrors = useCallback(() => {
    setErrors([]);
    setGlobalError(null);
  }, []);

  // Set global error (for critical errors that block the entire app)
  const setError = useCallback((error) => {
    const errorObj = {
      message: typeof error === 'string' ? error : error.message || 'Critical error occurred',
      type: 'critical',
      timestamp: new Date(),
      details: error.details || null,
      code: error.code || null
    };
    setGlobalError(errorObj);
  }, []);

  // Clear global error
  const clearError = useCallback(() => {
    setGlobalError(null);
  }, []);

  // Handle API errors
  const handleApiError = useCallback((error) => {
    let errorMessage = 'An error occurred';
    let errorType = 'error';

    if (error.response) {
      // Server responded with error status
      const status = error.response.status;
      const data = error.response.data;

      if (status === 401) {
        errorMessage = 'Authentication required. Please log in.';
        errorType = 'warning';
      } else if (status === 403) {
        errorMessage = 'Access denied. You don\'t have permission to perform this action.';
        errorType = 'warning';
      } else if (status === 404) {
        errorMessage = 'Resource not found.';
        errorType = 'warning';
      } else if (status >= 500) {
        errorMessage = 'Server error. Please try again later.';
        errorType = 'error';
      } else {
        errorMessage = data?.message || `Error ${status}: ${error.response.statusText}`;
      }
    } else if (error.request) {
      // Network error
      errorMessage = 'Network error. Please check your connection.';
      errorType = 'error';
    } else {
      // Other error
      errorMessage = error.message || 'An unexpected error occurred';
    }

    return addError({
      message: errorMessage,
      type: errorType,
      details: error.response?.data || error.message,
      code: error.response?.status
    });
  }, [addError]);

  // Handle success messages
  const addSuccess = useCallback((message) => {
    return addError({
      message,
      type: 'success'
    });
  }, [addError]);

  // Handle warning messages
  const addWarning = useCallback((message) => {
    return addError({
      message,
      type: 'warning'
    });
  }, [addError]);

  // Handle info messages
  const addInfo = useCallback((message) => {
    return addError({
      message,
      type: 'info'
    });
  }, [addError]);

  const value = {
    errors,
    globalError,
    addError,
    removeError,
    clearErrors,
    setError,
    clearError,
    handleApiError,
    addSuccess,
    addWarning,
    addInfo,
    hasErrors: errors.length > 0 || globalError !== null
  };

  return (
    <ErrorContext.Provider value={value}>
      {children}
    </ErrorContext.Provider>
  );
};

export const useError = () => {
  const context = useContext(ErrorContext);
  if (!context) {
    throw new Error('useError must be used within an ErrorProvider');
  }
  return context;
};

export { ErrorContext }; 