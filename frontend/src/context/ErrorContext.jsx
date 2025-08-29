// src/context/ErrorContext.jsx - Global Error Management
import { createContext, useContext, useState } from 'react';

const ErrorContext = createContext();

export const useError = () => {
  const context = useContext(ErrorContext);
  if (!context) {
    throw new Error('useError must be used within an ErrorProvider');
  }
  return context;
};

export const ErrorProvider = ({ children }) => {
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(null);

  const showError = (message, duration = 5000) => {
    setError(message);
    if (duration > 0) {
      setTimeout(() => setError(null), duration);
    }
  };

  const clearError = () => {
    setError(null);
  };

  const showSuccess = (message, duration = 3000) => {
    setSuccess(message);
    if (duration > 0) {
      setTimeout(() => setSuccess(null), duration);
    }
  };

  const clearSuccess = () => {
    setSuccess(null);
  };

  const setLoadingState = (isLoading) => {
    setLoading(isLoading);
  };

  return (
    <ErrorContext.Provider 
      value={{ 
        error, 
        success, 
        loading,
        showError, 
        clearError, 
        showSuccess, 
        clearSuccess,
        setLoadingState
      }}
    >
      {children}
    </ErrorContext.Provider>
  );
};

export { ErrorContext }; 