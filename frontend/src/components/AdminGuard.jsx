// src/components/AdminGuard.jsx - Admin Access Control Component
import React, { useContext, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useError } from '../context/ErrorContext';

const AdminGuard = ({ children, fallback = null }) => {
  const { user, isAuthenticated, isLoading } = useAuth();
  const { addError } = useError();

  // Check if user is admin (support both is_admin boolean and role string)
  const isAdmin = user && (user.is_admin === true || user.role === 'admin');

  // Use useEffect to handle error state updates - but only after loading is complete
  useEffect(() => {
    if (!isLoading && isAuthenticated && user && !isAdmin) {
      addError('Admin access required for this feature');
    }
  }, [isAuthenticated, user, isAdmin, isLoading, addError]);

  // Show loading state while authentication is being initialized
  if (isLoading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }

  // Check if user is authenticated and is admin
  if (!isAuthenticated) {
    return fallback || <div>Please log in to access this feature.</div>;
  }

  if (!user || !isAdmin) {
    return fallback || <div>Admin access required.</div>;
  }

  return children;
};

export default AdminGuard;
