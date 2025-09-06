// src/components/AdminGuard.jsx - Admin Access Control Component
import React, { useContext, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useError } from '../context/ErrorContext';

const AdminGuard = ({ children, fallback = null }) => {
  const { user, isAuthenticated } = useAuth();
  const { addError } = useError();

  // Check if user is admin (support both is_admin boolean and role string)
  const isAdmin = user && (user.is_admin === true || user.role === 'admin');

  // Use useEffect to handle error state updates
  useEffect(() => {
    if (isAuthenticated && user && !isAdmin) {
      addError('Admin access required for this feature');
    }
  }, [isAuthenticated, user, isAdmin]);

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
