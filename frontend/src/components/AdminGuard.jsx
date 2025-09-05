// src/components/AdminGuard.jsx - Admin Access Control Component
import React, { useContext } from 'react';
import { useAuth } from '../context/AuthContext';
import { useError } from '../context/ErrorContext';

const AdminGuard = ({ children, fallback = null }) => {
  const { user, isAuthenticated } = useAuth();
  const { addError } = useError();

  // Check if user is authenticated and is admin
  if (!isAuthenticated) {
    return fallback || <div>Please log in to access this feature.</div>;
  }

  if (!user || !user.is_admin) {
    addError('Admin access required for this feature');
    return fallback || <div>Admin access required.</div>;
  }

  return children;
};

export default AdminGuard;
