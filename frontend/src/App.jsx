// Enhanced WebSecPen Frontend Application - Full Integration
import React from 'react';
import { ErrorProvider } from './context/ErrorContext';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

import Dashboard from './components/Dashboard';
import AuthForm from './components/AuthForm.jsx';
import FeedbackForm from './components/FeedbackForm';
import ErrorDisplay from './components/ErrorDisplay';
import ErrorBoundary from './components/ErrorBoundary';
import CommandPalette from './components/CommandPalette.jsx';

import CustomScanForm from './components/CustomScanForm';
import RealTimeScanProgress from './components/RealTimeScanProgress';

import MainLayout from './components/MainLayout.jsx';
import ProtectedRoute from './components/ProtectedRoute.jsx';
import AdminRoute from './components/AdminRoute.jsx';

import ReportsPage from './components/pages/ReportsPage.jsx';
import TeamPage from './components/pages/TeamPage.jsx';
import ProfilePage from './components/pages/ProfilePage.jsx';
import VulnerabilitiesPage from './components/pages/VulnerabilitiesPage.jsx';
import AdminPage from './components/pages/AdminPage.jsx';

import './App.css';
import './components/ModernNavigation.css';
import './i18n'; // Initialize i18n

const AppRoutes = () => (
  <Routes>
    <Route path="/auth" element={<AuthForm />} />

    <Route element={<ProtectedRoute><MainLayout /></ProtectedRoute>}>
      <Route index element={<Dashboard />} />
      <Route path="/scans" element={
        <>
          <CustomScanForm />
          <RealTimeScanProgress />
        </>
      } />
      <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
      <Route path="/reports" element={<ReportsPage />} />
      <Route path="/team" element={<TeamPage />} />
      <Route path="/profile" element={<ProfilePage />} />

      <Route path="/admin" element={
        <AdminRoute>
          <AdminPage />
        </AdminRoute>
      } />
    </Route>

    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>
  );

const App = () => {
  return (
    <ErrorProvider>
      <ThemeProvider>
        <AuthProvider>
          <ErrorDisplay />
          <ErrorBoundary>
            <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
              <AppRoutes />
              <CommandPalette />
            </BrowserRouter>
            <FeedbackForm />
          </ErrorBoundary>
        </AuthProvider>
      </ThemeProvider>
    </ErrorProvider>
  );
};

export default App;
