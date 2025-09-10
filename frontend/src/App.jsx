// Enhanced WebSecPen Frontend Application - Full Integration
import React, { useState, useEffect, Suspense } from 'react';
import { ErrorProvider } from './context/ErrorContext';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

// Core Components
import Dashboard from './components/Dashboard';
import AuthForm from './components/AuthForm.jsx';
import FeedbackForm from './components/FeedbackForm';
import ErrorDisplay from './components/ErrorDisplay';
import ErrorBoundary from './components/ErrorBoundary';
import CommandPalette from './components/CommandPalette.jsx';

// Scan Components
import CustomScanForm from './components/CustomScanForm';
import RealTimeScanProgress from './components/RealTimeScanProgress';

// Layout Components
import MainLayout from './components/MainLayout.jsx';
import ProtectedRoute from './components/ProtectedRoute.jsx';
import AdminRoute from './components/AdminRoute.jsx';

// Page Components
import ReportsPage from './components/pages/ReportsPage.jsx';
import TeamPage from './components/pages/TeamPage.jsx';
import ProfilePage from './components/pages/ProfilePage.jsx';
import VulnerabilitiesPage from './components/pages/VulnerabilitiesPage.jsx';
import AdminPage from './components/pages/AdminPage.jsx';

// Styles
import './App.css';
import './components/ModernNavigation.css';
import './i18n'; // Initialize i18n

// Loading Component
const LoadingSpinner = () => (
  <div className="app-loading">
    <div className="loading-spinner">
      <div className="spinner"></div>
      <p>Loading WebSecPen...</p>
    </div>
  </div>
);

// Scan Management Context
const ScanContext = React.createContext();

const ScanProvider = ({ children }) => {
  const [activeScan, setActiveScan] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [scanProgress, setScanProgress] = useState({});

  const startScan = (scanData) => {
    setActiveScan(scanData);
    setScanProgress({ ...scanProgress, [scanData.id]: { progress: 0, status: 'starting' } });
  };

  const updateScanProgress = (scanId, progressData) => {
    setScanProgress(prev => ({
      ...prev,
      [scanId]: progressData
    }));
  };

  const completeScan = (scanData) => {
    setScanHistory(prev => [scanData, ...prev]);
    setActiveScan(null);
    // Clean up progress data after completion
    setTimeout(() => {
      setScanProgress(prev => {
        const { [scanData.id]: removed, ...rest } = prev;
        return rest;
      });
    }, 5000);
  };

  return (
    <ScanContext.Provider value={{
      activeScan,
      scanHistory,
      scanProgress,
      startScan,
      updateScanProgress,
      completeScan
    }}>
      {children}
    </ScanContext.Provider>
  );
};

// Enhanced Scan Page Component
const ScanPage = () => {
  const [scanId, setScanId] = useState(null);
  const [showProgress, setShowProgress] = useState(false);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('results'); // 'results' or 'new-scan'

  // Fetch scan results
  const fetchScans = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('/scans', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setScans(data.scans || []);
      }
    } catch (error) {
      console.error('Error fetching scans:', error);
    } finally {
      setLoading(false);
    }
  };

  // Fetch scans on component mount
  useEffect(() => {
    fetchScans();
  }, []);

  const handleScanStart = (scanData) => {
    setScanId(scanData.scan_id);
    setShowProgress(true);
    setActiveTab('new-scan');
    console.log('Scan started:', scanData);
  };

  const handleScanComplete = (scanData) => {
    console.log('Scan completed:', scanData);
    setShowProgress(false);
    fetchScans(); // Refresh scan list
    setActiveTab('results'); // Switch back to results tab
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'success';
      case 'running': return 'info';
      case 'failed': return 'danger';
      default: return 'secondary';
    }
  };

  const getRiskColor = (score) => {
    if (score >= 7) return 'danger';
    if (score >= 4) return 'warning';
    return 'success';
  };

  return (
    <div className="scan-page">
      <div className="scan-header">
        <h2>🔍 Security Scanning</h2>
        <p>Manage your security scans and view detailed results</p>
        
        {/* Tab Navigation */}
        <div className="tab-navigation">
          <button 
            className={`tab-btn ${activeTab === 'results' ? 'active' : ''}`}
            onClick={() => setActiveTab('results')}
          >
            📊 Scan Results
          </button>
          <button 
            className={`tab-btn ${activeTab === 'new-scan' ? 'active' : ''}`}
            onClick={() => setActiveTab('new-scan')}
          >
            ➕ New Scan
          </button>
        </div>
      </div>
      
      <div className="scan-content">
        {activeTab === 'results' && (
          <div className="scan-results-section">
            <div className="results-header">
              <h3>Your Security Scans</h3>
              <button onClick={fetchScans} className="refresh-btn">
                🔄 Refresh
              </button>
            </div>
            
            {loading ? (
              <div className="loading-state">Loading scan results...</div>
            ) : scans.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">🔍</div>
                <h3>No scans yet</h3>
                <p>Start your first security scan to see results here</p>
                <button 
                  className="start-scan-btn"
                  onClick={() => setActiveTab('new-scan')}
                >
                  Start First Scan
                </button>
              </div>
            ) : (
              <div className="scan-results-grid">
                {scans.map((scan) => (
                  <div key={scan.id} className="scan-result-card">
                    <div className="card-header">
                      <div className="scan-target">
                        <h4>{scan.target_url}</h4>
                        <span className={`status-badge ${getStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                      <div className="scan-type">
                        {scan.scan_type}
                      </div>
                    </div>
                    
                    <div className="card-body">
                      <div className="scan-metrics">
                        <div className="metric">
                          <span className="metric-label">Vulnerabilities</span>
                          <span className="metric-value">{scan.vulnerabilities_count || 0}</span>
                        </div>
                        <div className="metric">
                          <span className="metric-label">Risk Score</span>
                          <span className={`metric-value risk-${getRiskColor(scan.risk_score || 0)}`}>
                            {(scan.risk_score || 0).toFixed(1)}/10
                          </span>
                        </div>
                        <div className="metric">
                          <span className="metric-label">Duration</span>
                          <span className="metric-value">
                            {scan.duration_seconds ? `${Math.round(scan.duration_seconds / 60)}m` : 'N/A'}
                          </span>
                        </div>
                      </div>
                      
                      <div className="vulnerability-breakdown">
                        {scan.high_severity_count > 0 && (
                          <span className="vuln-count high">
                            {scan.high_severity_count} High
                          </span>
                        )}
                        {scan.medium_severity_count > 0 && (
                          <span className="vuln-count medium">
                            {scan.medium_severity_count} Medium
                          </span>
                        )}
                        {scan.low_severity_count > 0 && (
                          <span className="vuln-count low">
                            {scan.low_severity_count} Low
                          </span>
                        )}
                        {scan.vulnerabilities_count === 0 && (
                          <span className="vuln-count clean">✅ Clean</span>
                        )}
                      </div>
                    </div>
                    
                    <div className="card-footer">
                      <div className="scan-date">
                        {scan.completed_at ? formatDate(scan.completed_at) : formatDate(scan.created_at)}
                      </div>
                      <button className="view-details-btn">
                        View Details →
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'new-scan' && (
          !showProgress ? (
            <CustomScanForm onScanStart={handleScanStart} />
          ) : (
            <div className="scan-progress-container">
              <RealTimeScanProgress 
                scanId={scanId} 
                onComplete={handleScanComplete} 
              />
              <button 
                className="back-to-form-btn"
                onClick={() => setShowProgress(false)}
              >
                ← Back to Scan Configuration
              </button>
            </div>
          )
        )}
      </div>
    </div>
  );
};

// Enhanced Routes with better error boundaries
const AppRoutes = () => (
  <Routes>
    {/* Public Routes */}
    <Route path="/auth" element={<AuthForm />} />

    {/* Protected Routes */}
    <Route element={<ProtectedRoute><MainLayout /></ProtectedRoute>}>
      <Route index element={
        <Suspense fallback={<LoadingSpinner />}>
          <Dashboard />
        </Suspense>
      } />
      
      <Route path="/scans" element={
        <ErrorBoundary>
          <ScanPage />
        </ErrorBoundary>
      } />
      
      <Route path="/vulnerabilities" element={
        <Suspense fallback={<LoadingSpinner />}>
          <VulnerabilitiesPage />
        </Suspense>
      } />
      
      <Route path="/reports" element={
        <Suspense fallback={<LoadingSpinner />}>
          <ReportsPage />
        </Suspense>
      } />
      
      <Route path="/team" element={
        <Suspense fallback={<LoadingSpinner />}>
          <TeamPage />
        </Suspense>
      } />
      
      <Route path="/profile" element={
        <Suspense fallback={<LoadingSpinner />}>
          <ProfilePage />
        </Suspense>
      } />

      {/* Admin Routes */}
      <Route path="/admin" element={
        <AdminRoute>
          <ErrorBoundary>
            <Suspense fallback={<LoadingSpinner />}>
              <AdminPage />
            </Suspense>
          </ErrorBoundary>
        </AdminRoute>
      } />

      {/* Additional Routes */}
      <Route path="/scan/:scanId" element={
        <ErrorBoundary>
          <RealTimeScanProgress />
        </ErrorBoundary>
      } />
      
      <Route path="/preferences" element={
        <Suspense fallback={<LoadingSpinner />}>
          <ProfilePage />
        </Suspense>
      } />
      
      <Route path="/help" element={
        <div className="help-page">
          <h2>Help & Support</h2>
          <p>Documentation and support resources coming soon...</p>
        </div>
      } />
    </Route>

    {/* Fallback Route */}
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>
);

// Enhanced App Component with better error handling
const App = () => {
  const [isInitialized, setIsInitialized] = useState(false);
  const [initError, setInitError] = useState(null);

  useEffect(() => {
    // Initialize app
    const initializeApp = async () => {
      try {
        // Simulate initialization tasks
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Check if required environment variables are set
        if (!process.env.REACT_APP_API_URL) {
          console.warn('REACT_APP_API_URL not set, using default');
        }
        
        setIsInitialized(true);
      } catch (error) {
        console.error('App initialization failed:', error);
        setInitError(error);
      }
    };

    initializeApp();
  }, []);

  if (initError) {
    return (
      <div className="app-error">
        <h2>Failed to initialize WebSecPen</h2>
        <p>Please check your configuration and try again.</p>
        <button onClick={() => window.location.reload()}>Retry</button>
      </div>
    );
  }

  if (!isInitialized) {
    return <LoadingSpinner />;
  }

  return (
    <ErrorProvider>
      <ThemeProvider>
        <AuthProvider>
          <ScanProvider>
            <ErrorDisplay />
            <ErrorBoundary>
              <BrowserRouter future={{ 
                v7_startTransition: true, 
                v7_relativeSplatPath: true 
              }}>
                <AppRoutes />
                <CommandPalette />
              </BrowserRouter>
              <FeedbackForm />
            </ErrorBoundary>
          </ScanProvider>
        </AuthProvider>
      </ThemeProvider>
    </ErrorProvider>
  );
};

export default App;
