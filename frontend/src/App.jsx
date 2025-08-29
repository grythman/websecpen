import { useState, useEffect } from 'react'
import './App.css'
import { ThemeProvider } from './ThemeContext.jsx';
import { ErrorProvider } from './context/ErrorContext.jsx';
import Login from './components/Login.jsx';
import Dashboard from './components/Dashboard.jsx';
import ErrorDisplay from './components/ErrorDisplay.jsx';
import apiService from './utils/api.js';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    // Check if user is already authenticated with proper token validation
    setIsAuthenticated(apiService.isAuthenticated());

    // Listen for logout events (session expiry, manual logout)
    const handleLogoutEvent = () => {
      setIsAuthenticated(false);
    };

    window.addEventListener('auth:logout', handleLogoutEvent);
    
    return () => {
      window.removeEventListener('auth:logout', handleLogoutEvent);
    };
  }, []);

  const handleLogin = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    apiService.logout();
    setIsAuthenticated(false);
  };

  return (
    <ThemeProvider>
      <ErrorProvider>
        <div className="app">
          <ErrorDisplay />
          {!isAuthenticated ? (
            <Login onLogin={handleLogin} />
          ) : (
            <Dashboard onLogout={handleLogout} />
          )}
        </div>
      </ErrorProvider>
    </ThemeProvider>
  );
}

export default App;
