// src/components/Login.jsx
import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import './Login.css';

const Login = ({ onSuccess }) => {
  const { login, register, error, isLoginLoading, isRegisterLoading, clearError } = useAuth();
  const [isLoginMode, setIsLoginMode] = useState(true);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: ''
  });
  const [localError, setLocalError] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Clear errors when switching modes
  useEffect(() => {
    clearError();
    setLocalError('');
  }, [isLoginMode, clearError]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    // Clear local error when user starts typing
    if (localError) setLocalError('');
  };

  const validateForm = () => {
    if (!formData.email || !formData.password) {
      setLocalError('Email and password are required');
      return false;
    }

    if (!isLoginMode) {
      if (formData.password !== formData.confirmPassword) {
        setLocalError('Passwords do not match');
        return false;
      }
      if (formData.password.length < 6) {
        setLocalError('Password must be at least 6 characters long');
        return false;
      }
    }

    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;

    try {
      let result;
      
      if (isLoginMode) {
        result = await login(formData.email, formData.password);
      } else {
        result = await register({
          email: formData.email,
          password: formData.password,
          first_name: formData.firstName,
          last_name: formData.lastName
        });
      }

      if (result.success) {
        if (onSuccess) {
          onSuccess();
        }
      } else {
        setLocalError(result.error || 'An error occurred');
      }
    } catch (err) {
      setLocalError('Network error. Please try again.');
    }
  };

  const toggleMode = () => {
    setIsLoginMode(!isLoginMode);
    setFormData({
      email: '',
      password: '',
      confirmPassword: '',
      firstName: '',
      lastName: ''
    });
  };

  const displayError = localError || error;

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <h2>{isLoginMode ? 'Welcome Back' : 'Create Account'}</h2>
          <p className="login-subtitle">
            {isLoginMode 
              ? 'Sign in to your WebSecPen account' 
              : 'Join WebSecPen and start securing your applications'
            }
          </p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {!isLoginMode && (
            <div className="form-row">
              <div className="form-group">
                <input
                  type="text"
                  name="firstName"
                  value={formData.firstName}
                  onChange={handleInputChange}
                  placeholder="First Name"
                  className="form-input"
                  required={!isLoginMode}
                />
              </div>
              <div className="form-group">
                <input
                  type="text"
                  name="lastName"
                  value={formData.lastName}
                  onChange={handleInputChange}
                  placeholder="Last Name"
                  className="form-input"
                  required={!isLoginMode}
                />
              </div>
            </div>
          )}

          <div className="form-group">
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              placeholder="Email Address"
              className="form-input"
              required
            />
          </div>

          <div className="form-group">
            <div className="password-input-container">
              <input
                type={showPassword ? 'text' : 'password'}
                name="password"
                value={formData.password}
                onChange={handleInputChange}
                placeholder="Password"
                className="form-input"
                required
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? '👁️' : '👁️‍🗨️'}
              </button>
            </div>
          </div>

          {!isLoginMode && (
            <div className="form-group">
              <input
                type="password"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleInputChange}
                placeholder="Confirm Password"
                className="form-input"
                required={!isLoginMode}
              />
            </div>
          )}

          {isLoginMode && (
            <div className="form-options">
              <label className="remember-me">
                <input type="checkbox" />
                <span>Remember me</span>
              </label>
              <a href="#" className="forgot-password">Forgot password?</a>
            </div>
          )}

          {displayError && (
            <div className="error-message">
              {displayError}
            </div>
          )}

          <button
            type="submit"
            className="login-button"
            disabled={isLoginLoading || isRegisterLoading}
          >
            {isLoginLoading || isRegisterLoading ? (
              <div className="loading-spinner">
                <div className="spinner"></div>
                {isLoginMode ? 'Signing in...' : 'Creating account...'}
              </div>
            ) : (
              isLoginMode ? 'Sign In' : 'Create Account'
            )}
          </button>
        </form>

        <div className="login-footer">
          <p>
            {isLoginMode ? "Don't have an account?" : "Already have an account?"}
            <button
              type="button"
              className="mode-toggle"
              onClick={toggleMode}
            >
              {isLoginMode ? 'Sign up' : 'Sign in'}
            </button>
          </p>
        </div>

        <div className="login-divider">
          <span>or</span>
        </div>

        <div className="social-login">
          <button className="social-button google">
            <span className="social-icon">��</span>
            Continue with Google
          </button>
          <button className="social-button github">
            <span className="social-icon">🐙</span>
            Continue with GitHub
          </button>
        </div>
      </div>
    </div>
  );
};

export default Login;
