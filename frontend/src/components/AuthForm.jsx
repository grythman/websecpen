// src/components/AuthForm.jsx - Enhanced Login/Register Form with Language Switcher
import React, { useState, useContext } from 'react';
import { useTranslation } from 'react-i18next';
import { ThemeContext } from '../context/ThemeContext.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { useError } from '../context/ErrorContext.jsx';
import Logo from './Logo.jsx';
import './AuthForm.css';
import { useNavigate, useLocation } from 'react-router-dom';

const AuthForm = ({ onSuccess }) => {
  const [mode, setMode] = useState('login'); // 'login' or 'register'
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const { theme } = useContext(ThemeContext);
  const { login, register } = useAuth();
  const { addError } = useError();
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();

  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const validateForm = () => {
    if (!formData.email || !formData.password) {
      setError(t('required_field'));
      return false;
    }

    if (!validateEmail(formData.email)) {
      setError(t('invalid_email'));
      return false;
    }

    if (formData.password.length < 6) {
      setError('Password must be at least 6 characters');
      return false;
    }

    if (mode === 'register') {
      if (!formData.firstName || !formData.lastName) {
        setError(t('required_field'));
        return false;
      }

      if (formData.password !== formData.confirmPassword) {
        setError(t('password_mismatch'));
        return false;
      }
    }

    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (isLoading) return;
    setError('');

    if (!validateForm()) return;

    setIsLoading(true);
    
    try {
      let result;
      if (mode === 'login') {
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
        const redirectTo = location.state?.from?.pathname || '/';
        if (onSuccess) onSuccess();
        navigate(redirectTo, { replace: true });
      } else {
        setError(result.error || `${mode === 'login' ? 'Login' : 'Registration'} failed. Please try again.`);
      }
      
    } catch (err) {
      console.error(`${mode} error:`, err);
      setError(`${mode === 'login' ? 'Login' : 'Registration'} failed. Please try again.`);
      addError(`${mode === 'login' ? 'Login' : 'Registration'} failed. Please check your information and try again.`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleInputChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const switchMode = () => {
    setMode(mode === 'login' ? 'register' : 'login');
    setError('');
    setFormData({
      email: '',
      password: '',
      confirmPassword: '',
      firstName: '',
      lastName: ''
    });
  };

  const changeLanguage = (lng) => {
    i18n.changeLanguage(lng);
  };

  return (
    <div className={`auth-container ${theme}`}>
      <div className="auth-card">
        {/* Language Switcher */}
        <div className="language-switcher">
          <button 
            className={`lang-btn ${i18n.language === 'en' ? 'active' : ''}`}
            onClick={() => changeLanguage('en')}
          >
            🇺🇸 EN
          </button>
          <button 
            className={`lang-btn ${i18n.language === 'mn' ? 'active' : ''}`}
            onClick={() => changeLanguage('mn')}
          >
            🇲🇳 МН
          </button>
        </div>

        <div className="auth-header">
          <Logo size="large" showText={true} />
          <h2>{mode === 'login' ? t('login') : t('register')}</h2>
          <p>
            {mode === 'login' 
              ? 'Sign in to your security scanning dashboard'
              : 'Create your account to start scanning'
            }
          </p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          {mode === 'register' && (
            <div className="form-row">
              <div className="form-group">
                <input
                  type="text"
                  value={formData.firstName}
                  onChange={(e) => handleInputChange('firstName', e.target.value)}
                  placeholder="First Name"
                  className="form-input"
                  disabled={isLoading}
                  required
                />
              </div>
              <div className="form-group">
                <input
                  type="text"
                  value={formData.lastName}
                  onChange={(e) => handleInputChange('lastName', e.target.value)}
                  placeholder="Last Name"
                  className="form-input"
                  disabled={isLoading}
                  required
                />
              </div>
            </div>
          )}

          <div className="form-group">
            <input
              type="email"
              value={formData.email}
              onChange={(e) => handleInputChange('email', e.target.value)}
              placeholder={t('email')}
              className="form-input"
              disabled={isLoading}
              required
            />
          </div>
          
          <div className="form-group">
            <div className="password-input-container">
              <input
                type={showPassword ? 'text' : 'password'}
                value={formData.password}
                onChange={(e) => handleInputChange('password', e.target.value)}
                placeholder={t('password')}
                className="form-input"
                disabled={isLoading}
                required
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex={-1}
              >
                {showPassword ? '👁️' : '👁️‍🗨️'}
              </button>
            </div>
          </div>

          {mode === 'register' && (
            <div className="form-group">
              <div className="password-input-container">
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={formData.confirmPassword}
                  onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
                  placeholder={t('confirm_password')}
                  className="form-input"
                  disabled={isLoading}
                  required
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  tabIndex={-1}
                >
                  {showConfirmPassword ? '👁️' : '👁️‍🗨️'}
                </button>
              </div>
            </div>
          )}
          
          {error && <div className="error-message">{error}</div>}
          
          <button 
            type="submit" 
            className="auth-button" 
            disabled={isLoading}
          >
            {isLoading ? (
              <div className="loading-spinner">
                <div className="spinner"></div>
                <span>{t('loading')}</span>
              </div>
            ) : (
              mode === 'login' ? t('login') : t('register')
            )}
          </button>
        </form>

        <div className="auth-footer">
          <div className="mode-switch">
            <p>
              {mode === 'login' 
                ? "Don't have an account? " 
                : "Already have an account? "
              }
              <button onClick={switchMode} className="switch-btn">
                {mode === 'login' ? t('register') : t('login')}
              </button>
            </p>
          </div>
          
          {mode === 'login' && (
            <div className="forgot-password-link">
              <a href="#" className="forgot-password">Forgot Password?</a>
            </div>
          )}
        </div>

        <div className="demo-accounts">
          <p>Demo Accounts:</p>
          <div className="demo-buttons">
            <button 
              type="button" 
              className="demo-btn"
              onClick={() => {
                setFormData(prev => ({
                  ...prev,
                  email: 'admin@websecpen.com',
                  password: 'admin123'
                }));
              }}
            >
              👑 Admin
            </button>
            <button 
              type="button" 
              className="demo-btn"
              onClick={() => {
                setFormData(prev => ({
                  ...prev,
                  email: 'test@example.com',
                  password: 'test123'
                }));
              }}
            >
              👤 User
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuthForm; 