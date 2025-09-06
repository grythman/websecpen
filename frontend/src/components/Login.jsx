// src/components/Login.jsx
import { useState, useContext } from 'react';
import { ThemeContext } from '../context/ThemeContext.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { useError } from '../context/ErrorContext.jsx';
import Logo from './Logo.jsx';
import './Login.css';

const Login = ({ onSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { theme } = useContext(ThemeContext);
  const { login } = useAuth();
  const { addError } = useError();

  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Client-side validation
    if (!email || !password) {
      setError('Please fill in all fields');
      return;
    }

    if (!validateEmail(email)) {
      setError('Please enter a valid email address');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }

    setIsLoading(true);
    
    try {
      // Use real authentication service
      const result = await login(email, password);
      
      if (result.success) {
        console.log('Login successful');
        
        // Call the onLogin callback to update parent component
        if (onSuccess) {
          onSuccess();
        }
      } else {
        setError(result.message || 'Login failed. Please try again.');
      }
      
    } catch (err) {
      console.error('Login error:', err);
      setError('Login failed. Please try again.');
      addError('Login failed. Please check your credentials and try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={`login-container ${theme}`}>
      <div className="login-card">
        <div className="login-header">
          <Logo size="large" showText={true} />
          <p>Sign in to your security scanning dashboard</p>
        </div>
        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Email"
              className="form-input"
              disabled={isLoading}
            />
          </div>
          
          <div className="form-group">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              className="form-input"
              disabled={isLoading}
            />
          </div>
          
          {error && <div className="error-message">{error}</div>}
          
          <button 
            type="submit" 
            className="login-button" 
            disabled={isLoading}
          >
            {isLoading ? 'Logging in...' : 'Login'}
          </button>
          
          <div className="login-footer">
            <a href="#" className="forgot-password">Forgot Password?</a>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Login;
