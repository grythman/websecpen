// src/components/Logo.jsx - Adaptive Logo Component
import React, { useContext } from 'react';
import { ThemeContext } from '../ThemeContext.jsx';
import './Logo.css';

const Logo = ({ size = 'medium', showText = true, className = '' }) => {
  const { theme } = useContext(ThemeContext);
  
  const sizes = {
    small: { width: 120, height: 28, iconSize: 24 },
    medium: { width: 180, height: 40, iconSize: 30 },
    large: { width: 240, height: 56, iconSize: 42 }
  };
  
  const currentSize = sizes[size];
  const isDark = theme === 'dark';
  
  return (
    <div className={`logo-container ${className} ${theme}`}>
      <svg 
        width={currentSize.width} 
        height={currentSize.height} 
        viewBox="0 0 180 40" 
        fill="none" 
        xmlns="http://www.w3.org/2000/svg"
        className="logo-svg"
      >
        {/* Shield with scanner */}
        <g transform="translate(5, 5)">
          {/* Shield background */}
          <path 
            d="M15 2L8 5V15C8 22 12 28 15 30C18 28 22 22 22 15V5L15 2Z" 
            fill="#667eea" 
            stroke="#4c51bf" 
            strokeWidth="1"
          />
          
          {/* Shield inner design */}
          <path 
            d="M15 4L10 6V14C10 19 12.5 23 15 24.5C17.5 23 20 19 20 14V6L15 4Z" 
            fill={isDark ? '#1a202c' : 'white'}
          />
          
          {/* Scanner lines */}
          <line 
            x1="6" y1="26" x2="12" y2="20" 
            stroke="#38a169" 
            strokeWidth="2" 
            strokeLinecap="round"
          />
          <line 
            x1="24" y1="26" x2="18" y2="20" 
            stroke="#38a169" 
            strokeWidth="2" 
            strokeLinecap="round"
          />
          <line 
            x1="4" y1="22" x2="10" y2="17" 
            stroke="#38a169" 
            strokeWidth="1.5" 
            strokeLinecap="round" 
            opacity="0.7"
          />
          <line 
            x1="26" y1="22" x2="20" y2="17" 
            stroke="#38a169" 
            strokeWidth="1.5" 
            strokeLinecap="round" 
            opacity="0.7"
          />
          
          {/* Scan center with pulse animation */}
          <circle 
            cx="15" 
            cy="15" 
            r="2" 
            fill="#e53e3e" 
            opacity="0.8"
            className="scan-pulse"
          />
        </g>
        
        {/* Text: WebSecPen */}
        {showText && (
          <>
            <text 
              x="45" 
              y="15" 
              fontFamily="Arial, sans-serif" 
              fontSize="14" 
              fontWeight="bold" 
              fill={isDark ? '#f7fafc' : '#2d3748'}
            >
              Web
            </text>
            <text 
              x="45" 
              y="30" 
              fontFamily="Arial, sans-serif" 
              fontSize="14" 
              fontWeight="bold" 
              fill={isDark ? '#f7fafc' : '#2d3748'}
            >
              Sec
            </text>
            <text 
              x="75" 
              y="15" 
              fontFamily="Arial, sans-serif" 
              fontSize="14" 
              fontWeight="bold" 
              fill="#667eea"
            >
              Pen
            </text>
            
            {/* Tagline */}
            <text 
              x="100" 
              y="18" 
              fontFamily="Arial, sans-serif" 
              fontSize="8" 
              fill={isDark ? '#a0aec0' : '#718096'} 
              opacity="0.8"
            >
              AI-Powered
            </text>
            <text 
              x="100" 
              y="28" 
              fontFamily="Arial, sans-serif" 
              fontSize="8" 
              fill={isDark ? '#a0aec0' : '#718096'} 
              opacity="0.8"
            >
              Security Scanner
            </text>
          </>
        )}
      </svg>
    </div>
  );
};

export default Logo; 