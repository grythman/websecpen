// src/components/Onboarding.jsx - Interactive User Onboarding Tour
import React, { useState, useEffect } from 'react';
import { useError } from '../context/ErrorContext.jsx';
import './Onboarding.css';

const Onboarding = ({ onComplete }) => {
  const { addSuccess } = useError();
  const [currentStep, setCurrentStep] = useState(0);
  const [isVisible, setIsVisible] = useState(false);

  const steps = [
    {
      target: '.nav-brand',
      title: '🎯 Welcome to WebSecPen!',
      content: 'Your AI-powered security scanning platform. Let\'s take a quick tour to get you started.',
      position: 'bottom'
    },
    {
      target: '.scan-section',
      title: '🔍 Start Security Scans',
      content: 'Begin by entering a target URL and selecting the type of security scan you want to perform. We support XSS, SQL injection, CSRF, and comprehensive scans.',
      position: 'top'
    },
    {
      target: '.history-section',
      title: '📊 View Scan History',
      content: 'Track all your previous scans, view their status, and access detailed results. Your scan history helps you monitor security improvements over time.',
      position: 'top'
    },
    {
      target: '.result-section',
      title: '⚠️ Latest Results',
      content: 'Get AI-powered analysis of vulnerabilities found in your scans. Each result includes severity levels, descriptions, and remediation guidance.',
      position: 'top'
    },
    {
      target: '.stats-section',
      title: '📈 Quick Stats',
      content: 'Monitor your security posture with quick statistics showing total scans, vulnerability counts, and risk levels at a glance.',
      position: 'top'
    },
    {
      target: '.theme-toggle',
      title: '🌙 Theme Toggle',
      content: 'Switch between light and dark themes to customize your viewing experience. Your preference is automatically saved.',
      position: 'bottom'
    },
    {
      target: 'button[onClick*="setShowFeedbackModal"]',
      title: '💬 Send Feedback',
      content: 'Have suggestions or found a bug? Use the feedback button to help us improve WebSecPen. We value your input!',
      position: 'bottom'
    }
  ];

  useEffect(() => {
    // Check if user has seen onboarding before
    const hasSeenOnboarding = localStorage.getItem('websecpen_onboarding_completed');
    if (!hasSeenOnboarding) {
      setIsVisible(true);
    }
  }, []);

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      handleComplete();
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleSkip = () => {
    handleComplete();
  };

  const handleComplete = () => {
    localStorage.setItem('websecpen_onboarding_completed', 'true');
    setIsVisible(false);
    addSuccess('🎉 Welcome to WebSecPen! You\'re all set to start scanning for security vulnerabilities.');
    if (onComplete) {
      onComplete();
    }
  };

  const getCurrentStepElement = () => {
    const step = steps[currentStep];
    const element = document.querySelector(step.target);
    return element;
  };

  const getTooltipPosition = () => {
    const element = getCurrentStepElement();
    if (!element) return { top: '50%', left: '50%' };

    const rect = element.getBoundingClientRect();
    const step = steps[currentStep];
    
    let top, left;
    
    switch (step.position) {
      case 'top':
        top = rect.top - 10;
        left = rect.left + rect.width / 2;
        break;
      case 'bottom':
        top = rect.bottom + 10;
        left = rect.left + rect.width / 2;
        break;
      case 'left':
        top = rect.top + rect.height / 2;
        left = rect.left - 10;
        break;
      case 'right':
        top = rect.top + rect.height / 2;
        left = rect.right + 10;
        break;
      default:
        top = rect.bottom + 10;
        left = rect.left + rect.width / 2;
    }

    return { top: `${top}px`, left: `${left}px` };
  };

  const highlightCurrentElement = () => {
    // Remove previous highlights
    document.querySelectorAll('.onboarding-highlight').forEach(el => {
      el.classList.remove('onboarding-highlight');
    });

    // Add highlight to current element
    const element = getCurrentStepElement();
    if (element) {
      element.classList.add('onboarding-highlight');
    }
  };

  useEffect(() => {
    if (isVisible) {
      highlightCurrentElement();
    }
    
    return () => {
      // Clean up highlights
      document.querySelectorAll('.onboarding-highlight').forEach(el => {
        el.classList.remove('onboarding-highlight');
      });
    };
  }, [currentStep, isVisible]);

  if (!isVisible) return null;

  const currentStepData = steps[currentStep];
  const tooltipPosition = getTooltipPosition();

  return (
    <>
      {/* Overlay */}
      <div className="onboarding-overlay" />
      
      {/* Tooltip */}
      <div 
        className={`onboarding-tooltip ${currentStepData.position}`}
        style={tooltipPosition}
      >
        <div className="tooltip-header">
          <h3>{currentStepData.title}</h3>
          <button 
            className="tooltip-close"
            onClick={handleSkip}
            aria-label="Skip tour"
          >
            ×
          </button>
        </div>
        
        <div className="tooltip-content">
          <p>{currentStepData.content}</p>
        </div>
        
        <div className="tooltip-footer">
          <div className="step-indicator">
            <span>{currentStep + 1} of {steps.length}</span>
            <div className="progress-bar">
              <div 
                className="progress-fill"
                style={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}
              />
            </div>
          </div>
          
          <div className="tooltip-actions">
            <button 
              className="btn btn-secondary"
              onClick={handleSkip}
            >
              Skip Tour
            </button>
            
            {currentStep > 0 && (
              <button 
                className="btn btn-secondary"
                onClick={handlePrevious}
              >
                Previous
              </button>
            )}
            
            <button 
              className="btn btn-primary"
              onClick={handleNext}
            >
              {currentStep === steps.length - 1 ? 'Get Started!' : 'Next'}
            </button>
          </div>
        </div>
        
        {/* Tooltip arrow */}
        <div className={`tooltip-arrow tooltip-arrow-${currentStepData.position}`} />
      </div>
    </>
  );
};

// Reset onboarding function for testing
export const resetOnboarding = () => {
  localStorage.removeItem('websecpen_onboarding_completed');
};

export default Onboarding; 