// src/components/LanguageSwitcher.jsx - Reusable Language Switcher Component
import React from 'react';
import { useTranslation } from 'react-i18next';
import './LanguageSwitcher.css';

const LanguageSwitcher = ({ position = 'fixed', size = 'normal', className = '' }) => {
  const { i18n } = useTranslation();

  const changeLanguage = (lng) => {
    i18n.changeLanguage(lng);
    localStorage.setItem('websecpen_language', lng);
  };

  const languages = [
    { code: 'en', name: 'English', flag: '🇺🇸', short: 'EN' },
    { code: 'mn', name: 'Монгол', flag: '🇲🇳', short: 'МН' }
  ];

  return (
    <div className={`language-switcher-container ${position} ${size} ${className}`}>
      {languages.map((lang) => (
        <button
          key={lang.code}
          className={`lang-switch-btn ${i18n.language === lang.code ? 'active' : ''}`}
          onClick={() => changeLanguage(lang.code)}
          title={lang.name}
        >
          <span className="flag">{lang.flag}</span>
          <span className="short">{lang.short}</span>
        </button>
      ))}
    </div>
  );
};

export default LanguageSwitcher; 
