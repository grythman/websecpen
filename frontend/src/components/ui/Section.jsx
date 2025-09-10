import React from 'react';
import './Section.css';

const Section = ({ title, actions = null, children }) => {
  return (
    <section className="section">
      {(title || actions) && (
        <div className="section-header">
          {title && <h3 className="section-title">{title}</h3>}
          {actions && <div className="section-actions">{actions}</div>}
        </div>
      )}
      <div className="section-body">
        {children}
      </div>
    </section>
  );
};

export default Section; 