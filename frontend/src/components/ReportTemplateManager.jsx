import React, { useState, useEffect } from 'react';
import './ReportTemplateManager.css';

const ReportTemplateManager = ({ scanId, onClose }) => {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(false);
  const [createMode, setCreateMode] = useState(false);
  const [newTemplate, setNewTemplate] = useState({
    name: '',
    template: {
      title: '',
      fields: [],
      includeExecutiveSummary: true,
      includeRecommendations: true,
      includeTechnicalDetails: true
    }
  });

  const availableFields = [
    { key: 'name', label: 'Vulnerability Name', description: 'The name/title of the vulnerability' },
    { key: 'risk', label: 'Risk Level', description: 'High, Medium, Low risk classification' },
    { key: 'confidence', label: 'Confidence', description: 'Scanner confidence in the finding' },
    { key: 'url', label: 'Affected URL', description: 'The specific URL where vulnerability was found' },
    { key: 'param', label: 'Parameter', description: 'The vulnerable parameter or input' },
    { key: 'desc', label: 'Description', description: 'Detailed description of the vulnerability' },
    { key: 'solution', label: 'Solution', description: 'Recommended fix or mitigation' },
    { key: 'reference', label: 'References', description: 'External references and links' },
    { key: 'evidence', label: 'Evidence', description: 'Proof of concept or evidence' },
    { key: 'attack', label: 'Attack Vector', description: 'How the vulnerability can be exploited' }
  ];

  useEffect(() => {
    fetchTemplates();
  }, []);

  const fetchTemplates = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/report/templates', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setTemplates(data);
      } else {
        console.error('Failed to fetch templates');
      }
    } catch (error) {
      console.error('Error fetching templates:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTemplate = async () => {
    if (!newTemplate.name.trim() || newTemplate.template.fields.length === 0) {
      alert('Please provide a template name and select at least one field.');
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/report/templates', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newTemplate)
      });

      if (response.ok) {
        const result = await response.json();
        alert('Template created successfully!');
        setCreateMode(false);
        setNewTemplate({
          name: '',
          template: {
            title: '',
            fields: [],
            includeExecutiveSummary: true,
            includeRecommendations: true,
            includeTechnicalDetails: true
          }
        });
        fetchTemplates();
      } else {
        const errorData = await response.json();
        alert(`Failed to create template: ${errorData.error}`);
      }
    } catch (error) {
      console.error('Error creating template:', error);
      alert('Failed to create template. Please try again.');
    }
  };

  const handleGenerateReport = async (templateId, templateName) => {
    if (!scanId) {
      alert('No scan ID provided');
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/scan/${scanId}/report/custom/${templateId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        // Download the PDF
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `scan_${scanId}_${templateName.replace(/\s+/g, '_')}.pdf`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      } else {
        const errorData = await response.json();
        alert(`Failed to generate report: ${errorData.error}`);
      }
    } catch (error) {
      console.error('Error generating report:', error);
      alert('Failed to generate report. Please try again.');
    }
  };

  const handleFieldToggle = (fieldKey) => {
    setNewTemplate(prev => ({
      ...prev,
      template: {
        ...prev.template,
        fields: prev.template.fields.includes(fieldKey)
          ? prev.template.fields.filter(f => f !== fieldKey)
          : [...prev.template.fields, fieldKey]
      }
    }));
  };

  const getDefaultTemplates = () => [
    {
      id: 'executive',
      name: 'Executive Summary',
      description: 'High-level overview for executives and management',
      fields: ['name', 'risk', 'desc', 'solution'],
      isDefault: true
    },
    {
      id: 'technical',
      name: 'Technical Report',
      description: 'Detailed technical information for developers',
      fields: ['name', 'risk', 'confidence', 'url', 'param', 'desc', 'evidence', 'attack', 'solution', 'reference'],
      isDefault: true
    },
    {
      id: 'compliance',
      name: 'Compliance Report',
      description: 'Focused on regulatory compliance requirements',
      fields: ['name', 'risk', 'desc', 'solution', 'reference'],
      isDefault: true
    }
  ];

  if (loading) {
    return (
      <div className="report-template-modal">
        <div className="report-template-content loading">
          <div className="loading-spinner">
            <div className="spinner"></div>
            <p>Loading templates...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="report-template-modal">
      <div className="report-template-content">
        <div className="template-header">
          <h2>📄 Custom Report Templates</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="template-tabs">
          <button
            className={`tab-btn ${!createMode ? 'active' : ''}`}
            onClick={() => setCreateMode(false)}
          >
            📋 Use Templates
          </button>
          <button
            className={`tab-btn ${createMode ? 'active' : ''}`}
            onClick={() => setCreateMode(true)}
          >
            ➕ Create Template
          </button>
        </div>

        <div className="template-body">
          {!createMode ? (
            <div className="templates-list">
              <div className="section">
                <h3>🏗️ Default Templates</h3>
                <div className="templates-grid">
                  {getDefaultTemplates().map((template) => (
                    <div key={template.id} className="template-card default">
                      <div className="template-card-header">
                        <h4>{template.name}</h4>
                        <span className="default-badge">Default</span>
                      </div>
                      <p className="template-description">{template.description}</p>
                      <div className="template-fields">
                        <strong>Includes:</strong>
                        <div className="field-tags">
                          {template.fields.slice(0, 3).map(field => (
                            <span key={field} className="field-tag">
                              {availableFields.find(f => f.key === field)?.label || field}
                            </span>
                          ))}
                          {template.fields.length > 3 && (
                            <span className="field-tag more">+{template.fields.length - 3} more</span>
                          )}
                        </div>
                      </div>
                      <button
                        className="generate-btn"
                        onClick={() => handleGenerateReport(template.id, template.name)}
                      >
                        📄 Generate Report
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {templates.length > 0 && (
                <div className="section">
                  <h3>🎨 Custom Templates</h3>
                  <div className="templates-grid">
                    {templates.map((template) => (
                      <div key={template.id} className="template-card custom">
                        <div className="template-card-header">
                          <h4>{template.name}</h4>
                          <span className="custom-badge">Custom</span>
                        </div>
                        <div className="template-meta">
                          <span>Created: {new Date(template.created_at).toLocaleDateString()}</span>
                        </div>
                        <div className="template-fields">
                          <strong>Includes:</strong>
                          <div className="field-tags">
                            {template.template.fields.slice(0, 3).map(field => (
                              <span key={field} className="field-tag">
                                {availableFields.find(f => f.key === field)?.label || field}
                              </span>
                            ))}
                            {template.template.fields.length > 3 && (
                              <span className="field-tag more">+{template.template.fields.length - 3} more</span>
                            )}
                          </div>
                        </div>
                        <button
                          className="generate-btn"
                          onClick={() => handleGenerateReport(template.id, template.name)}
                        >
                          📄 Generate Report
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="create-template">
              <h3>✨ Create Custom Template</h3>
              
              <div className="form-section">
                <label htmlFor="template-name">Template Name</label>
                <input
                  id="template-name"
                  type="text"
                  value={newTemplate.name}
                  onChange={(e) => setNewTemplate(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="e.g., Security Assessment Report"
                  className="template-input"
                />
              </div>

              <div className="form-section">
                <label htmlFor="template-title">Report Title</label>
                <input
                  id="template-title"
                  type="text"
                  value={newTemplate.template.title}
                  onChange={(e) => setNewTemplate(prev => ({
                    ...prev,
                    template: { ...prev.template, title: e.target.value }
                  }))}
                  placeholder="e.g., Security Vulnerability Assessment"
                  className="template-input"
                />
              </div>

              <div className="form-section">
                <label>Report Sections</label>
                <div className="sections-options">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={newTemplate.template.includeExecutiveSummary}
                      onChange={(e) => setNewTemplate(prev => ({
                        ...prev,
                        template: { ...prev.template, includeExecutiveSummary: e.target.checked }
                      }))}
                    />
                    <span>Executive Summary</span>
                  </label>
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={newTemplate.template.includeTechnicalDetails}
                      onChange={(e) => setNewTemplate(prev => ({
                        ...prev,
                        template: { ...prev.template, includeTechnicalDetails: e.target.checked }
                      }))}
                    />
                    <span>Technical Details</span>
                  </label>
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={newTemplate.template.includeRecommendations}
                      onChange={(e) => setNewTemplate(prev => ({
                        ...prev,
                        template: { ...prev.template, includeRecommendations: e.target.checked }
                      }))}
                    />
                    <span>Recommendations</span>
                  </label>
                </div>
              </div>

              <div className="form-section">
                <label>Vulnerability Fields to Include</label>
                <div className="fields-grid">
                  {availableFields.map((field) => (
                    <div key={field.key} className="field-option">
                      <label className="field-checkbox">
                        <input
                          type="checkbox"
                          checked={newTemplate.template.fields.includes(field.key)}
                          onChange={() => handleFieldToggle(field.key)}
                        />
                        <div className="field-info">
                          <span className="field-label">{field.label}</span>
                          <span className="field-description">{field.description}</span>
                        </div>
                      </label>
                    </div>
                  ))}
                </div>
              </div>

              <div className="form-actions">
                <button
                  className="cancel-btn"
                  onClick={() => setCreateMode(false)}
                >
                  Cancel
                </button>
                <button
                  className="create-btn"
                  onClick={handleCreateTemplate}
                  disabled={!newTemplate.name.trim() || newTemplate.template.fields.length === 0}
                >
                  ✨ Create Template
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ReportTemplateManager; 