import React, { useState, useEffect } from 'react';
import './ReportTemplate.css';

const ReportTemplate = ({ scanId }) => {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newTemplate, setNewTemplate] = useState({
    name: '',
    description: '',
    template_config: {
      title: '',
      fields: [],
      show_charts: true,
      include_summary: true,
      group_by_severity: false,
      group_by_type: false,
      include_methodology: false,
      include_compliance: false
    }
  });
  const [message, setMessage] = useState('');

  const availableFields = [
    { value: 'name', label: 'Vulnerability Name', description: 'Name of the vulnerability' },
    { value: 'severity', label: 'Severity Level', description: 'Risk level (High, Medium, Low)' },
    { value: 'desc', label: 'Description', description: 'Detailed vulnerability description' },
    { value: 'solution', label: 'Solution', description: 'Remediation guidance' },
    { value: 'reference', label: 'References', description: 'External references and links' },
    { value: 'evidence', label: 'Evidence', description: 'Proof of concept or evidence' },
    { value: 'url', label: 'Affected URL', description: 'Specific URL where vulnerability was found' },
    { value: 'cweid', label: 'CWE ID', description: 'Common Weakness Enumeration ID' },
    { value: 'wascid', label: 'WASC ID', description: 'Web Application Security Consortium ID' },
    { value: 'confidence', label: 'Confidence Level', description: 'Scanner confidence in finding' }
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
        setTemplates(data.templates || []);
      }
    } catch (error) {
      console.error('Error fetching templates:', error);
      setMessage('Failed to load templates');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTemplate = async (e) => {
    e.preventDefault();
    
    if (!newTemplate.name.trim()) {
      setMessage('Template name is required');
      return;
    }

    if (newTemplate.template_config.fields.length === 0) {
      setMessage('Please select at least one field');
      return;
    }

    setLoading(true);
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

      const data = await response.json();

      if (response.ok) {
        setMessage('Template created successfully!');
        setShowCreateForm(false);
        setNewTemplate({
          name: '',
          description: '',
          template_config: {
            title: '',
            fields: [],
            show_charts: true,
            include_summary: true,
            group_by_severity: false,
            group_by_type: false,
            include_methodology: false,
            include_compliance: false
          }
        });
        fetchTemplates();
      } else {
        setMessage(data.error || 'Failed to create template');
      }
    } catch (error) {
      setMessage('Error creating template');
      console.error('Template creation error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async (templateId) => {
    if (!scanId) {
      setMessage('No scan selected');
      return;
    }

    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/scan/${scanId}/report/custom/${templateId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `scan_${scanId}_custom_report.pdf`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
        setMessage('Report generated successfully!');
      } else {
        const data = await response.json();
        setMessage(data.error || 'Failed to generate report');
      }
    } catch (error) {
      setMessage('Error generating report');
      console.error('Report generation error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFieldToggle = (fieldValue) => {
    const currentFields = newTemplate.template_config.fields;
    const updatedFields = currentFields.includes(fieldValue)
      ? currentFields.filter(f => f !== fieldValue)
      : [...currentFields, fieldValue];

    setNewTemplate({
      ...newTemplate,
      template_config: {
        ...newTemplate.template_config,
        fields: updatedFields
      }
    });
  };

  const handleConfigChange = (key, value) => {
    setNewTemplate({
      ...newTemplate,
      template_config: {
        ...newTemplate.template_config,
        [key]: value
      }
    });
  };

  return (
    <div className="report-template">
      <div className="template-header">
        <h3>📊 Custom Report Templates</h3>
        <button 
          onClick={() => setShowCreateForm(!showCreateForm)}
          className="create-template-btn"
        >
          {showCreateForm ? '❌ Cancel' : '➕ Create Template'}
        </button>
      </div>

      {message && (
        <div className={`template-message ${message.includes('successfully') ? 'success' : 'error'}`}>
          {message}
        </div>
      )}

      {/* Create Template Form */}
      {showCreateForm && (
        <div className="create-template-form">
          <h4>Create New Template</h4>
          <form onSubmit={handleCreateTemplate}>
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="template-name">Template Name *</label>
                <input
                  id="template-name"
                  type="text"
                  value={newTemplate.name}
                  onChange={(e) => setNewTemplate({ ...newTemplate, name: e.target.value })}
                  placeholder="e.g., Executive Summary"
                  disabled={loading}
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="template-title">Report Title</label>
                <input
                  id="template-title"
                  type="text"
                  value={newTemplate.template_config.title}
                  onChange={(e) => handleConfigChange('title', e.target.value)}
                  placeholder="e.g., Security Assessment Report"
                  disabled={loading}
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="template-description">Description</label>
              <textarea
                id="template-description"
                value={newTemplate.description}
                onChange={(e) => setNewTemplate({ ...newTemplate, description: e.target.value })}
                placeholder="Brief description of this template's purpose"
                disabled={loading}
                rows={3}
              />
            </div>

            {/* Field Selection */}
            <div className="form-group">
              <label>Report Fields *</label>
              <div className="field-selection">
                {availableFields.map((field) => (
                  <div key={field.value} className="field-option">
                    <label className="field-checkbox">
                      <input
                        type="checkbox"
                        checked={newTemplate.template_config.fields.includes(field.value)}
                        onChange={() => handleFieldToggle(field.value)}
                        disabled={loading}
                      />
                      <div className="field-info">
                        <span className="field-label">{field.label}</span>
                        <small className="field-description">{field.description}</small>
                      </div>
                    </label>
                  </div>
                ))}
              </div>
            </div>

            {/* Template Options */}
            <div className="form-group">
              <label>Template Options</label>
              <div className="template-options">
                <label className="option-checkbox">
                  <input
                    type="checkbox"
                    checked={newTemplate.template_config.include_summary}
                    onChange={(e) => handleConfigChange('include_summary', e.target.checked)}
                    disabled={loading}
                  />
                  <span>Include Executive Summary</span>
                </label>

                <label className="option-checkbox">
                  <input
                    type="checkbox"
                    checked={newTemplate.template_config.include_methodology}
                    onChange={(e) => handleConfigChange('include_methodology', e.target.checked)}
                    disabled={loading}
                  />
                  <span>Include Testing Methodology</span>
                </label>

                <label className="option-checkbox">
                  <input
                    type="checkbox"
                    checked={newTemplate.template_config.group_by_severity}
                    onChange={(e) => handleConfigChange('group_by_severity', e.target.checked)}
                    disabled={loading}
                  />
                  <span>Group by Severity</span>
                </label>

                <label className="option-checkbox">
                  <input
                    type="checkbox"
                    checked={newTemplate.template_config.group_by_type}
                    onChange={(e) => handleConfigChange('group_by_type', e.target.checked)}
                    disabled={loading}
                  />
                  <span>Group by Vulnerability Type</span>
                </label>
              </div>
            </div>

            <div className="form-actions">
              <button
                type="submit"
                disabled={loading || newTemplate.template_config.fields.length === 0}
                className="submit-btn"
              >
                {loading ? 'Creating...' : 'Create Template'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Templates List */}
      <div className="templates-list">
        {loading && !showCreateForm ? (
          <div className="loading-spinner">
            <div className="spinner"></div>
            <p>Loading templates...</p>
          </div>
        ) : (
          <>
            {templates.length === 0 ? (
              <div className="no-templates">
                <p>No templates found. Create your first template to get started!</p>
              </div>
            ) : (
              <div className="templates-grid">
                {templates.map((template) => (
                  <div key={template.id} className="template-card">
                    <div className="template-info">
                      <h4 className="template-name">
                        {template.name}
                        {template.is_default && <span className="default-badge">Default</span>}
                      </h4>
                      {template.description && (
                        <p className="template-description">{template.description}</p>
                      )}
                      
                      <div className="template-details">
                        <div className="template-config">
                          <strong>Fields:</strong>
                          <span className="field-count">
                            {template.template_config?.fields?.length || 0} selected
                          </span>
                        </div>
                        
                        {template.template_config?.title && (
                          <div className="template-config">
                            <strong>Title:</strong>
                            <span>{template.template_config.title}</span>
                          </div>
                        )}

                        <div className="template-features">
                          {template.template_config?.include_summary && (
                            <span className="feature-tag">Summary</span>
                          )}
                          {template.template_config?.include_methodology && (
                            <span className="feature-tag">Methodology</span>
                          )}
                          {template.template_config?.group_by_severity && (
                            <span className="feature-tag">Grouped by Severity</span>
                          )}
                          {template.template_config?.group_by_type && (
                            <span className="feature-tag">Grouped by Type</span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="template-actions">
                      <button
                        onClick={() => handleGenerateReport(template.id)}
                        disabled={loading || !scanId}
                        className="generate-btn"
                        title={!scanId ? 'Select a scan to generate report' : 'Generate PDF report'}
                      >
                        {loading ? 'Generating...' : '📄 Generate PDF'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {/* Usage Tips */}
      <div className="usage-tips">
        <h4>💡 Template Tips</h4>
        <ul>
          <li><strong>Executive Summary:</strong> Include high-level overview and statistics</li>
          <li><strong>Technical Report:</strong> Include detailed descriptions and evidence</li>
          <li><strong>Compliance Report:</strong> Focus on CWE/WASC IDs and remediation</li>
          <li><strong>Group by Severity:</strong> Organize findings from high to low risk</li>
          <li><strong>Group by Type:</strong> Organize findings by vulnerability category</li>
        </ul>
      </div>
    </div>
  );
};

export default ReportTemplate; 