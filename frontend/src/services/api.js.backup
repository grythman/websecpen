// WebSecPen API Service
// Enhanced integration with all backend endpoints

const API_BASE_URL = 'http://localhost:5000';

class ApiService {
  constructor() {
    this.baseURL = API_BASE_URL;
    this.token = localStorage.getItem('auth_token');
  }

  // Set authentication token
  setToken(token) {
    this.token = token;
    localStorage.setItem('auth_token', token);
  }

  // Remove authentication token
  removeToken() {
    this.token = null;
    localStorage.removeItem('auth_token');
  }

  // Generic request method
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    // Add authorization header if token exists
    if (this.token) {
      config.headers.Authorization = `Bearer ${this.token}`;
    }

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }
      
      return response;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  // Authentication endpoints
  async login(email, password) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    
    if (response.access_token) {
      this.setToken(response.access_token);
    }
    
    return response;
  }

  async register(userData) {
    return await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  }

  async getProfile() {
    return await this.request('/auth/profile');
  }

  // Health check
  async getHealth() {
    const response = await fetch(`${this.baseURL}/health`);
    return await response.json();
  }

  // Mock endpoints for missing functionality
  async getScanPresets() {
    return {
      presets: [
        { id: 1, name: 'Quick Scan', description: 'Basic security scan' },
        { id: 2, name: 'Full Scan', description: 'Comprehensive security scan' },
        { id: 3, name: 'Custom Scan', description: 'Customized security scan' }
      ]
    };
  }

  async getScanProgress(scanId) {
    return {
      scanId: scanId || 'undefined',
      status: 'completed',
      progress: 100,
      results: []
    };
  }

  async getScanTrends(days = 30) {
    return {
      trends: [],
      period: `${days} days`
    };
  }

  async getScanSeverity() {
    return {
      severity: {
        high: 0,
        medium: 0,
        low: 0
      }
    };
  }

  async getReportTemplates() {
    return {
      templates: [
        { id: 1, name: 'Executive Summary', description: 'High-level security report' },
        { id: 2, name: 'Technical Report', description: 'Detailed technical findings' },
        { id: 3, name: 'Compliance Report', description: 'Compliance-focused report' }
      ]
    };
  }

  async getScanAnnotations(scanId) {
    return {
      scanId: scanId || 'undefined',
      annotations: []
    };
  }

  async getMfaStatus() {
    return {
      enabled: false,
      methods: []
    };
  }

  async getNotificationSettings() {
    return {
      email: true,
      push: false,
      sms: false
    };
  }

  async getApiKeys() {
    return {
      keys: []
    };
  }

  async getAdminFeedbackSummary() {
    return {
      summary: {
        total: 0,
        open: 0,
        closed: 0
      }
    };
  }

  async getAdminFeedbackAnalyze() {
    return {
      analysis: {
        trends: [],
        categories: []
      }
    };
  }

  async getAdminUsers(page = 1, perPage = 20) {
    return {
      users: [],
      total: 0,
      page: page,
      perPage: perPage
    };
  }

  async getAdminSnykResults() {
    return {
      results: []
    };
  }

  async getAdminFeedback() {
    return {
      feedback: []
    };
  }

  async getAdminHeatmap(days = 7) {
    return {
      heatmap: [],
      period: `${days} days`
    };
  }

  async getAdminAnalyticsEndpoints(days = 7) {
    return {
      endpoints: [],
      period: `${days} days`
    };
  }

  async getVulnerabilityTags(scanId, vulnId) {
    return {
      scanId: scanId || 'undefined',
      vulnId: vulnId || 'undefined',
      tags: []
    };
  }
}

export default new ApiService();
