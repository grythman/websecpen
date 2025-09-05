// WebSecPen API Service
// Enhanced integration with all backend endpoints

const API_BASE_URL = 'http://localhost:5000/api';

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
    const response = await fetch(`${this.baseURL.replace('/api', '')}/health`);
    return await response.json();
  }

  // Scan management
  async startScan(scanData) {
    return await this.request('/scan/start', {
      method: 'POST',
      body: JSON.stringify(scanData),
    });
  }

  async getScanResult(scanId) {
    return await this.request(`/scan/result/${scanId}`);
  }

  async getScanStatus(scanId) {
    return await this.request(`/scan/status/${scanId}`);
  }

  async getAllScans() {
    return await this.request('/scans');
  }

  // Advanced Analytics
  async getAnalytics() {
    return await this.request('/analytics');
  }

  async getScanStats() {
    return await this.request('/analytics/scan-stats');
  }

  async getVulnTrends() {
    return await this.request('/analytics/vuln-trends');
  }

  async getComplianceMetrics() {
    return await this.request('/analytics/compliance-metrics');
  }

  // Custom Reports
  async getReports() {
    return await this.request('/reports');
  }

  async createReport(reportData) {
    return await this.request('/reports', {
      method: 'POST',
      body: JSON.stringify(reportData),
    });
  }

  async generateReport(reportId) {
    return await this.request(`/reports/${reportId}/generate`, {
      method: 'POST',
    });
  }

  // MFA Management
  async setupMFA() {
    return await this.request('/mfa/setup', {
      method: 'POST',
    });
  }

  async verifyMFA(token) {
    return await this.request('/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  async disableMFA() {
    return await this.request('/mfa/disable', {
      method: 'DELETE',
    });
  }

  // Notifications
  async getNotifications() {
    return await this.request('/notifications');
  }

  async markNotificationRead(notificationId) {
    return await this.request(`/notifications/${notificationId}/read`, {
      method: 'POST',
    });
  }

  // API Key Management
  async getApiKeys() {
    return await this.request('/api-keys');
  }

  async createApiKey(keyData) {
    return await this.request('/api-keys', {
      method: 'POST',
      body: JSON.stringify(keyData),
    });
  }

  async revokeApiKey(keyId) {
    return await this.request(`/api-keys/${keyId}`, {
      method: 'DELETE',
    });
  }

  // Team Collaboration
  async getTeamMembers() {
    return await this.request('/team/members');
  }

  async inviteTeamMember(email, role) {
    return await this.request('/team/invite', {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    });
  }

  async removeTeamMember(userId) {
    return await this.request(`/team/members/${userId}`, {
      method: 'DELETE',
    });
  }

  // Vulnerability Management
  async getVulnerabilities(filters = {}) {
    const queryString = new URLSearchParams(filters).toString();
    return await this.request(`/vulnerabilities?${queryString}`);
  }

  async updateVulnerabilityStatus(vulnId, status) {
    return await this.request(`/vulnerabilities/${vulnId}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status }),
    });
  }

  // Export functionality
  async exportScanResults(scanId, format = 'pdf') {
    const response = await this.request(`/scan/report/${scanId}/${format}`);
    return response;
  }

  // Integrations
  async getIntegrations() {
    return await this.request('/integrations');
  }

  async configureIntegration(integrationType, config) {
    return await this.request(`/integrations/${integrationType}`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  // Dashboard data
  async getDashboardData() {
    return await this.request('/dashboard');
  }

  async getRecentActivity() {
    return await this.request('/dashboard/activity');
  }

  // Settings
  async getSettings() {
    return await this.request('/settings');
  }

  async updateSettings(settings) {
    return await this.request('/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  }
}

// Create and export a singleton instance
const apiService = new ApiService();
export default apiService;

// Named exports for specific functionality
export const {
  login,
  register,
  getProfile,
  getHealth,
  startScan,
  getScanResult,
  getScanStatus,
  getAllScans,
  getAnalytics,
  getScanStats,
  getVulnTrends,
  getComplianceMetrics,
  getReports,
  createReport,
  generateReport,
  setupMFA,
  verifyMFA,
  disableMFA,
  getNotifications,
  markNotificationRead,
  getApiKeys,
  createApiKey,
  revokeApiKey,
  getTeamMembers,
  inviteTeamMember,
  removeTeamMember,
  getVulnerabilities,
  updateVulnerabilityStatus,
  exportScanResults,
  getIntegrations,
  configureIntegration,
  getDashboardData,
  getRecentActivity,
  getSettings,
  updateSettings,
} = apiService; 