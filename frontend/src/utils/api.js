// src/utils/api.js - Centralized API Management with JWT & Session Handling
const API_BASE_URL = 'http://localhost:5000';

class ApiService {
  constructor() {
    this.baseURL = API_BASE_URL;
  }

  // Get JWT token from localStorage
  getToken() {
    return localStorage.getItem('authToken');
  }

  // Set JWT token in localStorage
  setToken(token) {
    localStorage.setItem('authToken', token);
  }

  // Remove JWT token
  removeToken() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('isAuthenticated');
  }

  // Check if user is authenticated
  isAuthenticated() {
    const token = this.getToken();
    if (!token) return false;
    
    try {
      // Basic JWT expiry check (decode without verification)
      const payload = JSON.parse(atob(token.split('.')[1]));
      const currentTime = Date.now() / 1000;
      
      if (payload.exp < currentTime) {
        this.removeToken();
        return false;
      }
      
      return true;
    } catch (error) {
      this.removeToken();
      return false;
    }
  }

  // Get headers with authorization
  getHeaders() {
    const headers = {
      'Content-Type': 'application/json',
    };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    return headers;
  }

  // Handle API response
  async handleResponse(response) {
    const data = await response.json();

    if (!response.ok) {
      // Handle specific error cases
      if (response.status === 401) {
        this.removeToken();
        window.dispatchEvent(new CustomEvent('auth:logout'));
        throw new Error('Session expired. Please log in again.');
      } else if (response.status === 403) {
        throw new Error('Access denied. Insufficient permissions.');
      } else if (response.status === 404) {
        throw new Error('Resource not found.');
      } else if (response.status >= 500) {
        throw new Error('Server error. Please try again later.');
      } else {
        throw new Error(data.error || `Request failed with status ${response.status}`);
      }
    }

    return data;
  }

  // Generic request method
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: this.getHeaders(),
      ...options,
    };

    try {
      const response = await fetch(url, config);
      return await this.handleResponse(response);
    } catch (error) {
      console.error(`API request failed: ${endpoint}`, error);
      throw error;
    }
  }

  // Authentication methods
  async login(credentials) {
    const data = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });

    if (data.access_token) {
      this.setToken(data.access_token);
      localStorage.setItem('isAuthenticated', 'true');
    }

    return data;
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

  logout() {
    this.removeToken();
    window.dispatchEvent(new CustomEvent('auth:logout'));
  }

  // Scan methods
  async startScan(scanData) {
    return await this.request('/scan/start', {
      method: 'POST',
      body: JSON.stringify(scanData),
    });
  }

  async getScanStatus(scanId) {
    return await this.request(`/scan/status/${scanId}`);
  }

  async getScanResult(scanId) {
    return await this.request(`/scan/result/${scanId}`);
  }

  async getNLPAnalysis(scanId) {
    return await this.request(`/scan/analyze/${scanId}`);
  }

  async getAllScans() {
    return await this.request('/scans');
  }

  async deleteScan(scanId) {
    return await this.request(`/scan/${scanId}`, {
      method: 'DELETE',
    });
  }

  // Health check
  async healthCheck() {
    return await this.request('/health');
  }
}

// Create and export singleton instance
const apiService = new ApiService();
export default apiService;

// Export specific methods for convenience
export const {
  login,
  register,
  getProfile,
  logout,
  startScan,
  getScanStatus,
  getScanResult,
  getNLPAnalysis,
  getAllScans,
  deleteScan,
  healthCheck,
  isAuthenticated,
} = apiService; 