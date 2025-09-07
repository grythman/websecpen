// Enhanced Authentication Service
import apiService from './api.js';

class AuthService {
  constructor() {
    this.user = null;
    this.token = localStorage.getItem('auth_token');
    this.listeners = [];
  }

  // Subscribe to auth state changes
  subscribe(callback) {
    this.listeners.push(callback);
    return () => {
      this.listeners = this.listeners.filter(listener => listener !== callback);
    };
  }

  // Notify all listeners of auth state change
  notifyListeners() {
    this.listeners.forEach(callback => callback(this.user));
  }

  // Check if user is authenticated
  isAuthenticated() {
    return !!this.token && !!this.user;
  }

  // Get current user
  getCurrentUser() {
    return this.user;
  }

  // Internal helper to clear auth state
  clearAuth({ notify = true } = {}) {
    this.token = null;
    this.user = null;
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user');
    apiService.removeToken();
    if (notify) this.notifyListeners();
  }

  // Login user
  async login(email, password) {
    try {
      const response = await apiService.login(email, password);
      
      if (response.access_token) {
        this.token = response.access_token;
        this.user = response.user;
        
        // Store in localStorage
        localStorage.setItem('auth_token', this.token);
        localStorage.setItem('user', JSON.stringify(this.user));
        
        this.notifyListeners();
        return { success: true, user: this.user };
      }
      
      throw new Error('Invalid response from server');
    } catch (error) {
      console.error('Login failed:', error);
      return { success: false, error: error.message };
    }
  }

  // Register new user
  async register(userData) {
    try {
      const response = await apiService.register(userData);
      return { success: true, data: response };
    } catch (error) {
      console.error('Registration failed:', error);
      return { success: false, error: error.message };
    }
  }

  // Logout user
  async logout() {
    try {
      this.clearAuth({ notify: true });
      return { success: true };
    } catch (error) {
      console.error('Logout failed:', error);
      return { success: false, error: error.message };
    }
  }

  // Initialize auth state from localStorage
  async initializeAuth() {
    try {
      const storedToken = localStorage.getItem('auth_token');
      const storedUser = localStorage.getItem('user');
      
      if (storedToken && storedUser) {
        try {
        this.token = storedToken;
        this.user = JSON.parse(storedUser);
        apiService.setToken(storedToken);
        
          // Notify listeners immediately with stored data
          this.notifyListeners();
          
          // Verify token is still valid and refresh user data
        try {
            const profileResponse = await apiService.getProfile();
            this.user = profileResponse.user || profileResponse;
          localStorage.setItem('user', JSON.stringify(this.user));
          this.notifyListeners();
          return true;
        } catch (error) {
            console.warn('Token validation failed during init, clearing stored token');
            // Clear silently to avoid racing a concurrent login
            this.clearAuth({ notify: false });
            return false;
          }
        } catch (parseError) {
          console.error('Failed to parse stored user data:', parseError);
          this.clearAuth({ notify: false });
          return false;
        }
      }
      
      return false;
    } catch (error) {
      console.error('Auth initialization failed:', error);
      this.clearAuth({ notify: false });
      return false;
    }
  }

  // Update user profile
  async updateProfile(profileData) {
    try {
      // This would be implemented in the backend
      return { success: true };
    } catch (error) {
      console.error('Profile update failed:', error);
      return { success: false, error: error.message };
    }
  }

  // Change password
  async changePassword(currentPassword, newPassword) {
    try {
      // This would be implemented in the backend
      return { success: true };
    } catch (error) {
      console.error('Password change failed:', error);
      return { success: false, error: error.message };
    }
  }

  // MFA methods
  async setupMFA() {
    try {
      const response = await apiService.setupMFA();
      return { success: true, data: response };
    } catch (error) {
      console.error('MFA setup failed:', error);
      return { success: false, error: error.message };
    }
  }

  async verifyMFA(token) {
    try {
      const response = await apiService.verifyMFA(token);
      return { success: true, data: response };
    } catch (error) {
      console.error('MFA verification failed:', error);
      return { success: false, error: error.message };
    }
  }

  async disableMFA() {
    try {
      await apiService.disableMFA();
      return { success: true };
    } catch (error) {
      console.error('MFA disable failed:', error);
      return { success: false, error: error.message };
    }
  }

  // Permission checking
  hasPermission(permission) {
    if (!this.user) return false;
    
    // Admin has all permissions
    if (this.user.role === 'admin') return true;
    
    // Check specific permissions
    const permissions = this.user.permissions || [];
    return permissions.includes(permission);
  }

  // Role checking
  hasRole(role) {
    if (!this.user) return false;
    return this.user.role === role;
  }

  // Check if user is admin
  isAdmin() {
    return this.hasRole('admin');
  }
}

// Create and export singleton instance
const authService = new AuthService();
export default authService; 
// Create and export singleton instance
const authService = new AuthService();
export default authService; 