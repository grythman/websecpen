// Enhanced Authentication Context for React
import React, { createContext, useContext, useReducer, useEffect } from 'react';
import authService from '../services/auth.js';

// Auth action types
const AUTH_ACTIONS = {
  LOGIN_START: 'LOGIN_START',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  REGISTER_START: 'REGISTER_START',
  REGISTER_SUCCESS: 'REGISTER_SUCCESS',
  REGISTER_FAILURE: 'REGISTER_FAILURE',
  UPDATE_USER: 'UPDATE_USER',
  SET_LOADING: 'SET_LOADING',
  CLEAR_ERROR: 'CLEAR_ERROR',
};

// Initial auth state
const initialState = {
  user: null,
  token: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
  isLoginLoading: false,
  isRegisterLoading: false,
};

// Auth reducer
function authReducer(state, action) {
  switch (action.type) {
    case AUTH_ACTIONS.LOGIN_START:
      return {
        ...state,
        isLoginLoading: true,
        error: null,
      };

    case AUTH_ACTIONS.LOGIN_SUCCESS:
      return {
        ...state,
        user: action.payload.user,
        token: action.payload.token,
        isAuthenticated: true,
        isLoginLoading: false,
        error: null,
      };

    case AUTH_ACTIONS.LOGIN_FAILURE:
      return {
        ...state,
        user: null,
        token: null,
        isAuthenticated: false,
        isLoginLoading: false,
        error: action.payload.error,
      };

    case AUTH_ACTIONS.LOGOUT:
      return {
        ...state,
        user: null,
        token: null,
        isAuthenticated: false,
        error: null,
      };

    case AUTH_ACTIONS.REGISTER_START:
      return {
        ...state,
        isRegisterLoading: true,
        error: null,
      };

    case AUTH_ACTIONS.REGISTER_SUCCESS:
      return {
        ...state,
        isRegisterLoading: false,
        error: null,
      };

    case AUTH_ACTIONS.REGISTER_FAILURE:
      return {
        ...state,
        isRegisterLoading: false,
        error: action.payload.error,
      };

    case AUTH_ACTIONS.UPDATE_USER:
      return {
        ...state,
        user: { ...state.user, ...action.payload.user },
      };

    case AUTH_ACTIONS.SET_LOADING:
      return {
        ...state,
        isLoading: action.payload.loading,
      };

    case AUTH_ACTIONS.CLEAR_ERROR:
      return {
        ...state,
        error: null,
      };

    default:
      return state;
  }
}

// Create context
const AuthContext = createContext();

// Auth provider component
export function AuthProvider({ children }) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Initialize auth on mount
  useEffect(() => {
    let didInit = false;
    const initializeAuth = async () => {
      if (didInit) return; // avoid double init in StrictMode
      didInit = true;
      dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: { loading: true } });
      
      try {
        const isAuthenticated = await authService.initializeAuth();
        
        if (isAuthenticated) {
          const user = authService.getCurrentUser();
          const token = localStorage.getItem('auth_token');
          
          dispatch({
            type: AUTH_ACTIONS.LOGIN_SUCCESS,
            payload: { user, token },
          });
        }
      } catch (error) {
        console.error('Auth initialization failed:', error);
      } finally {
        dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: { loading: false } });
      }
    };

    initializeAuth();

    // Subscribe to auth service changes
    const unsubscribe = authService.subscribe((user) => {
      if (user) {
        dispatch({
          type: AUTH_ACTIONS.UPDATE_USER,
          payload: { user },
        });
      } else {
        dispatch({ type: AUTH_ACTIONS.LOGOUT });
      }
    });

    return unsubscribe;
  }, []);

  // Login function
  const login = async (email, password) => {
    dispatch({ type: AUTH_ACTIONS.LOGIN_START });
    
    try {
      const result = await authService.login(email, password);
      
      if (result.success) {
        dispatch({
          type: AUTH_ACTIONS.LOGIN_SUCCESS,
          payload: {
            user: result.user,
            token: localStorage.getItem('auth_token'),
          },
        });
        return { success: true };
      } else {
        dispatch({
          type: AUTH_ACTIONS.LOGIN_FAILURE,
          payload: { error: result.error },
        });
        return { success: false, error: result.error };
      }
    } catch (error) {
      dispatch({
        type: AUTH_ACTIONS.LOGIN_FAILURE,
        payload: { error: error.message },
      });
      return { success: false, error: error.message };
    }
  };

  // Register function
  const register = async (userData) => {
    dispatch({ type: AUTH_ACTIONS.REGISTER_START });
    
    try {
      const result = await authService.register(userData);
      
      if (result.success) {
        dispatch({ type: AUTH_ACTIONS.REGISTER_SUCCESS });
        return { success: true, data: result.data };
      } else {
        dispatch({
          type: AUTH_ACTIONS.REGISTER_FAILURE,
          payload: { error: result.error },
        });
        return { success: false, error: result.error };
      }
    } catch (error) {
      dispatch({
        type: AUTH_ACTIONS.REGISTER_FAILURE,
        payload: { error: error.message },
      });
      return { success: false, error: error.message };
    }
  };

  // Logout function
  const logout = async () => {
    try {
      await authService.logout();
      dispatch({ type: AUTH_ACTIONS.LOGOUT });
      return { success: true };
    } catch (error) {
      console.error('Logout failed:', error);
      return { success: false, error: error.message };
    }
  };

  // Clear error function
  const clearError = () => {
    dispatch({ type: AUTH_ACTIONS.CLEAR_ERROR });
  };

  // Update user profile
  const updateProfile = async (profileData) => {
    try {
      const result = await authService.updateProfile(profileData);
      
      if (result.success) {
        dispatch({
          type: AUTH_ACTIONS.UPDATE_USER,
          payload: { user: profileData },
        });
      }
      
      return result;
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  // MFA functions
  const setupMFA = async () => {
    return await authService.setupMFA();
  };

  const verifyMFA = async (token) => {
    return await authService.verifyMFA(token);
  };

  const disableMFA = async () => {
    return await authService.disableMFA();
  };

  // Permission and role checking
  const hasPermission = (permission) => {
    return authService.hasPermission(permission);
  };

  const hasRole = (role) => {
    return authService.hasRole(role);
  };

  const isAdmin = () => {
    return authService.isAdmin();
  };

  // Context value
  const value = {
    // State
    ...state,
    
    // Actions
    login,
    register,
    logout,
    clearError,
    updateProfile,
    
    // MFA
    setupMFA,
    verifyMFA,
    disableMFA,
    
    // Permissions
    hasPermission,
    hasRole,
    isAdmin,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// Custom hook to use auth context
export function useAuth() {
  const context = useContext(AuthContext);
  
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  
  return context;
}

// HOC for protecting routes
export function withAuth(Component) {
  return function AuthenticatedComponent(props) {
    const { isAuthenticated, isLoading } = useAuth();
    
    if (isLoading) {
      return (
        <div className="flex items-center justify-center min-h-screen">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
        </div>
      );
    }
    
    if (!isAuthenticated) {
      // Redirect to login or show login component
      return null;
    }
    
    return <Component {...props} />;
  };
}

// HOC for role-based access
export function withRole(Component, requiredRole) {
  return function RoleProtectedComponent(props) {
    const { hasRole, isLoading } = useAuth();
    
    if (isLoading) {
      return (
        <div className="flex items-center justify-center min-h-screen">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
        </div>
      );
    }
    
    if (!hasRole(requiredRole)) {
      return (
        <div className="flex items-center justify-center min-h-screen">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-gray-900 mb-4">Access Denied</h2>
            <p className="text-gray-600">You don't have permission to access this page.</p>
          </div>
        </div>
      );
    }
    
    return <Component {...props} />;
  };
}

export default AuthContext; 