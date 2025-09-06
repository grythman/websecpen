// src/firebase.js
import { initializeApp } from 'firebase/app';
import { getMessaging, getToken, onMessage } from 'firebase/messaging';

const firebaseConfig = {
  apiKey: process.env.REACT_APP_FIREBASE_API_KEY,
  authDomain: process.env.REACT_APP_FIREBASE_AUTH_DOMAIN || 'your-app.firebaseapp.com',
  projectId: process.env.REACT_APP_FIREBASE_PROJECT_ID || 'your-app',
  storageBucket: process.env.REACT_APP_FIREBASE_STORAGE_BUCKET || 'your-app.appspot.com',
  messagingSenderId: process.env.REACT_APP_FIREBASE_MESSAGING_SENDER_ID || 'your-sender-id',
  appId: process.env.REACT_APP_FIREBASE_APP_ID || 'your-app-id'
};

// Initialize Firebase only if config is available
let app = null;
let messaging = null;

try {
  if (firebaseConfig.apiKey && firebaseConfig.apiKey !== 'undefined') {
    app = initializeApp(firebaseConfig);
    messaging = getMessaging(app);
  }
} catch (error) {
  console.warn('Firebase initialization failed:', error);
}

export const requestNotificationPermission = async () => {
  if (!messaging) {
    throw new Error('Firebase messaging not initialized');
  }

  try {
    // Request notification permission
    const permission = await Notification.requestPermission();
    
    if (permission === 'granted') {
      // Get FCM token
      const token = await getToken(messaging, { 
        vapidKey: process.env.REACT_APP_FIREBASE_VAPID_KEY 
      });
      
      if (token) {
        // Register token with backend
        const response = await fetch('/api/notifications/register', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ token }),
        });

        if (response.ok) {
          console.log('Notification token registered successfully');
          localStorage.setItem('notificationsEnabled', 'true');
          return token;
        } else {
          throw new Error('Failed to register notification token');
        }
      } else {
        throw new Error('Failed to get FCM token');
      }
    } else {
      throw new Error('Notification permission denied');
    }
  } catch (error) {
    console.error('Notification permission error:', error);
    throw error;
  }
};

export const disableNotifications = async () => {
  try {
    const response = await fetch('/api/notifications/unregister', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
      },
    });

    if (response.ok) {
      localStorage.setItem('notificationsEnabled', 'false');
      return true;
    } else {
      throw new Error('Failed to unregister notifications');
    }
  } catch (error) {
    console.error('Failed to disable notifications:', error);
    throw error;
  }
};

export const sendTestNotification = async () => {
  try {
    const response = await fetch('/api/notifications/test', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
      },
    });

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Failed to send test notification:', error);
    throw error;
  }
};

// Listen for foreground messages
export const onMessageListener = () => {
  if (!messaging) {
    return Promise.reject('Firebase messaging not initialized');
  }

  return new Promise((resolve) => {
    onMessage(messaging, (payload) => {
      console.log('Received foreground message:', payload);
      resolve(payload);
    });
  });
};

// Check if notifications are supported
export const isNotificationSupported = () => {
  return 'Notification' in window && 'serviceWorker' in navigator && messaging !== null;
};

// Get current notification status
export const getNotificationStatus = () => {
  if (!isNotificationSupported()) {
    return 'unsupported';
  }
  
  const permission = Notification.permission;
  const enabled = localStorage.getItem('notificationsEnabled') === 'true';
  
  return {
    permission,
    enabled,
    supported: true
  };
};

export { messaging }; 