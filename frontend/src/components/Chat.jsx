// Chat.jsx - Real-Time Support Chat Component
import React, { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useError } from '../context/ErrorContext.jsx';
import { ThemeContext } from '../context/ThemeContext.jsx';
import io from 'socket.io-client';
import './Chat.css';

const Chat = ({ isOpen, onToggle }) => {
  const { t } = useTranslation();
  const { showError, showSuccess } = useError();
  const { theme } = React.useContext(ThemeContext);
  
  const [socket, setSocket] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState(0);
  const [supportOnline, setSupportOnline] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const typingTimeoutRef = useRef(null);
  
  // Scroll to bottom when new messages arrive
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };
  
  useEffect(() => {
    scrollToBottom();
  }, [messages]);
  
  // Initialize socket connection
  useEffect(() => {
    if (isOpen && !socket) {
      const token = localStorage.getItem('token');
      if (!token) {
        showError('Please log in to use chat support');
        return;
      }
      
      setConnectionStatus('connecting');
      
      const newSocket = io(process.env.REACT_APP_API_URL || 'http://localhost:5000', {
        auth: { token },
        transports: ['websocket', 'polling']
      });
      
      newSocket.on('connect', () => {
        setIsConnected(true);
        setConnectionStatus('connected');
        setSocket(newSocket);
        showSuccess(t('chat_connected'));
      });
      
      newSocket.on('disconnect', () => {
        setIsConnected(false);
        setConnectionStatus('disconnected');
        showError(t('chat_disconnected'));
      });
      
      newSocket.on('connect_error', (error) => {
        setConnectionStatus('error');
        showError(`Chat connection failed: ${error.message}`);
      });
      
      newSocket.on('welcome', (data) => {
        setOnlineUsers(data.online_users || 0);
        setSupportOnline(data.admin_online || false);
        
        // Add welcome message
        const welcomeMessage = {
          id: Date.now(),
          message: data.message,
          username: 'System',
          is_admin: true,
          timestamp: new Date().toISOString(),
          formatted_time: new Date().toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit' 
          })
        };
        setMessages(prev => [...prev, welcomeMessage]);
      });
      
      newSocket.on('chat_history', (data) => {
        setMessages(data.messages || []);
      });
      
      newSocket.on('new_message', (message) => {
        setMessages(prev => [...prev, message]);
        
        // Show notification for admin messages
        if (message.is_admin && message.user_id !== getCurrentUserId()) {
          showSuccess('New message from support');
        }
      });
      
      newSocket.on('admin_broadcast', (data) => {
        const broadcastMessage = {
          ...data.message,
          id: Date.now(),
          isBroadcast: true
        };
        setMessages(prev => [...prev, broadcastMessage]);
        showSuccess('Announcement from support team');
      });
      
      newSocket.on('admin_direct_message', (data) => {
        setMessages(prev => [...prev, data.message]);
        showSuccess('Direct message from support');
      });
      
      newSocket.on('user_typing', (data) => {
        if (data.is_admin) {
          setIsTyping(true);
          
          // Clear typing indicator after 3 seconds
          if (typingTimeoutRef.current) {
            clearTimeout(typingTimeoutRef.current);
          }
          typingTimeoutRef.current = setTimeout(() => {
            setIsTyping(false);
          }, 3000);
        }
      });
      
      newSocket.on('error', (data) => {
        showError(data.message || 'Chat error occurred');
      });
      
      // Cleanup
      return () => {
        newSocket.disconnect();
        setSocket(null);
        setIsConnected(false);
        setConnectionStatus('disconnected');
      };
    }
    
    return () => {
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
    };
  }, [isOpen, socket, showError, showSuccess, t]);
  
  // Get current user ID from token
  const getCurrentUserId = () => {
    const token = localStorage.getItem('token');
    if (!token) return null;
    
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.sub;
    } catch {
      return null;
    }
  };
  
  // Send message
  const sendMessage = () => {
    if (!newMessage.trim() || !socket || !isConnected) return;
    
    socket.emit('send_message', {
      message: newMessage.trim(),
      room: 'general'
    });
    
    setNewMessage('');
    inputRef.current?.focus();
  };
  
  // Handle Enter key
  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };
  
  // Handle input change with typing indicator
  const handleInputChange = (e) => {
    setNewMessage(e.target.value);
    
    // Emit typing indicator (throttled)
    if (socket && isConnected) {
      socket.emit('typing', { room: 'general' });
    }
  };
  
  // Format message timestamp
  const formatMessageTime = (timestamp) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit' 
      });
    } catch {
      return '';
    }
  };
  
  // Get connection status indicator
  const getConnectionIndicator = () => {
    switch (connectionStatus) {
      case 'connecting':
        return { icon: '🔄', text: t('chat_connecting'), class: 'connecting' };
      case 'connected':
        return { icon: '🟢', text: t('chat_connected'), class: 'connected' };
      case 'error':
        return { icon: '🔴', text: 'Connection Error', class: 'error' };
      default:
        return { icon: '⚪', text: t('chat_disconnected'), class: 'disconnected' };
    }
  };
  
  if (!isOpen) {
    return (
      <div className={`chat-toggle ${theme}`} onClick={onToggle}>
        <div className="chat-toggle-icon">💬</div>
        <div className="chat-toggle-text">{t('chat_support')}</div>
        {supportOnline && <div className="support-indicator online"></div>}
      </div>
    );
  }
  
  const connectionIndicator = getConnectionIndicator();
  
  return (
    <div className={`chat-container ${theme}`}>
      <div className="chat-header">
        <div className="chat-title">
          <span className="chat-icon">💬</span>
          <span className="chat-title-text">{t('chat_support')}</span>
        </div>
        
        <div className="chat-status">
          <div className={`connection-status ${connectionIndicator.class}`}>
            <span className="status-icon">{connectionIndicator.icon}</span>
            <span className="status-text">{connectionIndicator.text}</span>
          </div>
          
          {onlineUsers > 0 && (
            <div className="online-count">
              👥 {onlineUsers} online
            </div>
          )}
        </div>
        
        <button 
          className="chat-close-btn" 
          onClick={onToggle}
          aria-label="Close chat"
        >
          ✕
        </button>
      </div>
      
      <div className="chat-messages">
        {messages.length === 0 ? (
          <div className="chat-empty">
            <div className="empty-icon">💬</div>
            <p>Welcome to WebSecPen Support!</p>
            <p>Send us a message and we'll help you out.</p>
          </div>
        ) : (
          messages.map((message, index) => (
            <div 
              key={message.id || index}
              className={`message ${message.is_admin ? 'admin' : 'user'} ${message.isBroadcast ? 'broadcast' : ''}`}
            >
              <div className="message-header">
                <span className="message-username">
                  {message.is_admin ? (
                    <>
                      <span className="admin-badge">🛡️</span>
                      {message.username}
                    </>
                  ) : (
                    <>
                      <span className="user-badge">👤</span>
                      {message.username}
                    </>
                  )}
                </span>
                <span className="message-time">
                  {message.formatted_time || formatMessageTime(message.timestamp)}
                </span>
              </div>
              
              <div className="message-content">
                {message.isBroadcast && (
                  <div className="broadcast-indicator">
                    📢 Announcement
                  </div>
                )}
                <p>{message.message}</p>
              </div>
            </div>
          ))
        )}
        
        {isTyping && (
          <div className="typing-indicator">
            <div className="typing-dots">
              <span></span>
              <span></span>
              <span></span>
            </div>
            <span className="typing-text">Support is typing...</span>
          </div>
        )}
        
        <div ref={messagesEndRef} />
      </div>
      
      <div className="chat-input">
        <div className="input-container">
          <textarea
            ref={inputRef}
            value={newMessage}
            onChange={handleInputChange}
            onKeyPress={handleKeyPress}
            placeholder={t('chat_placeholder')}
            disabled={!isConnected}
            rows="1"
            className="message-input"
          />
          
          <button
            onClick={sendMessage}
            disabled={!newMessage.trim() || !isConnected}
            className="send-button"
            aria-label={t('send_message')}
          >
            <span className="send-icon">📤</span>
          </button>
        </div>
        
        {!isConnected && (
          <div className="connection-warning">
            ⚠️ Not connected to chat. Check your internet connection.
          </div>
        )}
        
        <div className="chat-footer">
          <span className="support-status">
            {supportOnline ? (
              <>
                🟢 {t('online_support')}
              </>
            ) : (
              <>
                🔴 {t('offline_support')}
              </>
            )}
          </span>
          
          <span className="response-time">
            Avg. response: {supportOnline ? '< 5 min' : '< 24 hours'}
          </span>
        </div>
      </div>
    </div>
  );
};

export default Chat; 