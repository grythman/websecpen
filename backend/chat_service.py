# chat_service.py - Real-Time Chat Support System for WebSecPen
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional
from flask import request
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from models import db, User
import json

# Configure logging
logger = logging.getLogger(__name__)

class ChatMessage:
    """Represents a chat message"""
    def __init__(self, user_id: int, username: str, message: str, 
                 is_admin: bool = False, room: str = 'general'):
        self.user_id = user_id
        self.username = username
        self.message = message
        self.is_admin = is_admin
        self.room = room
        self.timestamp = datetime.utcnow()
        self.id = f"{user_id}_{int(self.timestamp.timestamp() * 1000)}"
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'message': self.message,
            'is_admin': self.is_admin,
            'room': self.room,
            'timestamp': self.timestamp.isoformat(),
            'formatted_time': self.timestamp.strftime('%H:%M')
        }

class ChatService:
    """
    Real-time chat service for user support and engagement
    """
    
    def __init__(self, socketio: SocketIO):
        self.socketio = socketio
        self.active_users: Dict[str, Dict] = {}  # session_id -> user_info
        self.chat_rooms: Dict[str, List[ChatMessage]] = {
            'general': [],
            'support': []
        }
        self.admin_sessions: set = set()
        
        # Register SocketIO event handlers
        self._register_handlers()
    
    def _register_handlers(self):
        """Register SocketIO event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect(auth=None):
            """Handle user connection to chat"""
            try:
                # Verify JWT token
                if auth and 'token' in auth:
                    # Set token in request headers for JWT verification
                    request.headers = {'Authorization': f"Bearer {auth['token']}"}
                
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                user = User.query.get(user_id)
                
                if not user:
                    emit('error', {'message': 'Invalid user'})
                    return False
                
                # Store user session info
                session_id = request.sid
                user_info = {
                    'user_id': user_id,
                    'username': user.name or user.email.split('@')[0],
                    'email': user.email,
                    'is_admin': getattr(user, 'is_admin', False),
                    'connected_at': datetime.utcnow()
                }
                
                self.active_users[session_id] = user_info
                
                # Track admin sessions
                if user_info['is_admin']:
                    self.admin_sessions.add(session_id)
                
                # Join default room
                join_room('general')
                
                # Send welcome message
                emit('welcome', {
                    'message': f"Welcome to WebSecPen Support, {user_info['username']}!",
                    'user_info': user_info,
                    'online_users': len(self.active_users),
                    'admin_online': len(self.admin_sessions) > 0
                })
                
                # Notify admins of new user
                if not user_info['is_admin']:
                    self.socketio.emit('user_joined', {
                        'user': user_info,
                        'online_users': len(self.active_users)
                    }, room='admin')
                
                # Send recent chat history
                recent_messages = self.chat_rooms['general'][-20:]  # Last 20 messages
                emit('chat_history', {
                    'messages': [msg.to_dict() for msg in recent_messages]
                })
                
                logger.info(f"User {user_info['username']} connected to chat")
                return True
                
            except Exception as e:
                logger.error(f"Chat connection error: {e}")
                emit('error', {'message': 'Authentication failed'})
                return False
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle user disconnection"""
            session_id = request.sid
            
            if session_id in self.active_users:
                user_info = self.active_users[session_id]
                
                # Remove from admin sessions if admin
                if session_id in self.admin_sessions:
                    self.admin_sessions.remove(session_id)
                
                # Notify admins of user leaving
                if not user_info['is_admin']:
                    self.socketio.emit('user_left', {
                        'user': user_info,
                        'online_users': len(self.active_users) - 1
                    }, room='admin')
                
                # Remove user session
                del self.active_users[session_id]
                
                logger.info(f"User {user_info['username']} disconnected from chat")
        
        @self.socketio.on('send_message')
        def handle_message(data):
            """Handle incoming chat messages"""
            try:
                session_id = request.sid
                
                if session_id not in self.active_users:
                    emit('error', {'message': 'User not authenticated'})
                    return
                
                user_info = self.active_users[session_id]
                message_text = data.get('message', '').strip()
                room = data.get('room', 'general')
                
                if not message_text or len(message_text) > 1000:
                    emit('error', {'message': 'Invalid message length'})
                    return
                
                # Create chat message
                chat_message = ChatMessage(
                    user_id=user_info['user_id'],
                    username=user_info['username'],
                    message=message_text,
                    is_admin=user_info['is_admin'],
                    room=room
                )
                
                # Store message
                if room not in self.chat_rooms:
                    self.chat_rooms[room] = []
                
                self.chat_rooms[room].append(chat_message)
                
                # Limit message history (keep last 100 messages per room)
                if len(self.chat_rooms[room]) > 100:
                    self.chat_rooms[room] = self.chat_rooms[room][-100:]
                
                # Broadcast message to room
                self.socketio.emit('new_message', chat_message.to_dict(), room=room)
                
                # Special handling for support requests
                if not user_info['is_admin'] and ('help' in message_text.lower() or 'support' in message_text.lower()):
                    self._notify_admins_support_request(user_info, message_text)
                
                logger.info(f"Message from {user_info['username']} in {room}: {message_text[:50]}...")
                
            except Exception as e:
                logger.error(f"Error handling message: {e}")
                emit('error', {'message': 'Failed to send message'})
        
        @self.socketio.on('join_room')
        def handle_join_room(data):
            """Handle user joining a chat room"""
            try:
                session_id = request.sid
                
                if session_id not in self.active_users:
                    return
                
                room = data.get('room', 'general')
                user_info = self.active_users[session_id]
                
                # Admin-only rooms
                if room == 'admin' and not user_info['is_admin']:
                    emit('error', {'message': 'Access denied to admin room'})
                    return
                
                join_room(room)
                
                # Send room history
                if room in self.chat_rooms:
                    recent_messages = self.chat_rooms[room][-20:]
                    emit('room_history', {
                        'room': room,
                        'messages': [msg.to_dict() for msg in recent_messages]
                    })
                
                emit('joined_room', {'room': room})
                logger.info(f"User {user_info['username']} joined room {room}")
                
            except Exception as e:
                logger.error(f"Error joining room: {e}")
        
        @self.socketio.on('leave_room')
        def handle_leave_room(data):
            """Handle user leaving a chat room"""
            try:
                room = data.get('room', 'general')
                leave_room(room)
                emit('left_room', {'room': room})
                
            except Exception as e:
                logger.error(f"Error leaving room: {e}")
        
        @self.socketio.on('admin_message')
        def handle_admin_message(data):
            """Handle admin broadcast messages"""
            try:
                session_id = request.sid
                
                if session_id not in self.active_users:
                    return
                
                user_info = self.active_users[session_id]
                
                if not user_info['is_admin']:
                    emit('error', {'message': 'Admin access required'})
                    return
                
                message_text = data.get('message', '').strip()
                target_user_id = data.get('target_user_id')
                broadcast = data.get('broadcast', False)
                
                if not message_text:
                    return
                
                admin_message = ChatMessage(
                    user_id=user_info['user_id'],
                    username=f"Admin ({user_info['username']})",
                    message=message_text,
                    is_admin=True,
                    room='admin'
                )
                
                if broadcast:
                    # Broadcast to all users
                    self.socketio.emit('admin_broadcast', {
                        'message': admin_message.to_dict(),
                        'type': 'announcement'
                    })
                elif target_user_id:
                    # Send to specific user
                    target_session = self._find_user_session(target_user_id)
                    if target_session:
                        self.socketio.emit('admin_direct_message', {
                            'message': admin_message.to_dict()
                        }, room=target_session)
                
                logger.info(f"Admin message from {user_info['username']}: {message_text[:50]}...")
                
            except Exception as e:
                logger.error(f"Error handling admin message: {e}")
        
        @self.socketio.on('get_online_users')
        def handle_get_online_users():
            """Get list of online users (admin only)"""
            try:
                session_id = request.sid
                
                if session_id not in self.active_users:
                    return
                
                user_info = self.active_users[session_id]
                
                if not user_info['is_admin']:
                    emit('error', {'message': 'Admin access required'})
                    return
                
                online_users = [
                    {
                        'user_id': info['user_id'],
                        'username': info['username'],
                        'email': info['email'],
                        'connected_at': info['connected_at'].isoformat()
                    }
                    for info in self.active_users.values()
                    if not info['is_admin']
                ]
                
                emit('online_users_list', {
                    'users': online_users,
                    'total': len(online_users)
                })
                
            except Exception as e:
                logger.error(f"Error getting online users: {e}")
    
    def _notify_admins_support_request(self, user_info: Dict, message: str):
        """Notify admins of support request"""
        if self.admin_sessions:
            self.socketio.emit('support_request', {
                'user': user_info,
                'message': message,
                'timestamp': datetime.utcnow().isoformat(),
                'priority': 'high' if 'urgent' in message.lower() else 'normal'
            }, room='admin')
    
    def _find_user_session(self, user_id: int) -> Optional[str]:
        """Find session ID for a specific user"""
        for session_id, user_info in self.active_users.items():
            if user_info['user_id'] == user_id:
                return session_id
        return None
    
    def get_chat_stats(self) -> Dict:
        """Get chat statistics"""
        total_messages = sum(len(messages) for messages in self.chat_rooms.values())
        
        return {
            'online_users': len(self.active_users),
            'admin_online': len(self.admin_sessions),
            'total_messages': total_messages,
            'active_rooms': len(self.chat_rooms),
            'support_requests_today': self._count_support_requests_today()
        }
    
    def _count_support_requests_today(self) -> int:
        """Count support requests from today"""
        today = datetime.utcnow().date()
        count = 0
        
        for messages in self.chat_rooms.values():
            for msg in messages:
                if (msg.timestamp.date() == today and 
                    not msg.is_admin and 
                    ('help' in msg.message.lower() or 'support' in msg.message.lower())):
                    count += 1
        
        return count

# Global chat service instance (will be initialized in app.py)
chat_service = None

def initialize_chat_service(socketio: SocketIO):
    """Initialize the global chat service"""
    global chat_service
    chat_service = ChatService(socketio)
    return chat_service 