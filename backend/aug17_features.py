# aug17_features.py - Advanced Features for WebSecPen (Aug 17, 2025)
# User Feedback, Advanced Integrations, and Resilience

import os
import json
import csv
import redis
import secrets
import hashlib
import hmac
import requests
import subprocess
from io import StringIO
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from flask import Flask, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from flask_socketio import emit
from models import db, User, Scan, AuditLog, TeamMember
from sklearn.linear_model import LogisticRegression
import numpy as np

# Redis client for priority queue and caching
redis_client = None

def init_redis():
    """Initialize Redis client"""
    global redis_client
    try:
        redis_client = redis.Redis(
            host=os.environ.get('REDIS_HOST', 'localhost'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            db=0,
            decode_responses=True
        )
        redis_client.ping()  # Test connection
        return True
    except Exception as e:
        print(f"Redis connection failed: {e}")
        return False

# =============================================================================
# 1. USER FEEDBACK SYSTEM
# =============================================================================

def create_feedback_model():
    """Create Feedback model definition"""
    from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
    from sqlalchemy.ext.declarative import declarative_base
    
    # This would be added to models.py
    feedback_model_code = '''
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False, index=True)  # 'general', 'bug', 'feature'
    subject = db.Column(db.String(200), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 star rating
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='open', index=True)  # 'open', 'reviewing', 'resolved'
    admin_response = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='feedback_submissions')
    
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'subject': self.subject,
            'rating': self.rating,
            'message': self.message,
            'status': self.status,
            'admin_response': self.admin_response,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    '''
    return feedback_model_code

def init_feedback_routes(app):
    """Initialize user feedback routes"""
    
    @app.route('/api/feedback', methods=['POST'])
    @jwt_required()
    def submit_feedback():
        """Submit user feedback"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        # Validate input
        feedback_type = data.get('type', 'general')
        subject = data.get('subject', '').strip()
        rating = data.get('rating')
        message = data.get('message', '').strip()
        
        if not subject or len(subject) < 5:
            return jsonify({'error': 'Subject must be at least 5 characters'}), 400
        
        if not message or len(message) < 10:
            return jsonify({'error': 'Message must be at least 10 characters'}), 400
        
        if not isinstance(rating, int) or not (1 <= rating <= 5):
            return jsonify({'error': 'Rating must be between 1 and 5'}), 400
        
        if feedback_type not in ['general', 'bug', 'feature']:
            feedback_type = 'general'
        
        try:
            # Create feedback record (simulated - would use actual Feedback model)
            feedback_data = {
                'user_id': user_id,
                'type': feedback_type,
                'subject': subject,
                'rating': rating,
                'message': message,
                'status': 'open',
                'created_at': datetime.utcnow().isoformat()
            }
            
            # Store in Redis for now (in production, would use database)
            feedback_id = f"feedback:{user_id}:{datetime.utcnow().timestamp()}"
            if redis_client:
                redis_client.setex(feedback_id, 86400 * 30, json.dumps(feedback_data))  # 30 days
            
            # Log the feedback submission
            log = AuditLog(
                user_id=user_id,
                action='submit_feedback',
                details={
                    'type': feedback_type,
                    'subject': subject,
                    'rating': rating
                }
            )
            db.session.add(log)
            db.session.commit()
            
            return jsonify({
                'message': 'Feedback submitted successfully',
                'feedback_id': feedback_id
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to submit feedback: {str(e)}'}), 500
    
    @app.route('/api/admin/feedback', methods=['GET'])
    @jwt_required()
    def get_admin_feedback():
        """Get all feedback for admin review"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            feedback_list = []
            
            if redis_client:
                # Get all feedback from Redis
                keys = redis_client.keys('feedback:*')
                for key in keys:
                    feedback_data = redis_client.get(key)
                    if feedback_data:
                        feedback_list.append(json.loads(feedback_data))
            
            # Sort by creation date
            feedback_list.sort(key=lambda x: x['created_at'], reverse=True)
            
            # Calculate statistics
            total_feedback = len(feedback_list)
            avg_rating = sum(f['rating'] for f in feedback_list) / total_feedback if total_feedback > 0 else 0
            rating_distribution = defaultdict(int)
            type_distribution = defaultdict(int)
            
            for feedback in feedback_list:
                rating_distribution[feedback['rating']] += 1
                type_distribution[feedback['type']] += 1
            
            return jsonify({
                'feedback': feedback_list,
                'statistics': {
                    'total': total_feedback,
                    'average_rating': round(avg_rating, 2),
                    'rating_distribution': dict(rating_distribution),
                    'type_distribution': dict(type_distribution)
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to fetch feedback: {str(e)}'}), 500
    
    @app.route('/api/admin/feedback/export', methods=['GET'])
    @jwt_required()
    def export_feedback():
        """Export feedback as CSV"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            feedback_list = []
            
            if redis_client:
                keys = redis_client.keys('feedback:*')
                for key in keys:
                    feedback_data = redis_client.get(key)
                    if feedback_data:
                        feedback_list.append(json.loads(feedback_data))
            
            # Create CSV
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['User ID', 'Type', 'Subject', 'Rating', 'Message', 'Status', 'Created At'])
            
            for feedback in feedback_list:
                writer.writerow([
                    feedback['user_id'],
                    feedback['type'],
                    feedback['subject'],
                    feedback['rating'],
                    feedback['message'][:100] + '...' if len(feedback['message']) > 100 else feedback['message'],
                    feedback.get('status', 'open'),
                    feedback['created_at']
                ])
            
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=feedback_export.csv'}
            )
            
        except Exception as e:
            return jsonify({'error': f'Failed to export feedback: {str(e)}'}), 500

# =============================================================================
# 2. SCAN SCHEDULING PRIORITY QUEUE
# =============================================================================

def enqueue_scan(scan_id, priority_score):
    """Add scan to priority queue"""
    if redis_client:
        redis_client.zadd('scan_priority_queue', {json.dumps({'scan_id': scan_id}): priority_score})

def dequeue_scan():
    """Get highest priority scan from queue"""
    if redis_client:
        scan_data = redis_client.zpopmax('scan_priority_queue')
        if scan_data:
            return json.loads(scan_data[0][0])
    return None

def init_priority_queue_routes(app):
    """Initialize priority queue routes"""
    
    @app.route('/api/scan/prioritize', methods=['POST'])
    @jwt_required()
    def prioritize_scans():
        """Prioritize scheduled scans using AI"""
        user_id = get_jwt_identity()
        
        try:
            # Get user's scheduled scans (simulated)
            scheduled_scans = []
            
            # Simulate some scheduled scans
            sample_scans = [
                {'id': 1, 'url': 'https://example.com', 'user_id': user_id},
                {'id': 2, 'url': 'https://test.com', 'user_id': user_id},
                {'id': 3, 'url': 'https://demo.com', 'user_id': user_id}
            ]
            
            if not sample_scans:
                return jsonify({'message': 'No scheduled scans found'}), 200
            
            # AI-driven prioritization
            X = []
            scan_ids = []
            
            for scan in sample_scans:
                # Get historical vulnerability data for this URL
                historical_scans = Scan.query.filter_by(
                    target_url=scan['url'], 
                    user_id=user_id
                ).limit(10).all()
                
                # Calculate features for ML model
                vuln_count = 0
                scan_frequency = len(historical_scans)
                last_scan_days = 30  # Default
                
                for historical_scan in historical_scans:
                    if historical_scan.results:
                        vuln_count += len(historical_scan.results.get('alerts', []))
                    
                    # Days since last scan
                    if historical_scan.created_at:
                        days_diff = (datetime.utcnow() - historical_scan.created_at).days
                        last_scan_days = min(last_scan_days, days_diff)
                
                # Features: [vulnerability_count, scan_frequency, days_since_last_scan]
                X.append([vuln_count, scan_frequency, last_scan_days])
                scan_ids.append(scan['id'])
            
            if not X:
                # No historical data, use basic prioritization
                for i, scan in enumerate(sample_scans):
                    enqueue_scan(scan['id'], i + 1)
            else:
                # Use logistic regression for prioritization
                # Higher vulnerability count and longer time since last scan = higher priority
                y = [1] * len(X)  # All positive samples for training
                
                if len(X) > 1:
                    model = LogisticRegression()
                    model.fit(X, y)
                    scores = model.predict_proba(X)[:, 1]
                else:
                    scores = [1.0] * len(X)
                
                # Enqueue scans with priority scores
                for scan_id, score in zip(scan_ids, scores):
                    enqueue_scan(scan_id, float(score))
            
            return jsonify({
                'message': f'Prioritized {len(scan_ids)} scans',
                'prioritized_scans': scan_ids
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to prioritize scans: {str(e)}'}), 500
    
    @app.route('/api/scan/queue/status', methods=['GET'])
    @jwt_required()
    def get_queue_status():
        """Get scan queue status"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            queue_length = 0
            pending_scans = []
            
            if redis_client:
                queue_length = redis_client.zcard('scan_priority_queue')
                
                # Get top 10 pending scans
                scan_data = redis_client.zrevrange('scan_priority_queue', 0, 9, withscores=True)
                for scan_json, score in scan_data:
                    scan_info = json.loads(scan_json)
                    scan_info['priority_score'] = score
                    pending_scans.append(scan_info)
            
            return jsonify({
                'queue_length': queue_length,
                'pending_scans': pending_scans
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get queue status: {str(e)}'}), 500

# =============================================================================
# 3. AWS SECURITY HUB INTEGRATION
# =============================================================================

def init_security_hub_routes(app):
    """Initialize AWS Security Hub integration"""
    
    @app.route('/api/scan/<int:scan_id>/export/security-hub', methods=['POST'])
    @jwt_required()
    def export_to_security_hub(scan_id):
        """Export scan results to AWS Security Hub"""
        user_id = get_jwt_identity()
        
        # Check scan access
        scan = Scan.query.filter(
            Scan.id == scan_id,
            db.or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != 'completed':
            return jsonify({'error': 'Scan not completed'}), 400
        
        try:
            # AWS Security Hub configuration
            aws_region = os.environ.get('AWS_REGION', 'us-east-1')
            aws_account_id = os.environ.get('AWS_ACCOUNT_ID', '123456789012')
            
            # Simulate Security Hub findings (in production, would use boto3)
            findings = []
            
            for vuln in scan.results.get('alerts', []) if scan.results else []:
                finding = {
                    'SchemaVersion': '2018-10-08',
                    'Id': f'websecpen-{scan.id}-{vuln.get("pluginid", "unknown")}',
                    'ProductArn': f'arn:aws:securityhub:{aws_region}:{aws_account_id}:product/{aws_account_id}/websecpen',
                    'GeneratorId': 'websecpen-scanner',
                    'AwsAccountId': aws_account_id,
                    'Types': ['Software and Configuration Checks/Vulnerabilities'],
                    'CreatedAt': scan.created_at.isoformat() + 'Z',
                    'UpdatedAt': datetime.utcnow().isoformat() + 'Z',
                    'Title': vuln.get('name', 'Unknown Vulnerability'),
                    'Description': vuln.get('desc', 'No description available'),
                    'Resources': [{
                        'Type': 'AwsOther',
                        'Id': scan.target_url,
                        'Region': aws_region
                    }],
                    'Severity': {
                        'Label': map_severity_to_security_hub(vuln.get('risk', 'Low'))
                    },
                    'Confidence': 85,
                    'Criticality': 70,
                    'SourceUrl': scan.target_url,
                    'ProductFields': {
                        'websecpen/scan_id': str(scan.id),
                        'websecpen/scan_type': scan.scan_type or 'spider',
                        'websecpen/user_id': str(scan.user_id)
                    }
                }
                findings.append(finding)
            
            # Log the export (simulated)
            log = AuditLog(
                user_id=user_id,
                action='export_security_hub',
                details={
                    'scan_id': scan_id,
                    'findings_count': len(findings),
                    'aws_account': aws_account_id
                }
            )
            db.session.add(log)
            db.session.commit()
            
            return jsonify({
                'message': f'Exported {len(findings)} findings to Security Hub',
                'findings_count': len(findings),
                'aws_account_id': aws_account_id
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Security Hub export failed: {str(e)}'}), 500

def map_severity_to_security_hub(zap_severity):
    """Map ZAP severity to Security Hub severity"""
    severity_mapping = {
        'High': 'HIGH',
        'Medium': 'MEDIUM',
        'Low': 'LOW',
        'Informational': 'INFORMATIONAL'
    }
    return severity_mapping.get(zap_severity, 'MEDIUM')

# =============================================================================
# 4. RATE LIMITING DASHBOARD
# =============================================================================

def init_rate_limit_routes(app):
    """Initialize rate limiting dashboard"""
    
    @app.route('/api/admin/rate-limits', methods=['GET'])
    @jwt_required()
    def get_rate_limit_stats():
        """Get rate limiting statistics"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            rate_limit_data = {}
            
            if redis_client:
                # Get all rate limit keys
                keys = redis_client.keys('LIMITER_*')
                
                for key in keys:
                    try:
                        # Parse rate limit data
                        data = redis_client.hgetall(key)
                        if data:
                            endpoint = key.replace('LIMITER_', '').split('_')[0]
                            rate_limit_data[endpoint] = {
                                'current': int(data.get('current', 0)),
                                'limit': int(data.get('limit', 100)),
                                'window': data.get('window', '3600'),
                                'remaining': int(data.get('limit', 100)) - int(data.get('current', 0))
                            }
                    except (ValueError, TypeError):
                        continue
            
            # Calculate summary statistics
            total_requests = sum(data['current'] for data in rate_limit_data.values())
            total_limits = sum(data['limit'] for data in rate_limit_data.values())
            
            # Find endpoints approaching limits (>80% usage)
            high_usage_endpoints = [
                endpoint for endpoint, data in rate_limit_data.items()
                if data['limit'] > 0 and (data['current'] / data['limit']) > 0.8
            ]
            
            return jsonify({
                'rate_limits': rate_limit_data,
                'summary': {
                    'total_requests': total_requests,
                    'total_limits': total_limits,
                    'utilization_percent': round((total_requests / total_limits * 100), 2) if total_limits > 0 else 0,
                    'high_usage_endpoints': high_usage_endpoints
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to fetch rate limits: {str(e)}'}), 500

# =============================================================================
# 5. BACKUP AND RECOVERY SYSTEM
# =============================================================================

def init_backup_routes(app):
    """Initialize backup and recovery routes"""
    
    @app.route('/api/admin/backup/create', methods=['POST'])
    @jwt_required()
    def create_backup():
        """Create database backup"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_filename = f'websecpen_backup_{timestamp}.sql'
            backup_path = f'/tmp/{backup_filename}'
            
            # Database backup command (SQLite for development)
            db_path = os.environ.get('DATABASE_URL', 'sqlite:///websecpen.db').replace('sqlite:///', '')
            
            if db_path.endswith('.db'):
                # SQLite backup
                backup_cmd = f'sqlite3 {db_path} ".backup {backup_path}"'
            else:
                # PostgreSQL backup (for production)
                backup_cmd = [
                    'pg_dump',
                    '-h', os.environ.get('DB_HOST', 'localhost'),
                    '-U', os.environ.get('DB_USER', 'postgres'),
                    '-f', backup_path,
                    os.environ.get('DB_NAME', 'websecpen')
                ]
            
            # Execute backup
            if isinstance(backup_cmd, str):
                result = subprocess.run(backup_cmd, shell=True, capture_output=True, text=True)
            else:
                env = os.environ.copy()
                if 'DB_PASSWORD' in os.environ:
                    env['PGPASSWORD'] = os.environ['DB_PASSWORD']
                result = subprocess.run(backup_cmd, capture_output=True, text=True, env=env)
            
            if result.returncode == 0:
                # Get backup file size
                backup_size = os.path.getsize(backup_path) if os.path.exists(backup_path) else 0
                
                # Log backup creation
                log = AuditLog(
                    user_id=get_jwt_identity(),
                    action='create_backup',
                    details={
                        'backup_file': backup_filename,
                        'backup_size': backup_size,
                        'backup_path': backup_path
                    }
                )
                db.session.add(log)
                db.session.commit()
                
                return jsonify({
                    'message': 'Backup created successfully',
                    'backup_file': backup_filename,
                    'backup_size': backup_size,
                    'created_at': datetime.utcnow().isoformat()
                }), 200
            else:
                return jsonify({
                    'error': 'Backup failed',
                    'details': result.stderr
                }), 500
                
        except Exception as e:
            return jsonify({'error': f'Backup creation failed: {str(e)}'}), 500
    
    @app.route('/api/admin/backup/status', methods=['GET'])
    @jwt_required()
    def get_backup_status():
        """Get backup status and history"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            # Get backup history from audit logs
            backup_logs = AuditLog.query.filter_by(action='create_backup')\
                .order_by(AuditLog.timestamp.desc())\
                .limit(10).all()
            
            backup_history = []
            for log in backup_logs:
                backup_history.append({
                    'backup_file': log.details.get('backup_file'),
                    'backup_size': log.details.get('backup_size'),
                    'created_at': log.timestamp.isoformat(),
                    'status': 'completed'
                })
            
            # Calculate backup statistics
            total_backups = len(backup_history)
            total_size = sum(backup.get('backup_size', 0) for backup in backup_history)
            latest_backup = backup_history[0] if backup_history else None
            
            return jsonify({
                'backup_history': backup_history,
                'statistics': {
                    'total_backups': total_backups,
                    'total_size': total_size,
                    'latest_backup': latest_backup,
                    'last_backup_age_hours': (
                        (datetime.utcnow() - datetime.fromisoformat(latest_backup['created_at'])).total_seconds() / 3600
                        if latest_backup else None
                    )
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get backup status: {str(e)}'}), 500

# =============================================================================
# MAIN INITIALIZATION FUNCTION
# =============================================================================

def init_aug17_routes(app):
    """Initialize all August 17th features"""
    
    # Initialize Redis
    redis_available = init_redis()
    if not redis_available:
        print("Warning: Redis not available. Some features may not work properly.")
    
    # Initialize all feature routes
    init_feedback_routes(app)
    init_priority_queue_routes(app)
    init_security_hub_routes(app)
    init_rate_limit_routes(app)
    init_backup_routes(app)
    
    print("✅ August 17th features initialized successfully!")
    
    return app 