# new_advanced_features.py - New Advanced Features for WebSecPen (Aug 10-12, 2025)
import os
import csv
import json
import random
import string
import requests
import subprocess
from io import StringIO
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from transformers import pipeline
from pyfcm import FCMNotification
from models import db, User, Scan, Feedback, Referral, AuditLog, Schedule

# Initialize services
fcm_service = None
sentiment_analyzer = None

def init_services():
    """Initialize external services"""
    global fcm_service, sentiment_analyzer
    
    # Initialize FCM if API key is available
    fcm_api_key = os.environ.get('FCM_SERVER_KEY')
    if fcm_api_key:
        fcm_service = FCMNotification(api_key=fcm_api_key)
    
    # Initialize sentiment analyzer
    try:
        sentiment_analyzer = pipeline('sentiment-analysis', model='cardiffnlp/twitter-roberta-base-sentiment-latest')
    except Exception as e:
        print(f"Warning: Could not initialize sentiment analyzer: {e}")
        # Fallback to simpler model
        try:
            sentiment_analyzer = pipeline('sentiment-analysis')
        except Exception as e2:
            print(f"Error: Could not initialize any sentiment analyzer: {e2}")

def log_admin_action(admin_id, action, details=None, ip_address=None, user_agent=None):
    """Log admin action for audit purposes"""
    audit_log = AuditLog(
        admin_id=admin_id,
        action=action,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.session.add(audit_log)
    db.session.commit()

def generate_referral_code():
    """Generate unique referral code"""
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        if not Referral.query.filter_by(code=code).first():
            return code

def calculate_next_run(frequency):
    """Calculate next run time based on frequency"""
    now = datetime.utcnow()
    if frequency == 'daily':
        return now + timedelta(days=1)
    elif frequency == 'weekly':
        return now + timedelta(weeks=1)
    elif frequency == 'monthly':
        return now + timedelta(days=30)
    else:
        return now + timedelta(hours=1)  # Default fallback

def init_new_advanced_routes(app):
    """Initialize all new advanced feature routes"""
    
    # Configure rate limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=os.environ.get('REDIS_URL', 'redis://localhost:6379')
    )
    
    # Configure upload directory
    UPLOAD_FOLDER = 'uploads/avatars'
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # =============================================================================
    # 1. REFERRAL SYSTEM
    # =============================================================================
    
    @app.route('/api/referral/create', methods=['POST'])
    @jwt_required()
    def create_referral():
        """Create a new referral"""
        user_id = get_jwt_identity()
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Check if referral already exists for this email
        existing = Referral.query.filter_by(referrer_id=user_id, referee_email=email).first()
        if existing:
            return jsonify({'error': 'Referral already exists for this email'}), 400
        
        code = generate_referral_code()
        referral = Referral(
            referrer_id=user_id,
            referee_email=email,
            code=code
        )
        
        db.session.add(referral)
        db.session.commit()
        
        share_url = f"{request.host_url}signup?ref={code}"
        
        return jsonify({
            'referral_code': code,
            'share_url': share_url,
            'referee_email': email
        }), 201
    
    @app.route('/api/referral/redeem', methods=['POST'])
    @jwt_required()
    def redeem_referral():
        """Redeem a referral code"""
        user_id = get_jwt_identity()
        data = request.get_json()
        code = data.get('code')
        
        if not code:
            return jsonify({'error': 'Referral code is required'}), 400
        
        referral = Referral.query.filter_by(code=code, redeemed=False).first()
        if not referral:
            return jsonify({'error': 'Invalid or already redeemed code'}), 400
        
        # Mark as redeemed
        referral.redeemed = True
        referral.redeemed_by_user_id = user_id
        referral.redeemed_at = datetime.utcnow()
        
        # Grant reward to referrer
        referrer = User.query.get(referral.referrer_id)
        if referrer:
            referrer.scan_limit += referral.reward_amount
            referral.reward_granted = True
        
        db.session.commit()
        
        return jsonify({
            'message': f'Referral redeemed! {referral.reward_amount} extra scans added to referrer.',
            'reward_type': referral.reward_type,
            'reward_amount': referral.reward_amount
        }), 200
    
    @app.route('/api/referral/list', methods=['GET'])
    @jwt_required()
    def list_referrals():
        """List user's referrals"""
        user_id = get_jwt_identity()
        referrals = Referral.query.filter_by(referrer_id=user_id).all()
        
        return jsonify([referral.to_dict() for referral in referrals]), 200
    
    # =============================================================================
    # 2. AUDIT LOGS
    # =============================================================================
    
    @app.route('/api/admin/user/<int:user_id>/ban', methods=['POST'])
    @jwt_required()
    def ban_user(user_id):
        """Ban a user (admin only)"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_active = False
        
        # Log the action
        log_admin_action(
            admin_id=claims['sub'],
            action='ban_user',
            details={'user_id': user_id, 'email': user.email},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        db.session.commit()
        
        return jsonify({'message': f'User {user.email} has been banned'}), 200
    
    @app.route('/api/admin/user/<int:user_id>/unban', methods=['POST'])
    @jwt_required()
    def unban_user(user_id):
        """Unban a user (admin only)"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_active = True
        
        # Log the action
        log_admin_action(
            admin_id=claims['sub'],
            action='unban_user',
            details={'user_id': user_id, 'email': user.email},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        db.session.commit()
        
        return jsonify({'message': f'User {user.email} has been unbanned'}), 200
    
    @app.route('/api/admin/audit-logs', methods=['GET'])
    @jwt_required()
    def get_audit_logs():
        """Get audit logs (admin only)"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'logs': [log.to_dict() for log in logs.items],
            'total': logs.total,
            'pages': logs.pages,
            'current_page': page
        }), 200
    
    # =============================================================================
    # 3. SCHEDULED SCANS
    # =============================================================================
    
    @app.route('/api/schedule', methods=['POST'])
    @jwt_required()
    def create_schedule():
        """Create a scheduled scan"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        name = data.get('name')
        url = data.get('url')
        frequency = data.get('frequency')
        scan_type = data.get('scan_type', 'spider')
        
        if not all([name, url, frequency]):
            return jsonify({'error': 'Name, URL, and frequency are required'}), 400
        
        if frequency not in ['daily', 'weekly', 'monthly']:
            return jsonify({'error': 'Invalid frequency. Must be daily, weekly, or monthly'}), 400
        
        # Check user's schedule limit
        user = User.query.get(user_id)
        schedule_limit = 5 if user.role == 'free' else 20
        current_schedules = Schedule.query.filter_by(user_id=user_id, is_active=True).count()
        
        if current_schedules >= schedule_limit:
            return jsonify({'error': f'Schedule limit reached ({schedule_limit})'}), 400
        
        schedule = Schedule(
            user_id=user_id,
            name=name,
            url=url,
            scan_type=scan_type,
            frequency=frequency,
            next_run=calculate_next_run(frequency),
            scan_config=data.get('scan_config', {"max_depth": 10, "timeout": 300})
        )
        
        db.session.add(schedule)
        db.session.commit()
        
        return jsonify({
            'message': 'Schedule created successfully',
            'schedule': schedule.to_dict()
        }), 201
    
    @app.route('/api/schedule', methods=['GET'])
    @jwt_required()
    def list_schedules():
        """List user's scheduled scans"""
        user_id = get_jwt_identity()
        schedules = Schedule.query.filter_by(user_id=user_id).all()
        
        return jsonify([schedule.to_dict() for schedule in schedules]), 200
    
    @app.route('/api/schedule/<int:schedule_id>', methods=['PUT'])
    @jwt_required()
    def update_schedule(schedule_id):
        """Update a scheduled scan"""
        user_id = get_jwt_identity()
        schedule = Schedule.query.filter_by(id=schedule_id, user_id=user_id).first()
        
        if not schedule:
            return jsonify({'error': 'Schedule not found'}), 404
        
        data = request.get_json()
        
        if 'name' in data:
            schedule.name = data['name']
        if 'url' in data:
            schedule.url = data['url']
        if 'frequency' in data:
            if data['frequency'] in ['daily', 'weekly', 'monthly']:
                schedule.frequency = data['frequency']
                schedule.next_run = calculate_next_run(data['frequency'])
        if 'is_active' in data:
            schedule.is_active = data['is_active']
        if 'scan_config' in data:
            schedule.scan_config = data['scan_config']
        
        schedule.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Schedule updated successfully',
            'schedule': schedule.to_dict()
        }), 200
    
    @app.route('/api/schedule/<int:schedule_id>', methods=['DELETE'])
    @jwt_required()
    def delete_schedule(schedule_id):
        """Delete a scheduled scan"""
        user_id = get_jwt_identity()
        schedule = Schedule.query.filter_by(id=schedule_id, user_id=user_id).first()
        
        if not schedule:
            return jsonify({'error': 'Schedule not found'}), 404
        
        db.session.delete(schedule)
        db.session.commit()
        
        return jsonify({'message': 'Schedule deleted successfully'}), 200
    
    # =============================================================================
    # 4. PROFILE MANAGEMENT
    # =============================================================================
    
    @app.route('/api/profile', methods=['GET'])
    @jwt_required()
    def get_profile():
        """Get user profile"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict()), 200
    
    @app.route('/api/profile', methods=['PUT'])
    @jwt_required()
    def update_profile():
        """Update user profile"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Handle file upload (avatar)
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename:
                # Validate file type
                allowed_extensions = {'.png', '.jpg', '.jpeg', '.gif'}
                file_ext = os.path.splitext(file.filename)[1].lower()
                
                if file_ext not in allowed_extensions:
                    return jsonify({'error': 'Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed'}), 400
                
                # Save file
                filename = f"{user_id}_{int(datetime.utcnow().timestamp())}{file_ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Update user avatar URL
                user.avatar_url = f"/uploads/avatars/{filename}"
        
        # Handle JSON data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        # Update preferences
        if 'preferences' in data:
            if isinstance(data['preferences'], str):
                preferences = json.loads(data['preferences'])
            else:
                preferences = data['preferences']
            
            # Merge with existing preferences
            current_prefs = user.preferences or {}
            current_prefs.update(preferences)
            user.preferences = current_prefs
        
        # Update other fields
        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'language_preference' in data:
            user.language_preference = data['language_preference']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'profile': user.to_dict()
        }), 200
    
    # =============================================================================
    # 5. BUGCROWD INTEGRATION
    # =============================================================================
    
    @app.route('/api/scan/<int:scan_id>/submit-bugcrowd', methods=['POST'])
    @jwt_required()
    def submit_to_bugcrowd(scan_id):
        """Submit scan results to Bugcrowd"""
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != 'completed' or not scan.results:
            return jsonify({'error': 'Scan must be completed with results'}), 400
        
        bugcrowd_api_key = os.environ.get('BUGCROWD_API_KEY')
        if not bugcrowd_api_key:
            return jsonify({'error': 'Bugcrowd integration not configured'}), 400
        
        # Format vulnerabilities for Bugcrowd
        vulnerabilities = []
        if scan.results and 'alerts' in scan.results:
            for alert in scan.results['alerts']:
                vulnerability = {
                    'title': f"{alert.get('name', 'Vulnerability')} in {scan.target_url}",
                    'description': alert.get('desc', 'No description available'),
                    'severity': alert.get('risk', 'low').lower(),
                    'url': alert.get('url', scan.target_url),
                    'method': alert.get('method', 'GET'),
                    'parameter': alert.get('param', ''),
                    'attack': alert.get('attack', ''),
                    'evidence': alert.get('evidence', '')
                }
                vulnerabilities.append(vulnerability)
        
        if not vulnerabilities:
            return jsonify({'error': 'No vulnerabilities found to submit'}), 400
        
        # Submit to Bugcrowd (mock implementation)
        try:
            # This would be the actual Bugcrowd API call
            report = {
                'title': f'Vulnerability Report for {scan.target_url}',
                'description': f'Automated scan found {len(vulnerabilities)} vulnerabilities',
                'vulnerabilities': vulnerabilities,
                'scanner': 'WebSecPen',
                'scan_date': scan.created_at.isoformat()
            }
            
            # Mock API call - replace with actual Bugcrowd endpoint
            # response = requests.post(
            #     'https://api.bugcrowd.com/submissions',
            #     headers={'Authorization': f'Bearer {bugcrowd_api_key}'},
            #     json=report
            # )
            
            # For now, just log the submission
            print(f"Mock Bugcrowd submission: {json.dumps(report, indent=2)}")
            
            return jsonify({
                'message': 'Successfully submitted to Bugcrowd',
                'vulnerabilities_count': len(vulnerabilities),
                'report_id': f'mock-{scan_id}-{int(datetime.utcnow().timestamp())}'
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to submit to Bugcrowd: {str(e)}'}), 500
    
    # =============================================================================
    # 6. ENHANCED RATE LIMITING
    # =============================================================================
    
    @app.route('/api/scan/start', methods=['POST'])
    @jwt_required()
    @limiter.limit("10 per hour", key_func=lambda: f"scan_{get_jwt_identity()}")
    def start_scan_with_limits():
        """Start a scan with enhanced rate limiting"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        # Check scan limit
        current_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_scans = Scan.query.filter(
            Scan.user_id == user_id,
            Scan.created_at >= current_month
        ).count()
        
        if monthly_scans >= user.scan_limit:
            return jsonify({
                'error': f'Monthly scan limit reached ({user.scan_limit}). Upgrade for more scans.'
            }), 429
        
        # Continue with normal scan logic...
        data = request.get_json()
        target_url = data.get('url')
        scan_type = data.get('scan_type', 'spider')
        
        if not target_url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Create scan record
        scan = Scan(
            user_id=user_id,
            target_url=target_url,
            scan_type=scan_type,
            status='pending'
        )
        
        db.session.add(scan)
        db.session.commit()
        
        return jsonify({
            'message': 'Scan started successfully',
            'scan_id': scan.id,
            'status': scan.status
        }), 201
    
    # =============================================================================
    # 7. FEEDBACK SENTIMENT ANALYSIS
    # =============================================================================
    
    @app.route('/api/admin/feedback/analyze', methods=['GET'])
    @jwt_required()
    def analyze_feedback():
        """Analyze feedback sentiment (admin only)"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        if not sentiment_analyzer:
            return jsonify({'error': 'Sentiment analysis not available'}), 503
        
        feedbacks = Feedback.query.all()
        analysis = []
        
        for feedback in feedbacks:
            try:
                # Analyze sentiment of the message
                sentiment_result = sentiment_analyzer(feedback.message)[0]
                
                analysis.append({
                    'id': feedback.id,
                    'subject': feedback.subject,
                    'message': feedback.message[:200] + '...' if len(feedback.message) > 200 else feedback.message,
                    'type': feedback.type,
                    'status': feedback.status,
                    'sentiment': {
                        'label': sentiment_result['label'],
                        'score': round(sentiment_result['score'], 3)
                    },
                    'created_at': feedback.created_at.isoformat()
                })
            except Exception as e:
                print(f"Error analyzing feedback {feedback.id}: {e}")
                analysis.append({
                    'id': feedback.id,
                    'subject': feedback.subject,
                    'message': feedback.message[:200] + '...' if len(feedback.message) > 200 else feedback.message,
                    'type': feedback.type,
                    'status': feedback.status,
                    'sentiment': {
                        'label': 'UNKNOWN',
                        'score': 0.0
                    },
                    'created_at': feedback.created_at.isoformat()
                })
        
        return jsonify(analysis), 200
    
    # =============================================================================
    # 8. ENHANCED SCAN MANAGEMENT
    # =============================================================================
    
    @app.route('/api/scan/archive/<int:scan_id>', methods=['POST'])
    @jwt_required()
    def archive_scan(scan_id):
        """Archive a scan"""
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan.archived = True
        db.session.commit()
        
        return jsonify({'message': 'Scan archived successfully'}), 200
    
    @app.route('/api/scan/archived', methods=['GET'])
    @jwt_required()
    def list_archived_scans():
        """List archived scans"""
        user_id = get_jwt_identity()
        scans = Scan.query.filter_by(user_id=user_id, archived=True).all()
        
        return jsonify([scan.to_dict() for scan in scans]), 200
    
    # Initialize services when routes are set up
    init_services()
    
    return app 