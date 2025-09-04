# aug24_29_features.py - Final Advanced Features for WebSecPen (Aug 24-29, 2025)
# Real-time Tracking, AI Prioritization, Enterprise Integrations, and Collaboration

import os
import json
import secrets
import hashlib
import time
import redis
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from io import StringIO, BytesIO
import base64

from flask import Flask, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from flask_socketio import emit
from sqlalchemy import and_, or_
from croniter import croniter
from cryptography.fernet import Fernet

from models import db, User, Scan, TeamMember, Team

# Initialize encryption for API keys
try:
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key().decode())
    fernet = Fernet(ENCRYPTION_KEY.encode())
except:
    # Generate a new key if none provided
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    fernet = Fernet(ENCRYPTION_KEY.encode())
    print(f"Generated new encryption key: {ENCRYPTION_KEY}")

# Global Redis client
redis_client = None

def init_redis():
    """Initialize Redis client"""
    global redis_client
    try:
        import redis
        redis_client = redis.Redis(
            host=os.environ.get('REDIS_HOST', 'localhost'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            db=0,
            decode_responses=True
        )
        redis_client.ping()
        return True
    except Exception as e:
        print(f"Redis connection failed: {e}")
        return False

# =============================================================================
# AUGUST 24TH FEATURES - REAL-TIME TRACKING AND ONBOARDING
# =============================================================================

# 1. REAL-TIME SCAN PROGRESS TRACKING
def init_realtime_tracking(app):
    """Initialize real-time scan progress tracking"""
    
    @app.route('/api/scan/<int:scan_id>/progress', methods=['GET'])
    @jwt_required()
    def get_scan_progress(scan_id):
        """Get real-time scan progress"""
        user_id = get_jwt_identity()
        
        scan = Scan.query.filter(
            Scan.id == scan_id,
            or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        try:
            # Mock progress calculation - in real implementation, would query ZAP
            progress = calculate_scan_progress(scan)
            
            # Emit real-time update
            try:
                from app import socketio
                socketio.emit('scan_progress', {
                    'scan_id': scan.id,
                    'progress': progress,
                    'status': scan.status,
                    'estimated_completion': estimate_completion_time(scan, progress)
                }, room=f'user_{user_id}')
            except:
                pass  # SocketIO not available
            
            return jsonify({
                'progress': progress,
                'status': scan.status,
                'estimated_completion': estimate_completion_time(scan, progress)
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get progress: {str(e)}'}), 500

def calculate_scan_progress(scan):
    """Calculate scan progress based on status and timing"""
    if scan.status == 'completed':
        return 100
    elif scan.status == 'failed':
        return 0
    elif scan.status == 'running':
        # Estimate based on elapsed time
        elapsed = (datetime.utcnow() - scan.created_at).total_seconds()
        estimated_duration = 300  # 5 minutes estimated scan time
        progress = min(95, (elapsed / estimated_duration) * 100)
        return int(progress)
    else:
        return 0

def estimate_completion_time(scan, progress):
    """Estimate scan completion time"""
    if progress >= 100:
        return None
    
    elapsed = (datetime.utcnow() - scan.created_at).total_seconds()
    if progress > 0:
        total_estimated = (elapsed / progress) * 100
        remaining = total_estimated - elapsed
        completion_time = datetime.utcnow() + timedelta(seconds=remaining)
        return completion_time.isoformat()
    
    return None

# 2. USER ONBOARDING TUTORIAL
class OnboardingStep(db.Model):
    """User onboarding progress tracking"""
    __tablename__ = 'onboarding_steps'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    step_name = db.Column(db.String(50), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)

def init_onboarding_system(app):
    """Initialize user onboarding system"""
    
    @app.route('/api/onboarding/status', methods=['GET'])
    @jwt_required()
    def get_onboarding_status():
        """Get user's onboarding progress"""
        user_id = get_jwt_identity()
        
        try:
            steps = OnboardingStep.query.filter_by(user_id=user_id).all()
            
            # Define onboarding steps
            default_steps = [
                'welcome',
                'first_scan',
                'view_results',
                'setup_integrations',
                'team_collaboration'
            ]
            
            # Create missing steps
            existing_steps = {step.step_name for step in steps}
            for step_name in default_steps:
                if step_name not in existing_steps:
                    new_step = OnboardingStep(user_id=user_id, step_name=step_name)
                    db.session.add(new_step)
            
            db.session.commit()
            
            # Get updated steps
            steps = OnboardingStep.query.filter_by(user_id=user_id).all()
            
            return jsonify({
                'steps': [{
                    'name': step.step_name,
                    'completed': step.completed,
                    'completed_at': step.completed_at.isoformat() if step.completed_at else None
                } for step in steps],
                'total_steps': len(default_steps),
                'completed_steps': len([s for s in steps if s.completed])
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get onboarding status: {str(e)}'}), 500
    
    @app.route('/api/onboarding/complete/<step_name>', methods=['POST'])
    @jwt_required()
    def complete_onboarding_step(step_name):
        """Mark an onboarding step as completed"""
        user_id = get_jwt_identity()
        
        try:
            step = OnboardingStep.query.filter_by(user_id=user_id, step_name=step_name).first()
            
            if not step:
                return jsonify({'error': 'Onboarding step not found'}), 404
            
            step.completed = True
            step.completed_at = datetime.utcnow()
            db.session.commit()
            
            # Check if all steps are completed
            all_steps = OnboardingStep.query.filter_by(user_id=user_id).all()
            if all(s.completed for s in all_steps):
                user = User.query.get(user_id)
                if hasattr(user, 'preferences'):
                    user.preferences = user.preferences or {}
                    user.preferences['onboarding_completed'] = True
                    db.session.commit()
            
            return jsonify({'message': f'Step {step_name} completed'}), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to complete step: {str(e)}'}), 500

# 3. CROWDSTRIKE FALCON INTEGRATION
def init_crowdstrike_integration(app):
    """Initialize CrowdStrike Falcon integration"""
    
    @app.route('/api/scan/<int:scan_id>/crowdstrike', methods=['POST'])
    @jwt_required()
    def create_crowdstrike_alert(scan_id):
        """Create CrowdStrike alerts for high-severity vulnerabilities"""
        user_id = get_jwt_identity()
        
        scan = Scan.query.filter(
            Scan.id == scan_id,
            or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Get CrowdStrike credentials
        falcon_credentials = get_integration_credentials(user_id, 'crowdstrike')
        if not falcon_credentials:
            return jsonify({'error': 'CrowdStrike credentials not configured'}), 400
        
        try:
            import requests
            
            created_alerts = []
            alerts = scan.results.get('alerts', []) if scan.results else []
            
            for alert in alerts:
                if alert.get('risk', '').lower() == 'high':
                    
                    falcon_data = {
                        'type': 'vulnerability_detected',
                        'severity': 'high',
                        'title': f'Security Vulnerability: {alert.get("name", "Unknown")} in {scan.target_url}',
                        'description': f"""
High-risk vulnerability detected by WebSecPen:

Vulnerability: {alert.get('name', 'Unknown')}
Risk Level: {alert.get('risk', 'Unknown')}
Confidence: {alert.get('confidence', 'Unknown')}
Affected URL: {alert.get('url', scan.target_url)}
Parameter: {alert.get('param', 'N/A')}

Description:
{alert.get('desc', 'No description available')}

Evidence:
{alert.get('evidence', 'No evidence available')}

Scan Details:
- Scan ID: {scan.id}
- Target: {scan.target_url}
- Scan Date: {scan.created_at}
                        """.strip(),
                        'source': f'WebSecPen Scan {scan.id}',
                        'detection_id': f'websecpen-{scan.id}-{alert.get("pluginid", hashlib.md5(alert.get("name", "").encode()).hexdigest()[:8])}',
                        'custom_details': {
                            'scan_id': scan.id,
                            'target_url': scan.target_url,
                            'vulnerability_type': alert.get('name'),
                            'risk_level': alert.get('risk'),
                            'affected_parameter': alert.get('param'),
                            'solution': alert.get('solution', 'No solution provided')
                        }
                    }
                    
                    # Mock API call - replace with actual CrowdStrike API
                    response = mock_crowdstrike_api_call(falcon_credentials, falcon_data)
                    
                    if response.get('success'):
                        created_alerts.append({
                            'detection_id': falcon_data['detection_id'],
                            'vulnerability': alert.get('name'),
                            'status': 'created',
                            'falcon_id': response.get('falcon_id')
                        })
                    else:
                        created_alerts.append({
                            'detection_id': falcon_data['detection_id'],
                            'vulnerability': alert.get('name'),
                            'status': 'failed',
                            'error': response.get('error', 'Unknown error')
                        })
            
            return jsonify({
                'message': f'CrowdStrike integration completed',
                'alerts_created': len([a for a in created_alerts if a['status'] == 'created']),
                'alerts_failed': len([a for a in created_alerts if a['status'] == 'failed']),
                'alerts': created_alerts
            }), 200
            
        except Exception as e:
            app.logger.error(f'CrowdStrike integration error: {str(e)}')
            return jsonify({'error': f'CrowdStrike integration failed: {str(e)}'}), 500

def mock_crowdstrike_api_call(credentials, data):
    """Mock CrowdStrike API call - replace with actual implementation"""
    # In real implementation, this would make actual API calls to CrowdStrike
    return {
        'success': True,
        'falcon_id': f'falcon_{secrets.token_hex(8)}',
        'message': 'Alert created successfully'
    }

# 4. VULNERABILITY REMEDIATION TRACKING
class VulnerabilityStatus(db.Model):
    """Track vulnerability remediation status"""
    __tablename__ = 'vulnerability_statuses'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    vuln_id = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(20), default='open')  # open, remediated, false_positive, in_progress
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    notes = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

def init_remediation_tracking(app):
    """Initialize vulnerability remediation tracking"""
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities/<vuln_id>/status', methods=['PUT'])
    @jwt_required()
    def update_vulnerability_status(scan_id, vuln_id):
        """Update vulnerability remediation status"""
        user_id = get_jwt_identity()
        
        scan = Scan.query.filter(
            Scan.id == scan_id,
            or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        try:
            data = request.get_json()
            status = data.get('status')
            assigned_to = data.get('assigned_to')
            notes = data.get('notes')
            
            valid_statuses = ['open', 'remediated', 'false_positive', 'in_progress']
            if status not in valid_statuses:
                return jsonify({'error': f'Invalid status. Must be one of: {valid_statuses}'}), 400
            
            # Find or create vulnerability status record
            vuln_status = VulnerabilityStatus.query.filter_by(
                scan_id=scan_id, 
                vuln_id=vuln_id
            ).first()
            
            if not vuln_status:
                vuln_status = VulnerabilityStatus(
                    scan_id=scan_id,
                    vuln_id=vuln_id,
                    status=status,
                    assigned_to=assigned_to,
                    notes=notes
                )
                db.session.add(vuln_status)
            else:
                vuln_status.status = status
                if assigned_to:
                    vuln_status.assigned_to = assigned_to
                if notes:
                    vuln_status.notes = notes
                vuln_status.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            # Emit real-time update
            try:
                from app import socketio
                socketio.emit('vulnerability_status_update', {
                    'scan_id': scan_id,
                    'vuln_id': vuln_id,
                    'status': status,
                    'assigned_to': assigned_to,
                    'updated_by': user_id,
                    'updated_at': vuln_status.updated_at.isoformat()
                }, room=f'team_{scan.team_id}' if scan.team_id else f'user_{user_id}')
            except:
                pass
            
            return jsonify({
                'message': 'Vulnerability status updated',
                'status': status,
                'updated_at': vuln_status.updated_at.isoformat()
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to update status: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities/<vuln_id>/status', methods=['GET'])
    @jwt_required()
    def get_vulnerability_status(scan_id, vuln_id):
        """Get vulnerability remediation status"""
        user_id = get_jwt_identity()
        
        scan = Scan.query.filter(
            Scan.id == scan_id,
            or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        try:
            vuln_status = VulnerabilityStatus.query.filter_by(
                scan_id=scan_id, 
                vuln_id=vuln_id
            ).first()
            
            if not vuln_status:
                return jsonify({
                    'status': 'open',
                    'assigned_to': None,
                    'notes': None,
                    'updated_at': None
                }), 200
            
            return jsonify({
                'status': vuln_status.status,
                'assigned_to': vuln_status.assigned_to,
                'notes': vuln_status.notes,
                'updated_at': vuln_status.updated_at.isoformat()
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get status: {str(e)}'}), 500

# =============================================================================
# AUGUST 25TH FEATURES - AI PRIORITIZATION AND INTEGRATIONS
# =============================================================================

# 1. AI-DRIVEN VULNERABILITY PRIORITIZATION
def init_ai_prioritization(app):
    """Initialize AI-driven vulnerability prioritization"""
    
    @app.route('/api/scan/<int:scan_id>/prioritize', methods=['GET'])
    @jwt_required()
    def prioritize_vulnerabilities(scan_id):
        """AI-driven vulnerability prioritization"""
        user_id = get_jwt_identity()
        
        scan = Scan.query.filter(
            Scan.id == scan_id,
            or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        try:
            # Check cache first
            cache_key = f'priority:{scan_id}'
            if redis_client:
                cached = redis_client.get(cache_key)
                if cached:
                    return jsonify(json.loads(cached)), 200
            
            prioritized = []
            alerts = scan.results.get('alerts', []) if scan.results else []
            
            for alert in alerts:
                # Calculate priority score using multiple factors
                priority_score = calculate_vulnerability_priority(alert)
                
                prioritized.append({
                    'id': alert.get('pluginid', alert.get('name', '')),
                    'name': alert.get('name', 'Unknown'),
                    'type': alert.get('name', 'Unknown'),
                    'risk': alert.get('risk', 'Unknown'),
                    'confidence': alert.get('confidence', 'Unknown'),
                    'description': alert.get('desc', ''),
                    'priority_score': round(priority_score, 2),
                    'priority_level': get_priority_level(priority_score),
                    'exploitability': calculate_exploitability_score(alert),
                    'business_impact': calculate_business_impact(alert),
                    'technical_severity': calculate_technical_severity(alert)
                })
            
            # Sort by priority score (highest first)
            prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
            
            # Cache results
            if redis_client:
                redis_client.setex(cache_key, 3600, json.dumps(prioritized))
            
            return jsonify({
                'vulnerabilities': prioritized,
                'total_count': len(prioritized),
                'high_priority_count': len([v for v in prioritized if v['priority_level'] == 'Critical']),
                'medium_priority_count': len([v for v in prioritized if v['priority_level'] == 'High']),
                'low_priority_count': len([v for v in prioritized if v['priority_level'] in ['Medium', 'Low']])
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to prioritize vulnerabilities: {str(e)}'}), 500

def calculate_vulnerability_priority(alert):
    """Calculate vulnerability priority score using AI-like factors"""
    
    # Base severity score
    risk_scores = {
        'high': 0.9,
        'medium': 0.6,
        'low': 0.3,
        'informational': 0.1
    }
    severity_score = risk_scores.get(alert.get('risk', '').lower(), 0.5)
    
    # Confidence score
    confidence_scores = {
        'high': 0.9,
        'medium': 0.7,
        'low': 0.4,
        'false positive': 0.1
    }
    confidence_score = confidence_scores.get(alert.get('confidence', '').lower(), 0.5)
    
    # Exploitability score based on vulnerability type
    exploitability_score = calculate_exploitability_score(alert)
    
    # Business impact score
    business_impact_score = calculate_business_impact(alert)
    
    # Technical complexity score
    technical_score = calculate_technical_severity(alert)
    
    # Weighted combination
    priority_score = (
        severity_score * 0.3 +
        confidence_score * 0.2 +
        exploitability_score * 0.25 +
        business_impact_score * 0.15 +
        technical_score * 0.1
    )
    
    return priority_score

def calculate_exploitability_score(alert):
    """Calculate exploitability score based on vulnerability characteristics"""
    vuln_name = alert.get('name', '').lower()
    
    # High exploitability vulnerabilities
    high_exploitability = [
        'sql injection', 'remote code execution', 'command injection',
        'cross-site scripting', 'path traversal', 'file inclusion'
    ]
    
    # Medium exploitability vulnerabilities
    medium_exploitability = [
        'cross-site request forgery', 'information disclosure',
        'authentication bypass', 'privilege escalation'
    ]
    
    # Check for high exploitability patterns
    for pattern in high_exploitability:
        if pattern in vuln_name:
            return 0.9
    
    # Check for medium exploitability patterns
    for pattern in medium_exploitability:
        if pattern in vuln_name:
            return 0.6
    
    # Default to medium-low exploitability
    return 0.4

def calculate_business_impact(alert):
    """Calculate business impact score"""
    url = alert.get('url', '').lower()
    
    # High impact areas
    if any(keyword in url for keyword in ['admin', 'login', 'payment', 'api', 'database']):
        return 0.8
    
    # Medium impact areas
    if any(keyword in url for keyword in ['user', 'account', 'profile', 'upload']):
        return 0.6
    
    # Default impact
    return 0.4

def calculate_technical_severity(alert):
    """Calculate technical severity based on attack complexity"""
    description = alert.get('desc', '').lower()
    
    # High technical severity indicators
    if any(keyword in description for keyword in ['remote', 'unauthenticated', 'bypass', 'execute']):
        return 0.8
    
    # Medium technical severity
    if any(keyword in description for keyword in ['local', 'authenticated', 'disclosure']):
        return 0.5
    
    # Low technical severity
    return 0.3

def get_priority_level(score):
    """Convert priority score to human-readable level"""
    if score >= 0.8:
        return 'Critical'
    elif score >= 0.6:
        return 'High'
    elif score >= 0.4:
        return 'Medium'
    else:
        return 'Low'

# 2. USER FEEDBACK SURVEYS
class Feedback(db.Model):
    """User feedback collection"""
    __tablename__ = 'feedback'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(200))
    message = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer)  # 1-5 star rating
    category = db.Column(db.String(50))  # bug, feature_request, general
    status = db.Column(db.String(20), default='open')  # open, reviewed, closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_feedback_system(app):
    """Initialize user feedback system"""
    
    @app.route('/api/feedback', methods=['POST'])
    @jwt_required()
    def submit_feedback():
        """Submit user feedback"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        try:
            feedback = Feedback(
                user_id=user_id,
                subject=data.get('subject'),
                message=data.get('message'),
                rating=data.get('rating'),
                category=data.get('category', 'general')
            )
            
            # Validate rating if provided
            if feedback.rating and (feedback.rating < 1 or feedback.rating > 5):
                return jsonify({'error': 'Rating must be between 1 and 5'}), 400
            
            db.session.add(feedback)
            db.session.commit()
            
            # Notify admins
            try:
                from app import socketio
                socketio.emit('new_feedback', {
                    'id': feedback.id,
                    'subject': feedback.subject,
                    'rating': feedback.rating,
                    'category': feedback.category,
                    'user_id': user_id
                }, room='admin')
            except:
                pass
            
            return jsonify({
                'message': 'Feedback submitted successfully',
                'feedback_id': feedback.id
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to submit feedback: {str(e)}'}), 500
    
    @app.route('/api/admin/feedback', methods=['GET'])
    @jwt_required()
    def get_all_feedback():
        """Get all user feedback (admin only)"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            feedback_items = Feedback.query.order_by(Feedback.created_at.desc()).all()
            
            return jsonify([{
                'id': f.id,
                'user_id': f.user_id,
                'subject': f.subject,
                'message': f.message,
                'rating': f.rating,
                'category': f.category,
                'status': f.status,
                'created_at': f.created_at.isoformat()
            } for f in feedback_items]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get feedback: {str(e)}'}), 500

# =============================================================================
# AUGUST 26TH FEATURES - AUTOMATED REMEDIATION AND CUSTOMIZATION
# =============================================================================

# 1. AUTOMATED REMEDIATION SUGGESTIONS
def init_remediation_ai(app):
    """Initialize AI-driven remediation suggestions"""
    
    @app.route('/api/scan/<int:scan_id>/remediations', methods=['GET'])
    @jwt_required()
    def get_remediation_suggestions(scan_id):
        """Get AI-generated remediation suggestions"""
        user_id = get_jwt_identity()
        
        scan = Scan.query.filter(
            Scan.id == scan_id,
            or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        try:
            # Check cache first
            cache_key = f'remediation:{scan_id}'
            if redis_client:
                cached = redis_client.get(cache_key)
                if cached:
                    return jsonify(json.loads(cached)), 200
            
            remediations = []
            alerts = scan.results.get('alerts', []) if scan.results else []
            
            for alert in alerts:
                remediation = generate_remediation_suggestion(alert)
                
                remediations.append({
                    'vuln_id': alert.get('pluginid', alert.get('name', '')),
                    'vuln_name': alert.get('name', 'Unknown'),
                    'risk_level': alert.get('risk', 'Unknown'),
                    'remediation': remediation,
                    'difficulty': estimate_remediation_difficulty(alert),
                    'estimated_time': estimate_remediation_time(alert),
                    'resources': get_remediation_resources(alert)
                })
            
            # Cache results
            if redis_client:
                redis_client.setex(cache_key, 3600, json.dumps(remediations))
            
            return jsonify({
                'remediations': remediations,
                'total_count': len(remediations)
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get remediations: {str(e)}'}), 500

def generate_remediation_suggestion(alert):
    """Generate remediation suggestion based on vulnerability type"""
    vuln_name = alert.get('name', '').lower()
    description = alert.get('desc', '')
    
    # Common remediation patterns
    remediations = {
        'sql injection': {
            'steps': [
                'Implement parameterized queries or prepared statements',
                'Validate and sanitize all user inputs',
                'Use stored procedures with proper input validation',
                'Apply principle of least privilege to database accounts',
                'Enable database activity monitoring'
            ],
            'code_example': """
# Example: Secure parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# Instead of: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            """.strip()
        },
        'cross-site scripting': {
            'steps': [
                'Encode all output data before displaying to users',
                'Validate and sanitize all user inputs',
                'Implement Content Security Policy (CSP) headers',
                'Use secure frameworks that auto-escape output',
                'Apply context-aware encoding'
            ],
            'code_example': """
# Example: Secure output encoding
import html
safe_output = html.escape(user_input)
# Or use template engine auto-escaping
            """.strip()
        },
        'remote code execution': {
            'steps': [
                'Remove or secure the vulnerable functionality',
                'Implement strict input validation and filtering',
                'Use safe APIs that don\'t execute user input',
                'Apply sandboxing and containerization',
                'Update all software components to latest versions'
            ],
            'code_example': """
# Example: Safe file operations
import os.path
safe_path = os.path.normpath(os.path.join(base_dir, user_filename))
if not safe_path.startswith(base_dir):
    raise ValueError("Invalid file path")
            """.strip()
        }
    }
    
    # Find matching remediation
    for pattern, remediation in remediations.items():
        if pattern in vuln_name:
            return remediation
    
    # Default remediation
    return {
        'steps': [
            'Review the vulnerability details carefully',
            'Consult security documentation for the affected component',
            'Apply available security patches or updates',
            'Implement additional security controls as needed',
            'Test the fix in a safe environment before production'
        ],
        'code_example': '# Consult specific documentation for this vulnerability type'
    }

def estimate_remediation_difficulty(alert):
    """Estimate remediation difficulty"""
    vuln_name = alert.get('name', '').lower()
    
    high_difficulty = ['remote code execution', 'privilege escalation', 'authentication bypass']
    medium_difficulty = ['sql injection', 'cross-site scripting', 'command injection']
    
    for pattern in high_difficulty:
        if pattern in vuln_name:
            return 'High'
    
    for pattern in medium_difficulty:
        if pattern in vuln_name:
            return 'Medium'
    
    return 'Low'

def estimate_remediation_time(alert):
    """Estimate remediation time"""
    difficulty = estimate_remediation_difficulty(alert)
    
    time_estimates = {
        'High': '2-5 days',
        'Medium': '4-8 hours',
        'Low': '1-2 hours'
    }
    
    return time_estimates.get(difficulty, '2-4 hours')

def get_remediation_resources(alert):
    """Get relevant remediation resources"""
    vuln_name = alert.get('name', '').lower()
    
    resources = []
    
    if 'sql injection' in vuln_name:
        resources.extend([
            'OWASP SQL Injection Prevention Cheat Sheet',
            'Database-specific security documentation',
            'Parameterized query examples'
        ])
    elif 'cross-site scripting' in vuln_name:
        resources.extend([
            'OWASP XSS Prevention Cheat Sheet',
            'Content Security Policy documentation',
            'Framework-specific encoding guidelines'
        ])
    elif 'remote code execution' in vuln_name:
        resources.extend([
            'OWASP Code Injection Prevention',
            'Secure coding guidelines',
            'Input validation best practices'
        ])
    else:
        resources.extend([
            'OWASP Top 10 documentation',
            'Security best practices guide',
            'Vendor security advisories'
        ])
    
    return resources

# 2. ROLE-BASED DASHBOARD WIDGETS
class DashboardWidget(db.Model):
    """Dashboard widget configuration"""
    __tablename__ = 'dashboard_widgets'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    widget_type = db.Column(db.String(50), nullable=False)
    config = db.Column(db.JSON, nullable=False)
    position = db.Column(db.Integer, default=0)
    size = db.Column(db.String(20), default='medium')  # small, medium, large
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_dashboard_customization(app):
    """Initialize dashboard customization"""
    
    @app.route('/api/dashboard/widgets', methods=['GET'])
    @jwt_required()
    def get_dashboard_widgets():
        """Get user's dashboard widgets"""
        user_id = get_jwt_identity()
        
        try:
            widgets = DashboardWidget.query.filter_by(
                user_id=user_id, 
                enabled=True
            ).order_by(DashboardWidget.position).all()
            
            return jsonify([{
                'id': w.id,
                'widget_type': w.widget_type,
                'config': w.config,
                'position': w.position,
                'size': w.size,
                'created_at': w.created_at.isoformat()
            } for w in widgets]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get widgets: {str(e)}'}), 500
    
    @app.route('/api/dashboard/widgets', methods=['POST'])
    @jwt_required()
    def add_dashboard_widget():
        """Add a new dashboard widget"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        try:
            widget = DashboardWidget(
                user_id=user_id,
                widget_type=data.get('widget_type'),
                config=data.get('config', {}),
                position=data.get('position', 0),
                size=data.get('size', 'medium')
            )
            
            db.session.add(widget)
            db.session.commit()
            
            return jsonify({
                'id': widget.id,
                'message': 'Widget added successfully'
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to add widget: {str(e)}'}), 500

# =============================================================================
# AUGUST 27TH FEATURES - ADVANCED SCHEDULING AND ANALYTICS
# =============================================================================

# 1. CRON-BASED SCAN SCHEDULING
class CronSchedule(db.Model):
    """Cron-based scan scheduling"""
    __tablename__ = 'cron_schedules'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    target_url = db.Column(db.String(255), nullable=False)
    cron_expression = db.Column(db.String(50), nullable=False)
    scan_config = db.Column(db.JSON, default={})
    enabled = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_advanced_scheduling(app):
    """Initialize advanced cron-based scheduling"""
    
    @app.route('/api/schedule/cron', methods=['POST'])
    @jwt_required()
    def create_cron_schedule():
        """Create a cron-based scan schedule"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        try:
            name = data.get('name')
            target_url = data.get('target_url')
            cron_expression = data.get('cron_expression')
            scan_config = data.get('scan_config', {})
            
            if not all([name, target_url, cron_expression]):
                return jsonify({'error': 'Missing required fields'}), 400
            
            # Validate cron expression
            try:
                cron = croniter(cron_expression, datetime.utcnow())
                next_run = cron.get_next(datetime)
            except ValueError as e:
                return jsonify({'error': f'Invalid cron expression: {str(e)}'}), 400
            
            schedule = CronSchedule(
                user_id=user_id,
                name=name,
                target_url=target_url,
                cron_expression=cron_expression,
                scan_config=scan_config,
                next_run=next_run
            )
            
            db.session.add(schedule)
            db.session.commit()
            
            return jsonify({
                'id': schedule.id,
                'name': name,
                'target_url': target_url,
                'cron_expression': cron_expression,
                'next_run': next_run.isoformat(),
                'message': 'Schedule created successfully'
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to create schedule: {str(e)}'}), 500
    
    @app.route('/api/schedule/cron', methods=['GET'])
    @jwt_required()
    def get_cron_schedules():
        """Get user's cron schedules"""
        user_id = get_jwt_identity()
        
        try:
            schedules = CronSchedule.query.filter_by(user_id=user_id).all()
            
            return jsonify([{
                'id': s.id,
                'name': s.name,
                'target_url': s.target_url,
                'cron_expression': s.cron_expression,
                'enabled': s.enabled,
                'last_run': s.last_run.isoformat() if s.last_run else None,
                'next_run': s.next_run.isoformat() if s.next_run else None,
                'created_at': s.created_at.isoformat()
            } for s in schedules]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get schedules: {str(e)}'}), 500

# =============================================================================
# AUGUST 28TH-29TH FEATURES - API KEY MANAGEMENT AND COLLABORATION
# =============================================================================

# 1. SECURE API KEY MANAGEMENT
class IntegrationApiKey(db.Model):
    """Secure API key storage for integrations"""
    __tablename__ = 'integration_api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    integration_name = db.Column(db.String(50), nullable=False)
    encrypted_credentials = db.Column(db.Text, nullable=False)
    key_prefix = db.Column(db.String(20))  # First few chars for identification
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)

def init_api_key_management(app):
    """Initialize secure API key management"""
    
    @app.route('/api/integrations/keys', methods=['POST'])
    @jwt_required()
    def add_integration_key():
        """Add encrypted integration API key"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        try:
            integration_name = data.get('integration_name')
            credentials = data.get('credentials')  # Can be dict for multiple keys
            description = data.get('description', '')
            
            if not integration_name or not credentials:
                return jsonify({'error': 'Missing integration_name or credentials'}), 400
            
            # Encrypt credentials
            credentials_json = json.dumps(credentials)
            encrypted_credentials = fernet.encrypt(credentials_json.encode()).decode()
            
            # Generate key prefix for identification
            if isinstance(credentials, dict):
                first_key = list(credentials.values())[0]
            else:
                first_key = str(credentials)
            key_prefix = first_key[:4] + '...' if len(first_key) > 4 else first_key
            
            # Check if key already exists for this integration
            existing_key = IntegrationApiKey.query.filter_by(
                user_id=user_id,
                integration_name=integration_name
            ).first()
            
            if existing_key:
                # Update existing key
                existing_key.encrypted_credentials = encrypted_credentials
                existing_key.key_prefix = key_prefix
                existing_key.description = description
                db.session.commit()
                key_id = existing_key.id
            else:
                # Create new key
                api_key = IntegrationApiKey(
                    user_id=user_id,
                    integration_name=integration_name,
                    encrypted_credentials=encrypted_credentials,
                    key_prefix=key_prefix,
                    description=description
                )
                db.session.add(api_key)
                db.session.commit()
                key_id = api_key.id
            
            return jsonify({
                'id': key_id,
                'integration_name': integration_name,
                'key_prefix': key_prefix,
                'message': 'API key saved successfully'
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to save API key: {str(e)}'}), 500
    
    @app.route('/api/integrations/keys', methods=['GET'])
    @jwt_required()
    def get_integration_keys():
        """Get user's integration API keys (without revealing actual keys)"""
        user_id = get_jwt_identity()
        
        try:
            keys = IntegrationApiKey.query.filter_by(user_id=user_id).all()
            
            return jsonify([{
                'id': k.id,
                'integration_name': k.integration_name,
                'key_prefix': k.key_prefix,
                'description': k.description,
                'created_at': k.created_at.isoformat(),
                'last_used': k.last_used.isoformat() if k.last_used else None
            } for k in keys]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get API keys: {str(e)}'}), 500

def get_integration_credentials(user_id, integration_name):
    """Get decrypted credentials for an integration"""
    try:
        api_key = IntegrationApiKey.query.filter_by(
            user_id=user_id,
            integration_name=integration_name
        ).first()
        
        if not api_key:
            return None
        
        # Update last used timestamp
        api_key.last_used = datetime.utcnow()
        db.session.commit()
        
        # Decrypt and return credentials
        decrypted_json = fernet.decrypt(api_key.encrypted_credentials.encode()).decode()
        return json.loads(decrypted_json)
        
    except Exception as e:
        print(f"Failed to get credentials for {integration_name}: {e}")
        return None

# 2. COLLABORATION COMMENTS
class CollaborationComment(db.Model):
    """Team collaboration comments on vulnerabilities"""
    __tablename__ = 'collaboration_comments'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    vuln_id = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment_text = db.Column(db.Text, nullable=False)
    comment_type = db.Column(db.String(20), default='general')  # general, remediation, false_positive
    parent_comment_id = db.Column(db.Integer, db.ForeignKey('collaboration_comments.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

def init_collaboration_system(app):
    """Initialize collaboration comment system"""
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities/<vuln_id>/comments', methods=['POST'])
    @jwt_required()
    def add_collaboration_comment(scan_id, vuln_id):
        """Add a collaboration comment"""
        user_id = get_jwt_identity()
        
        scan = Scan.query.filter(
            Scan.id == scan_id,
            or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        try:
            data = request.get_json()
            comment_text = data.get('comment_text')
            comment_type = data.get('comment_type', 'general')
            parent_comment_id = data.get('parent_comment_id')
            
            if not comment_text:
                return jsonify({'error': 'Comment text is required'}), 400
            
            comment = CollaborationComment(
                scan_id=scan_id,
                vuln_id=vuln_id,
                user_id=user_id,
                comment_text=comment_text,
                comment_type=comment_type,
                parent_comment_id=parent_comment_id
            )
            
            db.session.add(comment)
            db.session.commit()
            
            # Emit real-time update
            try:
                from app import socketio
                socketio.emit('new_collaboration_comment', {
                    'id': comment.id,
                    'scan_id': scan_id,
                    'vuln_id': vuln_id,
                    'user_id': user_id,
                    'comment_text': comment_text,
                    'comment_type': comment_type,
                    'created_at': comment.created_at.isoformat()
                }, room=f'team_{scan.team_id}' if scan.team_id else f'user_{user_id}')
            except:
                pass
            
            return jsonify({
                'id': comment.id,
                'message': 'Comment added successfully'
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to add comment: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities/<vuln_id>/comments', methods=['GET'])
    @jwt_required()
    def get_collaboration_comments(scan_id, vuln_id):
        """Get collaboration comments for a vulnerability"""
        user_id = get_jwt_identity()
        
        scan = Scan.query.filter(
            Scan.id == scan_id,
            or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        try:
            comments = CollaborationComment.query.filter_by(
                scan_id=scan_id,
                vuln_id=vuln_id
            ).order_by(CollaborationComment.created_at.desc()).all()
            
            return jsonify([{
                'id': c.id,
                'user_id': c.user_id,
                'comment_text': c.comment_text,
                'comment_type': c.comment_type,
                'parent_comment_id': c.parent_comment_id,
                'created_at': c.created_at.isoformat(),
                'updated_at': c.updated_at.isoformat()
            } for c in comments]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get comments: {str(e)}'}), 500

# =============================================================================
# NOTIFICATION SYSTEM
# =============================================================================

class UserNotification(db.Model):
    """User notification system"""
    __tablename__ = 'user_notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, urgent
    read = db.Column(db.Boolean, default=False)
    read_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_notification_system(app):
    """Initialize notification system"""
    
    @app.route('/api/notifications', methods=['GET'])
    @jwt_required()
    def get_user_notifications():
        """Get user notifications"""
        user_id = get_jwt_identity()
        
        try:
            unread_only = request.args.get('unread_only', 'false').lower() == 'true'
            limit = int(request.args.get('limit', 50))
            
            query = UserNotification.query.filter_by(user_id=user_id)
            
            if unread_only:
                query = query.filter_by(read=False)
            
            notifications = query.order_by(
                UserNotification.created_at.desc()
            ).limit(limit).all()
            
            return jsonify([{
                'id': n.id,
                'title': n.title,
                'message': n.message,
                'notification_type': n.notification_type,
                'priority': n.priority,
                'read': n.read,
                'read_at': n.read_at.isoformat() if n.read_at else None,
                'created_at': n.created_at.isoformat()
            } for n in notifications]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get notifications: {str(e)}'}), 500
    
    @app.route('/api/notifications/<int:notification_id>/read', methods=['PUT'])
    @jwt_required()
    def mark_notification_read(notification_id):
        """Mark notification as read"""
        user_id = get_jwt_identity()
        
        try:
            notification = UserNotification.query.filter_by(
                id=notification_id,
                user_id=user_id
            ).first()
            
            if not notification:
                return jsonify({'error': 'Notification not found'}), 404
            
            notification.read = True
            notification.read_at = datetime.utcnow()
            db.session.commit()
            
            return jsonify({'message': 'Notification marked as read'}), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to mark notification as read: {str(e)}'}), 500

def create_notification(user_id, title, message, notification_type, priority='normal'):
    """Helper function to create notifications"""
    try:
        notification = UserNotification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type,
            priority=priority
        )
        
        db.session.add(notification)
        db.session.commit()
        
        # Emit real-time notification
        try:
            from app import socketio
            socketio.emit('new_notification', {
                'id': notification.id,
                'title': title,
                'message': message,
                'notification_type': notification_type,
                'priority': priority,
                'created_at': notification.created_at.isoformat()
            }, room=f'user_{user_id}')
        except:
            pass
        
        return notification
        
    except Exception as e:
        print(f"Failed to create notification: {e}")
        return None

# =============================================================================
# MAIN INITIALIZATION FUNCTION
# =============================================================================

def init_aug24_29_routes(app):
    """Initialize all August 24-29 features"""
    
    # Initialize Redis
    redis_available = init_redis()
    if not redis_available:
        print("Warning: Redis not available. Some features may not work properly.")
    
    # Create database tables
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"Database initialization warning: {e}")
    
    # Initialize all feature modules
    init_realtime_tracking(app)
    init_onboarding_system(app)
    init_crowdstrike_integration(app)
    init_remediation_tracking(app)
    init_ai_prioritization(app)
    init_feedback_system(app)
    init_remediation_ai(app)
    init_dashboard_customization(app)
    init_advanced_scheduling(app)
    init_api_key_management(app)
    init_collaboration_system(app)
    init_notification_system(app)
    
    print("✅ August 24-29 features initialized successfully!")
    print("🔧 Features: Real-time Tracking, AI Prioritization, Advanced Scheduling, Collaboration, Secure API Management")
    
    return app 