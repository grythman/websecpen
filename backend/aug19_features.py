# aug19_features.py - Advanced Features for WebSecPen (Aug 19, 2025)
# Trend Analysis, Notifications, and Advanced Integrations

import os
import json
import secrets
import requests
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from flask import Flask, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from models import db, User, Scan, TeamMember

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
# 1. VULNERABILITY TREND ANALYSIS
# =============================================================================

def init_trend_analysis_routes(app):
    """Initialize vulnerability trend analysis routes"""
    
    @app.route('/api/scan/trends-v1', methods=['GET'])
    @jwt_required()
    def get_scan_trends_v1():
        """Get vulnerability trends over time"""
        user_id = get_jwt_identity()
        
        # Get date range from query params or default to 30 days
        days = int(request.args.get('days', 30))
        start_date = datetime.utcnow() - timedelta(days=days)
        
        try:
            # Get user's scans within date range
            scans = Scan.query.filter(
                Scan.created_at >= start_date,
                db.or_(
                    Scan.user_id == user_id,
                    Scan.team_id.in_(
                        db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                    )
                )
            ).order_by(Scan.created_at).all()
            
            # Aggregate trends by vulnerability type and date
            trends = defaultdict(lambda: defaultdict(int))
            severity_trends = defaultdict(lambda: defaultdict(int))
            dates = set()
            
            for scan in scans:
                date = scan.created_at.strftime('%Y-%m-%d')
                dates.add(date)
                
                if scan.results and isinstance(scan.results, dict):
                    alerts = scan.results.get('alerts', [])
                    for vuln in alerts:
                        vuln_type = vuln.get('name', 'Unknown')[:20]  # Truncate for readability
                        severity = vuln.get('risk', 'Low').title()
                        
                        trends[vuln_type][date] += 1
                        severity_trends[severity][date] += 1
            
            sorted_dates = sorted(dates)
            
            # Prepare trend data
            trend_data = []
            for vuln_type in list(trends.keys())[:10]:  # Limit to top 10 types
                data_points = [trends[vuln_type].get(date, 0) for date in sorted_dates]
                trend_data.append({
                    'label': vuln_type,
                    'data': data_points
                })
            
            # Prepare severity trend data
            severity_data = []
            for severity in ['High', 'Medium', 'Low', 'Informational']:
                if severity in severity_trends:
                    data_points = [severity_trends[severity].get(date, 0) for date in sorted_dates]
                    severity_data.append({
                        'label': severity,
                        'data': data_points
                    })
            
            return jsonify({
                'dates': sorted_dates,
                'vulnerability_trends': trend_data,
                'severity_trends': severity_data,
                'total_scans': len(scans),
                'date_range': {
                    'start': start_date.isoformat(),
                    'end': datetime.utcnow().isoformat(),
                    'days': days
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to fetch trends: {str(e)}'}), 500
    
    @app.route('/api/scan/severity-v1', methods=['GET'])
    @jwt_required()
    def get_severity_breakdown_v1():
        """Get vulnerability severity breakdown"""
        user_id = get_jwt_identity()
        
        try:
            scans = Scan.query.filter(
                db.or_(
                    Scan.user_id == user_id,
                    Scan.team_id.in_(
                        db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                    )
                )
            ).all()
            
            severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            total_vulnerabilities = 0
            
            for scan in scans:
                if scan.results and isinstance(scan.results, dict):
                    alerts = scan.results.get('alerts', [])
                    for vuln in alerts:
                        severity = vuln.get('risk', 'Low').title()
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                        else:
                            severity_counts['Low'] += 1  # Default fallback
                        total_vulnerabilities += 1
            
            return jsonify({
                'labels': list(severity_counts.keys()),
                'data': list(severity_counts.values()),
                'total_vulnerabilities': total_vulnerabilities,
                'breakdown_percentages': {
                    severity: round((count / total_vulnerabilities * 100), 1) if total_vulnerabilities > 0 else 0
                    for severity, count in severity_counts.items()
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to fetch severity data: {str(e)}'}), 500

# =============================================================================
# 2. USER NOTIFICATION PREFERENCES
# =============================================================================

def create_notification_settings_model():
    """Model definition for NotificationSettings (to be added to models.py)"""
    return '''
class NotificationSettings(db.Model):
    __tablename__ = 'notification_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    email = db.Column(db.Boolean, default=True)
    in_app = db.Column(db.Boolean, default=True)
    slack = db.Column(db.Boolean, default=False)
    sms = db.Column(db.Boolean, default=False)
    high_severity_only = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='notification_settings')
    
    def to_dict(self):
        return {
            'email': self.email,
            'in_app': self.in_app,
            'slack': self.slack,
            'sms': self.sms,
            'high_severity_only': self.high_severity_only
        }
'''

def init_notification_routes(app):
    """Initialize notification preference routes"""
    
    @app.route('/api/notification/settings', methods=['GET', 'PUT'])
    @jwt_required()
    def manage_notification_settings():
        """Get or update notification settings"""
        user_id = get_jwt_identity()
        
        try:
            # For now, simulate with Redis storage
            settings_key = f"notification_settings:{user_id}"
            
            if request.method == 'GET':
                if redis_client:
                    settings_json = redis_client.get(settings_key)
                    if settings_json:
                        settings = json.loads(settings_json)
                    else:
                        # Default settings
                        settings = {
                            'email': True,
                            'in_app': True,
                            'slack': False,
                            'sms': False,
                            'high_severity_only': False
                        }
                        redis_client.setex(settings_key, 86400 * 365, json.dumps(settings))
                else:
                    settings = {
                        'email': True,
                        'in_app': True,
                        'slack': False,
                        'sms': False,
                        'high_severity_only': False
                    }
                
                return jsonify(settings), 200
            
            elif request.method == 'PUT':
                data = request.get_json()
                
                # Get current settings
                current_settings = {
                    'email': True,
                    'in_app': True,
                    'slack': False,
                    'sms': False,
                    'high_severity_only': False
                }
                
                if redis_client:
                    settings_json = redis_client.get(settings_key)
                    if settings_json:
                        current_settings = json.loads(settings_json)
                
                # Update settings
                current_settings.update({
                    'email': data.get('email', current_settings['email']),
                    'in_app': data.get('in_app', current_settings['in_app']),
                    'slack': data.get('slack', current_settings['slack']),
                    'sms': data.get('sms', current_settings['sms']),
                    'high_severity_only': data.get('high_severity_only', current_settings['high_severity_only'])
                })
                
                # Save settings
                if redis_client:
                    redis_client.setex(settings_key, 86400 * 365, json.dumps(current_settings))
                
                return jsonify({
                    'message': 'Settings updated successfully',
                    'settings': current_settings
                }), 200
                
        except Exception as e:
            return jsonify({'error': f'Failed to manage settings: {str(e)}'}), 500

# =============================================================================
# 3. JIRA INTEGRATION
# =============================================================================

def init_jira_routes(app):
    """Initialize Jira integration routes"""
    
    @app.route('/api/scan/<int:scan_id>/jira', methods=['POST'])
    @jwt_required()
    def create_jira_issue(scan_id):
        """Create Jira tickets for detected vulnerabilities"""
        user_id = get_jwt_identity()
        
        # Verify scan access
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
            jira_url = os.environ.get('JIRA_URL')
            jira_token = os.environ.get('JIRA_TOKEN')
            jira_project = os.environ.get('JIRA_PROJECT', 'SEC')
            
            if not jira_url or not jira_token:
                return jsonify({'error': 'Jira not configured'}), 400
            
            issues_created = 0
            vulnerabilities = scan.results.get('alerts', []) if scan.results else []
            
            for vuln in vulnerabilities:
                # Create severity-based priority mapping
                severity = vuln.get('risk', 'Low').title()
                priority_map = {
                    'High': 'Highest',
                    'Medium': 'High',
                    'Low': 'Medium',
                    'Informational': 'Low'
                }
                
                issue_data = {
                    'fields': {
                        'project': {'key': jira_project},
                        'summary': f'{vuln.get("name", "Security Issue")} in {scan.target_url}',
                        'description': f'''
*Vulnerability Details:*
- *Name:* {vuln.get("name", "Unknown")}
- *Severity:* {severity}
- *URL:* {vuln.get("url", scan.target_url)}
- *Confidence:* {vuln.get("confidence", "Unknown")}

*Description:*
{vuln.get("desc", "No description available")}

*Solution:*
{vuln.get("solution", "No solution available")}

*Reference:*
{vuln.get("reference", "No reference available")}

*Scan ID:* {scan_id}
*Generated by:* WebSecPen Security Scanner
                        '''.strip(),
                        'issuetype': {'name': 'Bug'},
                        'priority': {'name': priority_map.get(severity, 'Medium')},
                        'labels': ['websecpen', 'security', f'severity-{severity.lower()}']
                    }
                }
                
                response = requests.post(
                    f'{jira_url}/rest/api/3/issue',
                    headers={
                        'Authorization': f'Bearer {jira_token}',
                        'Content-Type': 'application/json'
                    },
                    json=issue_data,
                    timeout=10
                )
                
                if response.status_code == 201:
                    issues_created += 1
                else:
                    print(f'Jira API error: {response.status_code} - {response.text}')
            
            return jsonify({
                'message': f'Created {issues_created} Jira issues',
                'issues_created': issues_created,
                'total_vulnerabilities': len(vulnerabilities)
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Jira integration failed: {str(e)}'}), 500
    
    @app.route('/api/jira/config', methods=['GET'])
    @jwt_required()
    def get_jira_config():
        """Get Jira configuration status"""
        jira_url = os.environ.get('JIRA_URL')
        jira_token = os.environ.get('JIRA_TOKEN')
        jira_project = os.environ.get('JIRA_PROJECT', 'SEC')
        
        return jsonify({
            'configured': bool(jira_url and jira_token),
            'jira_url': jira_url if jira_url else None,
            'project_key': jira_project,
            'integration_status': 'active' if jira_url and jira_token else 'inactive'
        }), 200

# =============================================================================
# 4. API KEY MANAGEMENT
# =============================================================================

def create_api_key_model():
    """Model definition for ApiKey (to be added to models.py)"""
    return '''
class ApiKey(db.Model):
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True)
    last_used = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', backref='api_keys')
    
    def to_dict(self, include_key=False):
        return {
            'id': self.id,
            'name': self.name,
            'key': self.key if include_key else self.key[:8] + '...',
            'is_active': self.is_active,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }
'''

def init_api_key_routes(app):
    """Initialize API key management routes"""
    
    @app.route('/api/apikey', methods=['POST'])
    @jwt_required()
    def generate_api_key():
        """Generate a new API key"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        name = data.get('name', '').strip()
        expires_days = data.get('expires_days')
        
        if not name or len(name) < 3:
            return jsonify({'error': 'API key name must be at least 3 characters'}), 400
        
        try:
            # Generate secure key
            key = secrets.token_hex(32)
            
            # Calculate expiration if specified
            expires_at = None
            if expires_days and isinstance(expires_days, int) and expires_days > 0:
                expires_at = datetime.utcnow() + timedelta(days=expires_days)
            
            # Create API key data (simulate with Redis for now)
            api_key_data = {
                'id': f"key_{user_id}_{datetime.utcnow().timestamp()}",
                'user_id': user_id,
                'name': name,
                'key': key,
                'is_active': True,
                'last_used': None,
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': expires_at.isoformat() if expires_at else None
            }
            
            # Store in Redis
            if redis_client:
                # Store by key for authentication lookups
                redis_client.setex(f'api_key:{key}', 86400 * 365, json.dumps(api_key_data))
                
                # Store in user's key list
                user_keys_key = f'user_api_keys:{user_id}'
                redis_client.sadd(user_keys_key, key)
                redis_client.expire(user_keys_key, 86400 * 365)
            
            return jsonify({
                'message': 'API key created successfully',
                'api_key': {
                    'name': name,
                    'key': key,  # Return full key only on creation
                    'created_at': api_key_data['created_at'],
                    'expires_at': api_key_data['expires_at']
                }
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to create API key: {str(e)}'}), 500
    
    @app.route('/api/apikey', methods=['GET'])
    @jwt_required()
    def list_api_keys():
        """List user's API keys"""
        user_id = get_jwt_identity()
        
        try:
            api_keys = []
            
            if redis_client:
                user_keys_key = f'user_api_keys:{user_id}'
                keys = redis_client.smembers(user_keys_key)
                
                for key in keys:
                    key_data_json = redis_client.get(f'api_key:{key}')
                    if key_data_json:
                        key_data = json.loads(key_data_json)
                        
                        # Check if expired
                        is_expired = False
                        if key_data.get('expires_at'):
                            expires_at = datetime.fromisoformat(key_data['expires_at'])
                            is_expired = expires_at < datetime.utcnow()
                        
                        api_keys.append({
                            'id': key_data['id'],
                            'name': key_data['name'],
                            'key': key[:8] + '...',  # Masked key
                            'is_active': key_data['is_active'] and not is_expired,
                            'is_expired': is_expired,
                            'last_used': key_data.get('last_used'),
                            'created_at': key_data['created_at'],
                            'expires_at': key_data.get('expires_at')
                        })
            
            # Sort by creation date (newest first)
            api_keys.sort(key=lambda x: x['created_at'], reverse=True)
            
            return jsonify({
                'api_keys': api_keys,
                'total': len(api_keys)
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to list API keys: {str(e)}'}), 500
    
    @app.route('/api/apikey/<key_id>', methods=['DELETE'])
    @jwt_required()
    def revoke_api_key(key_id):
        """Revoke an API key"""
        user_id = get_jwt_identity()
        
        try:
            if redis_client:
                user_keys_key = f'user_api_keys:{user_id}'
                keys = redis_client.smembers(user_keys_key)
                
                key_found = False
                for key in keys:
                    key_data_json = redis_client.get(f'api_key:{key}')
                    if key_data_json:
                        key_data = json.loads(key_data_json)
                        if key_data['id'] == key_id:
                            # Remove from Redis
                            redis_client.delete(f'api_key:{key}')
                            redis_client.srem(user_keys_key, key)
                            key_found = True
                            break
                
                if not key_found:
                    return jsonify({'error': 'API key not found'}), 404
            
            return jsonify({'message': 'API key revoked successfully'}), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to revoke API key: {str(e)}'}), 500

# =============================================================================
# 5. ADDITIONAL INTEGRATIONS
# =============================================================================

def init_additional_routes(app):
    """Initialize additional integration routes"""
    
    @app.route('/api/scan/<int:scan_id>/export/<format>', methods=['GET'])
    @jwt_required()
    def export_scan_results(scan_id, format):
        """Export scan results in various formats"""
        user_id = get_jwt_identity()
        
        # Verify scan access
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
        
        if format not in ['csv', 'json', 'xml']:
            return jsonify({'error': 'Invalid format. Supported: csv, json, xml'}), 400
        
        try:
            results = scan.results.get('alerts', []) if scan.results else []
            
            if format == 'json':
                return jsonify({
                    'scan_id': scan_id,
                    'target_url': scan.target_url,
                    'scan_date': scan.created_at.isoformat(),
                    'status': scan.status,
                    'vulnerabilities': results
                }), 200
            
            elif format == 'csv':
                import csv
                from io import StringIO
                from flask import Response
                
                output = StringIO()
                writer = csv.writer(output)
                
                # CSV headers
                writer.writerow([
                    'Scan ID', 'Target URL', 'Vulnerability Name', 'Severity', 
                    'Confidence', 'Description', 'Solution', 'URL', 'Reference'
                ])
                
                # CSV data
                for vuln in results:
                    writer.writerow([
                        scan_id,
                        scan.target_url,
                        vuln.get('name', ''),
                        vuln.get('risk', ''),
                        vuln.get('confidence', ''),
                        vuln.get('desc', ''),
                        vuln.get('solution', ''),
                        vuln.get('url', ''),
                        vuln.get('reference', '')
                    ])
                
                return Response(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}_report.csv'}
                )
            
            elif format == 'xml':
                from xml.etree.ElementTree import Element, SubElement, tostring
                from flask import Response
                
                root = Element('scan_report')
                root.set('scan_id', str(scan_id))
                root.set('target_url', scan.target_url)
                root.set('scan_date', scan.created_at.isoformat())
                root.set('status', scan.status)
                
                vulnerabilities = SubElement(root, 'vulnerabilities')
                vulnerabilities.set('count', str(len(results)))
                
                for vuln in results:
                    vuln_elem = SubElement(vulnerabilities, 'vulnerability')
                    
                    for key, value in vuln.items():
                        if value:
                            elem = SubElement(vuln_elem, key)
                            elem.text = str(value)
                
                xml_string = tostring(root, encoding='unicode')
                return Response(
                    xml_string,
                    mimetype='application/xml',
                    headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}_report.xml'}
                )
                
        except Exception as e:
            return jsonify({'error': f'Export failed: {str(e)}'}), 500

# =============================================================================
# MAIN INITIALIZATION FUNCTION
# =============================================================================

def init_aug19_routes(app):
    """Initialize all August 19th features"""
    
    # Initialize Redis
    redis_available = init_redis()
    if not redis_available:
        print("Warning: Redis not available. Some features may not work properly.")
    
    # Initialize all feature routes
    init_trend_analysis_routes(app)
    init_notification_routes(app)
    init_jira_routes(app)
    init_api_key_routes(app)
    init_additional_routes(app)
    
    print("✅ August 19th features initialized successfully!")
    print("📊 Features: Trend Analysis, Notification Preferences, Jira Integration, API Key Management")
    
    return app 