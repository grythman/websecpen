# aug20_25_features.py - Advanced Features for WebSecPen (Aug 20-25, 2025)
# Team Collaboration, Monitoring, Reporting, Security, and Integrations

import os
import json
import secrets
import hashlib
import hmac
import redis
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from io import StringIO, BytesIO
import csv

from flask import Flask, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from sqlalchemy import and_, or_
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from pyotp import TOTP
# import qrcode  # Temporarily disabled
from prometheus_client import Counter, Histogram, generate_latest
import time

from models import db, User, Scan, TeamMember, Vulnerability

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
# AUGUST 20TH FEATURES - COLLABORATION, MONITORING, AND SECURITY
# =============================================================================

# 1. SCAN RESULT ANNOTATIONS FOR TEAMS
class Annotation(db.Model):
    """Team annotations on scan results"""
    __tablename__ = 'annotations'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    vuln_id = db.Column(db.String(64), nullable=False)  # From scan.results
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

def init_annotation_routes(app):
    """Initialize annotation routes"""
    
    @app.route('/api/scan/<int:scan_id>/annotations', methods=['POST'])
    @jwt_required()
    def add_annotation(scan_id):
        """Add annotation to a vulnerability"""
        user_id = get_jwt_identity()
        
        # Verify scan access
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
        
        data = request.get_json()
        vuln_id = data.get('vuln_id')
        comment = data.get('comment')
        
        if not vuln_id or not comment:
            return jsonify({'error': 'Missing vuln_id or comment'}), 400
        
        try:
            annotation = Annotation(
                scan_id=scan_id,
                user_id=user_id,
                vuln_id=vuln_id,
                comment=comment
            )
            db.session.add(annotation)
            db.session.commit()
            
            # Emit real-time notification
            try:
                from app import socketio
                socketio.emit('new_annotation', {
                    'scan_id': scan_id,
                    'vuln_id': vuln_id,
                    'comment': comment,
                    'user_id': user_id,
                    'created_at': annotation.created_at.isoformat()
                }, room=f'team_{scan.team_id}' if scan.team_id else f'user_{user_id}')
            except:
                pass  # SocketIO not available
            
            return jsonify({
                'message': 'Annotation added',
                'annotation_id': annotation.id
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to add annotation: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/annotations', methods=['GET'])
    @jwt_required()
    def get_annotations(scan_id):
        """Get all annotations for a scan"""
        user_id = get_jwt_identity()
        
        # Verify scan access
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
            annotations = Annotation.query.filter_by(scan_id=scan_id).order_by(Annotation.created_at.desc()).all()
            
            return jsonify([{
                'id': a.id,
                'vuln_id': a.vuln_id,
                'comment': a.comment,
                'user_id': a.user_id,
                'created_at': a.created_at.isoformat(),
                'updated_at': a.updated_at.isoformat()
            } for a in annotations]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get annotations: {str(e)}'}), 500

# 2. ADVANCED MONITORING WITH ALERTING
# Prometheus metrics
error_counter = Counter('app_errors_total', 'Total errors', ['endpoint', 'error_type'])
request_counter = Counter('app_requests_total', 'Total requests', ['endpoint', 'method'])
request_duration = Histogram('app_request_duration_seconds', 'Request duration', ['endpoint'])

def init_monitoring_routes(app):
    """Initialize monitoring and alerting routes"""
    
    @app.before_request
    def before_request():
        """Track request start time"""
        request.start_time = time.time()
    
    @app.after_request
    def after_request(response):
        """Track request metrics"""
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time
            request_counter.labels(endpoint=request.path, method=request.method).inc()
            request_duration.labels(endpoint=request.path).observe(duration)
        return response
    
    @app.errorhandler(Exception)
    def handle_error(error):
        """Track errors and return standard response"""
        error_type = type(error).__name__
        error_counter.labels(endpoint=request.path, error_type=error_type).inc()
        app.logger.error(f'Error on {request.path}: {str(error)}')
        
        if app.debug:
            raise error  # Re-raise in debug mode
        
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/metrics')
    def metrics():
        """Prometheus metrics endpoint"""
        return Response(generate_latest(), mimetype='text/plain')
    
    @app.route('/api/admin/system/health', methods=['GET'])
    @jwt_required()
    def get_system_health():
        """Get system health metrics"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            # Database health
            db_healthy = True
            try:
                db.session.execute('SELECT 1')
            except:
                db_healthy = False
            
            # Redis health
            redis_healthy = False
            if redis_client:
                try:
                    redis_client.ping()
                    redis_healthy = True
                except:
                    pass
            
            # Queue status
            queue_length = 0
            if redis_client:
                try:
                    queue_length = redis_client.llen('scan_queue')
                except:
                    pass
            
            return jsonify({
                'status': 'healthy' if db_healthy and redis_healthy else 'degraded',
                'components': {
                    'database': 'healthy' if db_healthy else 'unhealthy',
                    'redis': 'healthy' if redis_healthy else 'unhealthy',
                    'scan_queue': {
                        'status': 'healthy',
                        'length': queue_length
                    }
                },
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get health status: {str(e)}'}), 500

# 3. ROLE-BASED ACCESS CONTROL (RBAC)
class Role(db.Model):
    """User roles for teams"""
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'viewer', 'editor', 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def require_role(roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_id = get_jwt_identity()
            
            # Get team_id from request data or URL params
            team_id = None
            if request.is_json:
                team_id = request.get_json().get('team_id')
            if not team_id and 'team_id' in kwargs:
                team_id = kwargs.get('team_id')
            
            if team_id:
                role = Role.query.filter_by(user_id=user_id, team_id=team_id).first()
                if not role or role.role not in roles:
                    return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

def init_rbac_routes(app):
    """Initialize RBAC routes"""
    
    @app.route('/api/team/<int:team_id>/roles', methods=['GET'])
    @jwt_required()
    @require_role(['admin'])
    def get_team_roles(team_id):
        """Get roles for a team"""
        try:
            roles = Role.query.filter_by(team_id=team_id).all()
            return jsonify([{
                'id': r.id,
                'user_id': r.user_id,
                'role': r.role,
                'created_at': r.created_at.isoformat()
            } for r in roles]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get roles: {str(e)}'}), 500
    
    @app.route('/api/team/<int:team_id>/roles', methods=['POST'])
    @jwt_required()
    @require_role(['admin'])
    def assign_team_role(team_id):
        """Assign role to user in team"""
        data = request.get_json()
        target_user_id = data.get('user_id')
        role_name = data.get('role')
        
        if not target_user_id or not role_name:
            return jsonify({'error': 'Missing user_id or role'}), 400
        
        if role_name not in ['viewer', 'editor', 'admin']:
            return jsonify({'error': 'Invalid role'}), 400
        
        try:
            # Check if role already exists
            existing_role = Role.query.filter_by(user_id=target_user_id, team_id=team_id).first()
            
            if existing_role:
                existing_role.role = role_name
            else:
                new_role = Role(user_id=target_user_id, team_id=team_id, role=role_name)
                db.session.add(new_role)
            
            db.session.commit()
            
            return jsonify({'message': 'Role assigned successfully'}), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to assign role: {str(e)}'}), 500

# =============================================================================
# AUGUST 21ST FEATURES - REPORTING, SHARING, AND AUTOMATION
# =============================================================================

# 1. EXPORTABLE VULNERABILITY REPORTS
def init_export_routes(app):
    """Initialize export routes"""
    
    @app.route('/api/scan/<int:scan_id>/export/<format>', methods=['GET'])
    @jwt_required()
    def export_scan_results(scan_id, format):
        """Export scan results in various formats"""
        user_id = get_jwt_identity()
        
        # Verify scan access
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
        
        if format not in ['csv', 'json', 'xml']:
            return jsonify({'error': 'Invalid format. Supported: csv, json, xml'}), 400
        
        try:
            results = scan.results or {}
            alerts = results.get('alerts', [])
            
            if format == 'json':
                return jsonify({
                    'scan_id': scan.id,
                    'target_url': scan.target_url,
                    'scan_date': scan.created_at.isoformat(),
                    'status': scan.status,
                    'vulnerabilities': alerts
                }), 200
            
            elif format == 'csv':
                output = StringIO()
                writer = csv.writer(output)
                writer.writerow([
                    'Scan ID', 'Target URL', 'Vulnerability Name', 'Risk Level', 
                    'Confidence', 'URL', 'Parameter', 'Attack', 'Evidence', 'Description'
                ])
                
                for alert in alerts:
                    writer.writerow([
                        scan.id,
                        scan.target_url,
                        alert.get('name', ''),
                        alert.get('risk', ''),
                        alert.get('confidence', ''),
                        alert.get('url', ''),
                        alert.get('param', ''),
                        alert.get('attack', ''),
                        alert.get('evidence', ''),
                        alert.get('desc', '')
                    ])
                
                return Response(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}_report.csv'}
                )
            
            elif format == 'xml':
                xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<scan_report>
    <scan_id>{scan.id}</scan_id>
    <target_url>{scan.target_url}</target_url>
    <scan_date>{scan.created_at.isoformat()}</scan_date>
    <status>{scan.status}</status>
    <vulnerabilities>
"""
                for alert in alerts:
                    xml_content += f"""        <vulnerability>
            <name>{alert.get('name', '')}</name>
            <risk>{alert.get('risk', '')}</risk>
            <confidence>{alert.get('confidence', '')}</confidence>
            <url>{alert.get('url', '')}</url>
            <parameter>{alert.get('param', '')}</parameter>
            <description>{alert.get('desc', '')}</description>
        </vulnerability>
"""
                xml_content += """    </vulnerabilities>
</scan_report>"""
                
                return Response(
                    xml_content,
                    mimetype='application/xml',
                    headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}_report.xml'}
                )
            
        except Exception as e:
            return jsonify({'error': f'Failed to export results: {str(e)}'}), 500

# 2. PUBLIC SCAN RESULT SHARING
class ShareLink(db.Model):
    """Public sharing links for scan results"""
    __tablename__ = 'share_links'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    access_count = db.Column(db.Integer, default=0)

def init_sharing_routes(app):
    """Initialize sharing routes"""
    
    @app.route('/api/scan/<int:scan_id>/share', methods=['POST'])
    @jwt_required()
    def create_share_link(scan_id):
        """Create a public sharing link for scan results"""
        user_id = get_jwt_identity()
        
        # Verify scan access
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
            data = request.get_json() or {}
            expires_days = data.get('expires_days', 7)
            
            # Generate secure token
            token = secrets.token_hex(32)
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
            
            # Check if link already exists
            existing_link = ShareLink.query.filter_by(scan_id=scan_id).first()
            if existing_link:
                existing_link.token = token
                existing_link.expires_at = expires_at
                existing_link.access_count = 0
            else:
                share_link = ShareLink(
                    scan_id=scan_id,
                    token=token,
                    expires_at=expires_at
                )
                db.session.add(share_link)
            
            db.session.commit()
            
            return jsonify({
                'share_url': f'{request.host_url}share/{token}',
                'expires_at': expires_at.isoformat(),
                'expires_days': expires_days
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to create share link: {str(e)}'}), 500
    
    @app.route('/api/share/<token>', methods=['GET'])
    def view_shared_scan(token):
        """View shared scan results"""
        try:
            share_link = ShareLink.query.filter_by(token=token).first()
            
            if not share_link:
                return jsonify({'error': 'Share link not found'}), 404
            
            if share_link.expires_at < datetime.utcnow():
                return jsonify({'error': 'Share link has expired'}), 410
            
            # Increment access count
            share_link.access_count += 1
            db.session.commit()
            
            # Get scan data
            scan = Scan.query.get(share_link.scan_id)
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            # Return limited scan data for public viewing
            return jsonify({
                'scan_id': scan.id,
                'target_url': scan.target_url,
                'scan_date': scan.created_at.isoformat(),
                'status': scan.status,
                'results_summary': {
                    'total_alerts': len(scan.results.get('alerts', [])) if scan.results else 0,
                    'high_risk': len([a for a in scan.results.get('alerts', []) if a.get('risk') == 'High']) if scan.results else 0,
                    'medium_risk': len([a for a in scan.results.get('alerts', []) if a.get('risk') == 'Medium']) if scan.results else 0,
                    'low_risk': len([a for a in scan.results.get('alerts', []) if a.get('risk') == 'Low']) if scan.results else 0
                },
                'expires_at': share_link.expires_at.isoformat(),
                'access_count': share_link.access_count
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to view shared scan: {str(e)}'}), 500

# =============================================================================
# AUGUST 22ND FEATURES - USER ANALYTICS, VERSIONING, AND INTEGRATIONS
# =============================================================================

# 1. USER ACTIVITY ANALYTICS DASHBOARD
def init_analytics_routes(app):
    """Initialize analytics routes"""
    
    @app.route('/api/admin/analytics/user-activity', methods=['GET'])
    @jwt_required()
    def get_user_activity_analytics():
        """Get user activity analytics for admins"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            days = int(request.args.get('days', 30))
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get audit logs if available, otherwise use scan data
            try:
                from models import AuditLog
                logs = AuditLog.query.filter(AuditLog.timestamp >= start_date).all()
                
                actions = defaultdict(lambda: defaultdict(int))
                dates = set()
                
                for log in logs:
                    date = log.timestamp.strftime('%Y-%m-%d')
                    dates.add(date)
                    actions[log.action][date] += 1
                
                sorted_dates = sorted(dates)
                
                return jsonify({
                    'dates': sorted_dates,
                    'actions': list(actions.keys()),
                    'data': [[actions[a][d] for d in sorted_dates] for a in actions],
                    'total_actions': len(logs),
                    'date_range': {
                        'start': start_date.isoformat(),
                        'end': datetime.utcnow().isoformat(),
                        'days': days
                    }
                }), 200
                
            except ImportError:
                # Fallback to scan-based analytics
                scans = Scan.query.filter(Scan.created_at >= start_date).all()
                
                daily_scans = defaultdict(int)
                dates = set()
                
                for scan in scans:
                    date = scan.created_at.strftime('%Y-%m-%d')
                    dates.add(date)
                    daily_scans[date] += 1
                
                sorted_dates = sorted(dates)
                
                return jsonify({
                    'dates': sorted_dates,
                    'actions': ['scan_started'],
                    'data': [[daily_scans[d] for d in sorted_dates]],
                    'total_actions': len(scans),
                    'date_range': {
                        'start': start_date.isoformat(),
                        'end': datetime.utcnow().isoformat(),
                        'days': days
                    }
                }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get analytics: {str(e)}'}), 500

# 2. SCAN RESULT VERSIONING
class ScanVersion(db.Model):
    """Historical versions of scan results"""
    __tablename__ = 'scan_versions'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    version = db.Column(db.Integer, nullable=False)
    results = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    hash = db.Column(db.String(64), nullable=False)  # Hash of results for comparison

def init_versioning_routes(app):
    """Initialize versioning routes"""
    
    @app.route('/api/scan/<int:scan_id>/versions', methods=['GET'])
    @jwt_required()
    def get_scan_versions(scan_id):
        """Get version history for a scan"""
        user_id = get_jwt_identity()
        
        # Verify scan access
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
            versions = ScanVersion.query.filter_by(scan_id=scan_id).order_by(ScanVersion.version.desc()).all()
            
            return jsonify([{
                'version': v.version,
                'created_at': v.created_at.isoformat(),
                'results_hash': v.hash,
                'vulnerability_count': len(v.results.get('alerts', [])) if v.results else 0
            } for v in versions]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get versions: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/versions/<int:version>', methods=['GET'])
    @jwt_required()
    def get_scan_version_details(scan_id, version):
        """Get detailed results for a specific version"""
        user_id = get_jwt_identity()
        
        # Verify scan access
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
            version_record = ScanVersion.query.filter_by(scan_id=scan_id, version=version).first()
            
            if not version_record:
                return jsonify({'error': 'Version not found'}), 404
            
            return jsonify({
                'version': version_record.version,
                'scan_id': scan_id,
                'created_at': version_record.created_at.isoformat(),
                'results': version_record.results
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get version details: {str(e)}'}), 500

def create_scan_version(scan):
    """Create a new version when scan results change"""
    try:
        if not scan.results:
            return
        
        # Generate hash of results
        results_str = json.dumps(scan.results, sort_keys=True)
        results_hash = hashlib.sha256(results_str.encode()).hexdigest()
        
        # Check if this version already exists
        existing = ScanVersion.query.filter_by(scan_id=scan.id, hash=results_hash).first()
        if existing:
            return existing
        
        # Get next version number
        last_version = ScanVersion.query.filter_by(scan_id=scan.id).order_by(ScanVersion.version.desc()).first()
        next_version = (last_version.version + 1) if last_version else 1
        
        # Create new version
        version = ScanVersion(
            scan_id=scan.id,
            version=next_version,
            results=scan.results,
            hash=results_hash
        )
        
        db.session.add(version)
        db.session.commit()
        
        return version
        
    except Exception as e:
        print(f"Failed to create scan version: {e}")
        return None

# =============================================================================
# AUGUST 23RD FEATURES - REPORT CUSTOMIZATION, SECURITY, AND INTEGRATIONS
# =============================================================================

# 1. CUSTOM SCAN REPORT TEMPLATES
class ReportTemplate(db.Model):
    """Custom report templates"""
    __tablename__ = 'report_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    template = db.Column(db.JSON, nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_report_template_routes(app):
    """Initialize report template routes"""
    
    @app.route('/api/report/templates', methods=['GET'])
    @jwt_required()
    def get_report_templates():
        """Get user's report templates"""
        user_id = get_jwt_identity()
        
        try:
            templates = ReportTemplate.query.filter_by(user_id=user_id).all()
            
            return jsonify([{
                'id': t.id,
                'name': t.name,
                'template': t.template,
                'is_default': t.is_default,
                'created_at': t.created_at.isoformat()
            } for t in templates]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get templates: {str(e)}'}), 500
    
    @app.route('/api/report/templates', methods=['POST'])
    @jwt_required()
    def create_report_template():
        """Create a new report template"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        name = data.get('name')
        template = data.get('template')
        
        if not name or not template:
            return jsonify({'error': 'Missing name or template'}), 400
        
        try:
            report_template = ReportTemplate(
                user_id=user_id,
                name=name,
                template=template
            )
            
            db.session.add(report_template)
            db.session.commit()
            
            return jsonify({
                'id': report_template.id,
                'name': name,
                'message': 'Template created successfully'
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to create template: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/report/custom/<int:template_id>', methods=['GET'])
    @jwt_required()
    def generate_custom_report(scan_id, template_id):
        """Generate custom PDF report using template"""
        user_id = get_jwt_identity()
        
        # Verify scan access
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
        
        # Get template
        template = ReportTemplate.query.filter_by(id=template_id, user_id=user_id).first()
        if not template:
            return jsonify({'error': 'Template not found'}), 404
        
        try:
            output = BytesIO()
            doc = SimpleDocTemplate(output, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title = template.template.get('title', f'Security Scan Report - {scan.target_url}')
            story.append(Paragraph(title, styles['Title']))
            story.append(Paragraph('<br/>', styles['Normal']))
            
            # Scan information
            story.append(Paragraph('Scan Information', styles['Heading2']))
            scan_info = [
                ['Scan ID', str(scan.id)],
                ['Target URL', scan.target_url],
                ['Scan Date', scan.created_at.strftime('%Y-%m-%d %H:%M:%S')],
                ['Status', scan.status]
            ]
            
            table = Table(scan_info)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            story.append(Paragraph('<br/><br/>', styles['Normal']))
            
            # Vulnerabilities
            if scan.results and scan.results.get('alerts'):
                story.append(Paragraph('Vulnerabilities Found', styles['Heading2']))
                
                alerts = scan.results.get('alerts', [])
                selected_fields = template.template.get('fields', ['name', 'risk', 'confidence', 'url'])
                
                # Create table headers
                headers = [field.capitalize() for field in selected_fields]
                vuln_data = [headers]
                
                # Add vulnerability data
                for alert in alerts:
                    row = []
                    for field in selected_fields:
                        value = alert.get(field, '')
                        if isinstance(value, str) and len(value) > 50:
                            value = value[:47] + '...'
                        row.append(str(value))
                    vuln_data.append(row)
                
                vuln_table = Table(vuln_data)
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(vuln_table)
            else:
                story.append(Paragraph('No vulnerabilities found.', styles['Normal']))
            
            # Build PDF
            doc.build(story)
            
            return Response(
                output.getvalue(),
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}_custom_report.pdf'}
            )
            
        except Exception as e:
            return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500

# 2. MULTI-FACTOR AUTHENTICATION (MFA)
def init_mfa_routes(app):
    """Initialize MFA routes"""
    
    @app.route('/api/mfa/setup', methods=['POST'])
    @jwt_required()
    def setup_mfa():
        """Set up MFA for user"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        try:
            # Generate secret if not exists
            if not hasattr(user, 'mfa_secret') or not user.mfa_secret:
                secret = TOTP.random_base32()
                # Store secret in user preferences or add mfa_secret column
                if hasattr(user, 'preferences'):
                    user.preferences = user.preferences or {}
                    user.preferences['mfa_secret'] = secret
                    db.session.commit()
                else:
                    return jsonify({'error': 'MFA setup not supported'}), 400
            else:
                secret = user.preferences.get('mfa_secret') if user.preferences else None
                if not secret:
                    secret = TOTP.random_base32()
                    user.preferences = user.preferences or {}
                    user.preferences['mfa_secret'] = secret
                    db.session.commit()
            
            # Generate QR code
            totp = TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=user.email,
                issuer_name='WebSecPen'
            )
            
            # Generate QR code image
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img_buffer = BytesIO()
            img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            import base64
            qr_code_data = base64.b64encode(img_buffer.getvalue()).decode()
            
            return jsonify({
                'secret': secret,
                'qr_code_uri': provisioning_uri,
                'qr_code_image': f'data:image/png;base64,{qr_code_data}',
                'instructions': 'Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)'
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to setup MFA: {str(e)}'}), 500
    
    @app.route('/api/mfa/verify', methods=['POST'])
    @jwt_required()
    def verify_mfa():
        """Verify MFA code"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        code = data.get('code')
        
        if not code:
            return jsonify({'error': 'MFA code required'}), 400
        
        try:
            secret = user.preferences.get('mfa_secret') if user.preferences else None
            if not secret:
                return jsonify({'error': 'MFA not set up'}), 400
            
            totp = TOTP(secret)
            if totp.verify(code):
                # Enable MFA for user
                user.preferences = user.preferences or {}
                user.preferences['mfa_enabled'] = True
                db.session.commit()
                
                return jsonify({'message': 'MFA verified and enabled'}), 200
            else:
                return jsonify({'error': 'Invalid MFA code'}), 400
                
        except Exception as e:
            return jsonify({'error': f'Failed to verify MFA: {str(e)}'}), 500

# =============================================================================
# MAIN INITIALIZATION FUNCTION
# =============================================================================

def init_aug20_25_routes(app):
    """Initialize all August 20-25 features"""
    
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
    
    # Initialize all feature routes
    init_annotation_routes(app)
    init_monitoring_routes(app)
    init_rbac_routes(app)
    init_export_routes(app)
    init_sharing_routes(app)
    init_analytics_routes(app)
    init_versioning_routes(app)
    init_report_template_routes(app)
    init_mfa_routes(app)
    
    print("✅ August 20-25 features initialized successfully!")
    print("🔧 Features: Team Collaboration, Advanced Monitoring, RBAC, Export/Sharing, Analytics, Versioning, Custom Reports, MFA")
    
    return app 