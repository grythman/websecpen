# final_features_aug30_sep3.py - Final Advanced Features for WebSecPen (Aug 30 - Sep 3, 2025)
# Audit Export, Vulnerability Filters, Advanced Integrations, 2FA, and Analytics

import os
import json
import secrets
import hashlib
import time
import csv
import boto3
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from io import StringIO, BytesIO

from flask import Flask, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt, create_access_token
from flask_socketio import emit
from sqlalchemy import and_, or_
from werkzeug.security import check_password_hash
from celery.result import AsyncResult
from pyotp import TOTP, random_base32
from botocore.exceptions import ClientError
import qrcode
import requests

from models import db, User, Scan, TeamMember, Team, AuditLog

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
# AUGUST 30TH FEATURES - AUDIT EXPORT AND VULNERABILITY FILTERS
# =============================================================================

# 1. AUDIT LOG EXPORT FUNCTIONALITY
def init_audit_export(app):
    """Initialize audit log export functionality"""
    
    @app.route('/api/admin/audit/export', methods=['GET'])
    @jwt_required()
    def export_audit_logs():
        """Export audit logs as CSV"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            # Get filter parameters
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            action_filter = request.args.get('action')
            user_filter = request.args.get('user_id')
            
            # Build query
            query = AuditLog.query
            
            if start_date:
                query = query.filter(AuditLog.timestamp >= datetime.fromisoformat(start_date))
            if end_date:
                query = query.filter(AuditLog.timestamp <= datetime.fromisoformat(end_date))
            if action_filter:
                query = query.filter(AuditLog.action == action_filter)
            if user_filter:
                query = query.filter(AuditLog.user_id == int(user_filter))
            
            logs = query.order_by(AuditLog.timestamp.desc()).all()
            
            # Create CSV
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow([
                'ID', 'User ID', 'Action', 'Details', 'IP Address', 
                'User Agent', 'Timestamp', 'Session ID'
            ])
            
            for log in logs:
                writer.writerow([
                    log.id,
                    log.user_id,
                    log.action,
                    json.dumps(log.details) if log.details else '',
                    getattr(log, 'ip_address', ''),
                    getattr(log, 'user_agent', ''),
                    log.timestamp.isoformat(),
                    getattr(log, 'session_id', '')
                ])
            
            filename = f'audit_logs_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
            
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
            
        except Exception as e:
            return jsonify({'error': f'Failed to export audit logs: {str(e)}'}), 500
    
    @app.route('/api/admin/audit/stats', methods=['GET'])
    @jwt_required()
    def get_audit_stats():
        """Get audit log statistics"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            # Get statistics for the last 30 days
            start_date = datetime.utcnow() - timedelta(days=30)
            logs = AuditLog.query.filter(AuditLog.timestamp >= start_date).all()
            
            stats = {
                'total_actions': len(logs),
                'unique_users': len(set(log.user_id for log in logs)),
                'actions_by_type': defaultdict(int),
                'actions_by_day': defaultdict(int),
                'top_users': defaultdict(int)
            }
            
            for log in logs:
                stats['actions_by_type'][log.action] += 1
                stats['actions_by_day'][log.timestamp.strftime('%Y-%m-%d')] += 1
                stats['top_users'][log.user_id] += 1
            
            # Convert to lists for JSON serialization
            stats['actions_by_type'] = dict(stats['actions_by_type'])
            stats['actions_by_day'] = dict(stats['actions_by_day'])
            stats['top_users'] = dict(list(sorted(stats['top_users'].items(), key=lambda x: x[1], reverse=True))[:10])
            
            return jsonify(stats), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get audit stats: {str(e)}'}), 500

# 2. VULNERABILITY SEVERITY FILTERS
def init_vulnerability_filters(app):
    """Initialize vulnerability filtering functionality"""
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities', methods=['GET'])
    @jwt_required()
    def get_filtered_vulnerabilities(scan_id):
        """Get vulnerabilities with advanced filtering"""
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
            # Get filter parameters
            severity_filter = request.args.get('severity')
            confidence_filter = request.args.get('confidence')
            type_filter = request.args.get('type')
            status_filter = request.args.get('status', 'all')
            
            # Get base vulnerabilities
            vulnerabilities = scan.results.get('alerts', []) if scan.results else []
            
            # Apply filters
            filtered_vulns = []
            for vuln in vulnerabilities:
                # Severity filter
                if severity_filter and vuln.get('risk', '').lower() != severity_filter.lower():
                    continue
                
                # Confidence filter
                if confidence_filter and vuln.get('confidence', '').lower() != confidence_filter.lower():
                    continue
                
                # Type filter
                if type_filter and type_filter.lower() not in vuln.get('name', '').lower():
                    continue
                
                # Status filter (check VulnerabilityStatus if available)
                if status_filter != 'all':
                    try:
                        from models import VulnerabilityStatus
                        vuln_status = VulnerabilityStatus.query.filter_by(
                            scan_id=scan_id,
                            vuln_id=vuln.get('pluginid', vuln.get('name', ''))
                        ).first()
                        
                        current_status = vuln_status.status if vuln_status else 'open'
                        if current_status != status_filter:
                            continue
                    except ImportError:
                        # VulnerabilityStatus not available, skip status filtering
                        pass
                
                # Add vulnerability with additional metadata
                enhanced_vuln = dict(vuln)
                enhanced_vuln['vuln_id'] = vuln.get('pluginid', vuln.get('name', ''))
                
                # Add tags if available
                try:
                    from models import VulnTag
                    tags = VulnTag.query.filter_by(
                        scan_id=scan_id,
                        vuln_id=enhanced_vuln['vuln_id']
                    ).all()
                    enhanced_vuln['tags'] = [{'tag': t.tag, 'user_id': t.user_id} for t in tags]
                except ImportError:
                    enhanced_vuln['tags'] = []
                
                filtered_vulns.append(enhanced_vuln)
            
            # Add summary statistics
            summary = {
                'total_count': len(filtered_vulns),
                'severity_breakdown': defaultdict(int),
                'confidence_breakdown': defaultdict(int),
                'type_breakdown': defaultdict(int)
            }
            
            for vuln in filtered_vulns:
                summary['severity_breakdown'][vuln.get('risk', 'Unknown')] += 1
                summary['confidence_breakdown'][vuln.get('confidence', 'Unknown')] += 1
                summary['type_breakdown'][vuln.get('name', 'Unknown')] += 1
            
            return jsonify({
                'vulnerabilities': filtered_vulns,
                'summary': {
                    'total_count': summary['total_count'],
                    'severity_breakdown': dict(summary['severity_breakdown']),
                    'confidence_breakdown': dict(summary['confidence_breakdown']),
                    'type_breakdown': dict(summary['type_breakdown'])
                },
                'filters_applied': {
                    'severity': severity_filter,
                    'confidence': confidence_filter,
                    'type': type_filter,
                    'status': status_filter
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to filter vulnerabilities: {str(e)}'}), 500

# 3. RAPID7 INSIGHTVM INTEGRATION
def init_rapid7_integration(app):
    """Initialize Rapid7 InsightVM integration"""
    
    @app.route('/api/scan/<int:scan_id>/rapid7', methods=['POST'])
    @jwt_required()
    def send_to_rapid7(scan_id):
        """Send scan results to Rapid7 InsightVM"""
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
        
        # Get Rapid7 credentials
        rapid7_credentials = get_integration_credentials(user_id, 'rapid7')
        if not rapid7_credentials:
            return jsonify({'error': 'Rapid7 credentials not configured'}), 400
        
        try:
            rapid7_url = os.environ.get('RAPID7_API_URL', 'https://us.api.insight.rapid7.com')
            
            created_assets = []
            alerts = scan.results.get('alerts', []) if scan.results else []
            
            # Create asset in Rapid7
            asset_data = {
                'name': scan.target_url,
                'ip': scan.target_url,
                'type': 'web_application',
                'vulnerabilities': []
            }
            
            for alert in alerts:
                vulnerability = {
                    'id': f'websecpen-{alert.get("pluginid", hashlib.md5(alert.get("name", "").encode()).hexdigest()[:8])}',
                    'title': alert.get('name', 'Unknown Vulnerability'),
                    'description': alert.get('desc', 'No description available'),
                    'severity': map_severity_to_rapid7(alert.get('risk', 'Medium')),
                    'cvss_score': get_cvss_score_from_risk(alert.get('risk', 'Medium')),
                    'solution': alert.get('solution', 'No solution provided'),
                    'proof_of_concept': alert.get('evidence', ''),
                    'references': alert.get('reference', ''),
                    'first_discovered': scan.created_at.isoformat(),
                    'last_discovered': scan.created_at.isoformat(),
                    'status': 'vulnerable'
                }
                asset_data['vulnerabilities'].append(vulnerability)
            
            # Mock API call - replace with actual Rapid7 API
            response = mock_rapid7_api_call(rapid7_credentials, asset_data)
            
            if response.get('success'):
                created_assets.append({
                    'asset_id': response.get('asset_id'),
                    'vulnerabilities_count': len(asset_data['vulnerabilities']),
                    'status': 'created'
                })
            else:
                created_assets.append({
                    'asset_id': None,
                    'vulnerabilities_count': len(asset_data['vulnerabilities']),
                    'status': 'failed',
                    'error': response.get('error', 'Unknown error')
                })
            
            return jsonify({
                'message': f'Rapid7 InsightVM integration completed',
                'assets_created': len([a for a in created_assets if a['status'] == 'created']),
                'assets_failed': len([a for a in created_assets if a['status'] == 'failed']),
                'assets': created_assets
            }), 200
            
        except Exception as e:
            app.logger.error(f'Rapid7 integration error: {str(e)}')
            return jsonify({'error': f'Rapid7 integration failed: {str(e)}'}), 500

def map_severity_to_rapid7(risk_level):
    """Map WebSecPen risk levels to Rapid7 severity"""
    mapping = {
        'high': 'critical',
        'medium': 'severe',
        'low': 'moderate',
        'informational': 'mild'
    }
    return mapping.get(risk_level.lower(), 'moderate')

def get_cvss_score_from_risk(risk_level):
    """Get CVSS score based on risk level"""
    scores = {
        'high': 8.5,
        'medium': 6.0,
        'low': 3.5,
        'informational': 1.0
    }
    return scores.get(risk_level.lower(), 5.0)

def mock_rapid7_api_call(credentials, data):
    """Mock Rapid7 API call - replace with actual implementation"""
    return {
        'success': True,
        'asset_id': f'rapid7_asset_{secrets.token_hex(8)}',
        'message': 'Asset created successfully'
    }

# 4. USER RETENTION DASHBOARD
def init_retention_analytics(app):
    """Initialize user retention analytics"""
    
    @app.route('/api/admin/retention', methods=['GET'])
    @jwt_required()
    def get_retention_metrics():
        """Get user retention metrics"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            days = int(request.args.get('days', 30))
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get user activity data
            users = User.query.all()
            scans = Scan.query.filter(Scan.created_at >= start_date).all()
            
            # Calculate daily metrics
            daily_metrics = defaultdict(lambda: {
                'active_users': set(),
                'new_users': set(),
                'scan_count': 0,
                'returning_users': set()
            })
            
            # Track user activity
            for scan in scans:
                date = scan.created_at.strftime('%Y-%m-%d')
                daily_metrics[date]['active_users'].add(scan.user_id)
                daily_metrics[date]['scan_count'] += 1
            
            # Track new users
            for user in users:
                if user.created_at >= start_date:
                    date = user.created_at.strftime('%Y-%m-%d')
                    daily_metrics[date]['new_users'].add(user.id)
            
            # Calculate returning users (users who were active before and are active again)
            all_dates = sorted(daily_metrics.keys())
            previous_active = set()
            
            for date in all_dates:
                current_active = daily_metrics[date]['active_users']
                daily_metrics[date]['returning_users'] = current_active.intersection(previous_active)
                previous_active.update(current_active)
            
            # Format data for response
            formatted_data = {
                'dates': all_dates,
                'active_users': [len(daily_metrics[d]['active_users']) for d in all_dates],
                'new_users': [len(daily_metrics[d]['new_users']) for d in all_dates],
                'returning_users': [len(daily_metrics[d]['returning_users']) for d in all_dates],
                'scan_counts': [daily_metrics[d]['scan_count'] for d in all_dates],
                'retention_rate': []
            }
            
            # Calculate retention rate
            for i, date in enumerate(all_dates):
                if i == 0:
                    formatted_data['retention_rate'].append(0)
                else:
                    prev_active = len(daily_metrics[all_dates[i-1]]['active_users'])
                    current_returning = len(daily_metrics[date]['returning_users'])
                    retention_rate = (current_returning / prev_active * 100) if prev_active > 0 else 0
                    formatted_data['retention_rate'].append(round(retention_rate, 2))
            
            # Calculate summary statistics
            total_users = len(users)
            active_users_period = len(set().union(*[daily_metrics[d]['active_users'] for d in all_dates]))
            avg_retention_rate = sum(formatted_data['retention_rate']) / len(formatted_data['retention_rate']) if formatted_data['retention_rate'] else 0
            
            return jsonify({
                'metrics': formatted_data,
                'summary': {
                    'total_users': total_users,
                    'active_users_period': active_users_period,
                    'avg_retention_rate': round(avg_retention_rate, 2),
                    'period_days': days
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get retention metrics: {str(e)}'}), 500

# =============================================================================
# AUGUST 31ST FEATURES - SCAN COMPARISON AND ROLE ESCALATION
# =============================================================================

# 1. SCAN RESULT COMPARISON ACROSS RUNS
def init_scan_comparison(app):
    """Initialize scan comparison functionality"""
    
    @app.route('/api/scan/compare', methods=['GET'])
    @jwt_required()
    def compare_scans():
        """Compare scan results across multiple runs"""
        user_id = get_jwt_identity()
        
        try:
            target_url = request.args.get('url')
            if not target_url:
                return jsonify({'error': 'URL parameter is required'}), 400
            
            # Get recent scans for the URL
            scans = Scan.query.filter(
                Scan.target_url == target_url,
                or_(
                    Scan.user_id == user_id,
                    Scan.team_id.in_(
                        db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                    )
                )
            ).order_by(Scan.created_at.desc()).limit(10).all()
            
            if len(scans) < 2:
                return jsonify({'error': 'At least 2 scans required for comparison'}), 400
            
            # Build comparison data
            comparison_data = {
                'target_url': target_url,
                'scans': [],
                'vulnerability_trends': defaultdict(list),
                'summary': {
                    'total_scans': len(scans),
                    'date_range': {
                        'earliest': scans[-1].created_at.isoformat(),
                        'latest': scans[0].created_at.isoformat()
                    }
                }
            }
            
            vulnerability_tracker = defaultdict(dict)
            
            # Process each scan
            for scan in scans:
                scan_data = {
                    'scan_id': scan.id,
                    'date': scan.created_at.isoformat(),
                    'status': scan.status,
                    'vulnerability_count': 0,
                    'vulnerabilities_by_severity': defaultdict(int)
                }
                
                alerts = scan.results.get('alerts', []) if scan.results else []
                scan_data['vulnerability_count'] = len(alerts)
                
                # Track vulnerabilities
                for alert in alerts:
                    vuln_id = alert.get('pluginid', alert.get('name', ''))
                    severity = alert.get('risk', 'Unknown')
                    
                    scan_data['vulnerabilities_by_severity'][severity] += 1
                    
                    # Track vulnerability across scans
                    vulnerability_tracker[vuln_id][scan.id] = {
                        'name': alert.get('name', 'Unknown'),
                        'severity': severity,
                        'confidence': alert.get('confidence', 'Unknown'),
                        'status': get_vulnerability_status(scan.id, vuln_id),
                        'first_seen': scan.created_at.isoformat()
                    }
                
                comparison_data['scans'].append(scan_data)
            
            # Build vulnerability trends
            for vuln_id, scan_history in vulnerability_tracker.items():
                trend = {
                    'vulnerability_id': vuln_id,
                    'name': '',
                    'appearances': len(scan_history),
                    'history': []
                }
                
                for scan in scans:
                    if scan.id in scan_history:
                        vuln_data = scan_history[scan.id]
                        trend['name'] = vuln_data['name']
                        trend['history'].append({
                            'scan_id': scan.id,
                            'date': scan.created_at.isoformat(),
                            'severity': vuln_data['severity'],
                            'confidence': vuln_data['confidence'],
                            'status': vuln_data['status'],
                            'present': True
                        })
                    else:
                        trend['history'].append({
                            'scan_id': scan.id,
                            'date': scan.created_at.isoformat(),
                            'present': False
                        })
                
                # Sort history by date
                trend['history'].sort(key=lambda x: x['date'], reverse=True)
                comparison_data['vulnerability_trends'][vuln_id] = trend
            
            # Calculate summary statistics
            all_vulns = set()
            persistent_vulns = set()
            
            for vuln_id, trend in comparison_data['vulnerability_trends'].items():
                all_vulns.add(vuln_id)
                if trend['appearances'] >= len(scans) * 0.7:  # Appears in 70% of scans
                    persistent_vulns.add(vuln_id)
            
            comparison_data['summary'].update({
                'unique_vulnerabilities': len(all_vulns),
                'persistent_vulnerabilities': len(persistent_vulns),
                'avg_vulnerabilities_per_scan': sum(s['vulnerability_count'] for s in comparison_data['scans']) / len(comparison_data['scans'])
            })
            
            return jsonify(comparison_data), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to compare scans: {str(e)}'}), 500

def get_vulnerability_status(scan_id, vuln_id):
    """Get vulnerability status if available"""
    try:
        from models import VulnerabilityStatus
        status_record = VulnerabilityStatus.query.filter_by(scan_id=scan_id, vuln_id=vuln_id).first()
        return status_record.status if status_record else 'open'
    except ImportError:
        return 'unknown'

# 2. ROLE ESCALATION WORKFLOWS
class RoleRequest(db.Model):
    """Role escalation requests"""
    __tablename__ = 'role_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    requested_role = db.Column(db.String(20), nullable=False)
    current_role = db.Column(db.String(20), nullable=False)
    justification = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

def init_role_escalation(app):
    """Initialize role escalation functionality"""
    
    @app.route('/api/role/request', methods=['POST'])
    @jwt_required()
    def create_role_request():
        """Create a role escalation request"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        try:
            data = request.get_json()
            requested_role = data.get('requested_role')
            justification = data.get('justification', '')
            
            if not requested_role:
                return jsonify({'error': 'Requested role is required'}), 400
            
            # Check if user already has a pending request
            existing_request = RoleRequest.query.filter_by(
                user_id=user_id,
                status='pending'
            ).first()
            
            if existing_request:
                return jsonify({'error': 'You already have a pending role request'}), 400
            
            # Create role request
            role_request = RoleRequest(
                user_id=user_id,
                requested_role=requested_role,
                current_role=user.role,
                justification=justification
            )
            
            db.session.add(role_request)
            db.session.commit()
            
            # Notify admins
            try:
                from app import socketio
                socketio.emit('new_role_request', {
                    'id': role_request.id,
                    'user_id': user_id,
                    'user_email': user.email,
                    'current_role': user.role,
                    'requested_role': requested_role,
                    'justification': justification,
                    'created_at': role_request.created_at.isoformat()
                }, room='admin')
            except:
                pass
            
            return jsonify({
                'message': 'Role request submitted successfully',
                'request_id': role_request.id
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to create role request: {str(e)}'}), 500
    
    @app.route('/api/admin/role/requests', methods=['GET'])
    @jwt_required()
    def get_role_requests():
        """Get all role requests (admin only)"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            status_filter = request.args.get('status', 'all')
            
            query = RoleRequest.query
            if status_filter != 'all':
                query = query.filter_by(status=status_filter)
            
            requests = query.order_by(RoleRequest.created_at.desc()).all()
            
            return jsonify([{
                'id': req.id,
                'user_id': req.user_id,
                'user_email': User.query.get(req.user_id).email,
                'current_role': req.current_role,
                'requested_role': req.requested_role,
                'justification': req.justification,
                'status': req.status,
                'approved_by': req.approved_by,
                'created_at': req.created_at.isoformat(),
                'updated_at': req.updated_at.isoformat()
            } for req in requests]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get role requests: {str(e)}'}), 500
    
    @app.route('/api/admin/role/requests/<int:request_id>/<action>', methods=['PUT'])
    @jwt_required()
    def handle_role_request(request_id, action):
        """Approve or reject a role request"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Invalid action. Must be approve or reject'}), 400
        
        try:
            role_request = RoleRequest.query.get(request_id)
            if not role_request:
                return jsonify({'error': 'Role request not found'}), 404
            
            if role_request.status != 'pending':
                return jsonify({'error': 'Role request has already been processed'}), 400
            
            admin_user_id = get_jwt_identity()
            role_request.status = 'approved' if action == 'approve' else 'rejected'
            role_request.approved_by = admin_user_id
            role_request.updated_at = datetime.utcnow()
            
            # If approved, update user role
            if action == 'approve':
                user = User.query.get(role_request.user_id)
                if user:
                    old_role = user.role
                    user.role = role_request.requested_role
                    
                    # Log the role change
                    audit_log = AuditLog(
                        user_id=admin_user_id,
                        action='role_escalation_approved',
                        details={
                            'target_user_id': user.id,
                            'old_role': old_role,
                            'new_role': user.role,
                            'request_id': request_id
                        }
                    )
                    db.session.add(audit_log)
            
            db.session.commit()
            
            # Notify user
            try:
                from app import socketio
                from models import UserNotification
                
                notification = UserNotification(
                    user_id=role_request.user_id,
                    title=f'Role Request {action.title()}',
                    message=f'Your request for {role_request.requested_role} role has been {action}d.',
                    notification_type='role_request_update',
                    priority='high' if action == 'approve' else 'normal'
                )
                db.session.add(notification)
                db.session.commit()
                
                socketio.emit('role_request_update', {
                    'request_id': request_id,
                    'status': role_request.status,
                    'action': action,
                    'message': f'Role request {action}d'
                }, room=f'user_{role_request.user_id}')
            except:
                pass
            
            return jsonify({
                'message': f'Role request {action}d successfully'
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to {action} role request: {str(e)}'}), 500

# =============================================================================
# SEPTEMBER 1ST FEATURES - AWS INTEGRATION AND ADVANCED ANALYTICS
# =============================================================================

# 1. AWS SECURITY HUB INTEGRATION
def init_aws_security_hub(app):
    """Initialize AWS Security Hub integration"""
    
    @app.route('/api/scan/<int:scan_id>/aws-security-hub', methods=['POST'])
    @jwt_required()
    def send_to_aws_security_hub(scan_id):
        """Send findings to AWS Security Hub"""
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
        
        # Get AWS credentials
        aws_credentials = get_integration_credentials(user_id, 'aws')
        if not aws_credentials:
            return jsonify({'error': 'AWS credentials not configured'}), 400
        
        try:
            # Initialize AWS Security Hub client
            session = boto3.Session(
                aws_access_key_id=aws_credentials.get('access_key'),
                aws_secret_access_key=aws_credentials.get('secret_key'),
                region_name=aws_credentials.get('region', 'us-east-1')
            )
            
            security_hub = session.client('securityhub')
            account_id = aws_credentials.get('account_id')
            
            findings = []
            alerts = scan.results.get('alerts', []) if scan.results else []
            
            for alert in alerts:
                # Only send high-severity findings
                if alert.get('risk', '').lower() != 'high':
                    continue
                
                finding_id = f'websecpen-{scan.id}-{alert.get("pluginid", hashlib.md5(alert.get("name", "").encode()).hexdigest()[:8])}'
                
                finding = {
                    'SchemaVersion': '2018-10-08',
                    'Id': finding_id,
                    'ProductArn': f'arn:aws:securityhub:{aws_credentials.get("region", "us-east-1")}:{account_id}:product/{account_id}/websecpen',
                    'GeneratorId': f'websecpen-scan-{scan.id}',
                    'AwsAccountId': account_id,
                    'Types': [
                        f'Software and Configuration Checks/Vulnerabilities/{alert.get("name", "Unknown")}'
                    ],
                    'CreatedAt': scan.created_at.isoformat() + 'Z',
                    'UpdatedAt': datetime.utcnow().isoformat() + 'Z',
                    'Severity': {
                        'Label': map_severity_to_aws(alert.get('risk', 'MEDIUM'))
                    },
                    'Title': f'{alert.get("name", "Unknown Vulnerability")} detected in {scan.target_url}',
                    'Description': alert.get('desc', 'No description available'),
                    'SourceUrl': alert.get('url', scan.target_url),
                    'Resources': [
                        {
                            'Type': 'Other',
                            'Id': f'websecpen:scan:{scan.id}:url:{scan.target_url}',
                            'Region': aws_credentials.get('region', 'us-east-1'),
                            'Details': {
                                'Other': {
                                    'ScanId': str(scan.id),
                                    'TargetUrl': scan.target_url,
                                    'VulnerabilityType': alert.get('name', 'Unknown'),
                                    'Confidence': alert.get('confidence', 'Unknown'),
                                    'Parameter': alert.get('param', ''),
                                    'Evidence': alert.get('evidence', '')
                                }
                            }
                        }
                    ],
                    'RecordState': 'ACTIVE',
                    'WorkflowState': 'NEW'
                }
                
                # Add remediation if available
                if alert.get('solution'):
                    finding['Remediation'] = {
                        'Recommendation': {
                            'Text': alert.get('solution')
                        }
                    }
                
                findings.append(finding)
            
            # Send findings to Security Hub
            if findings:
                response = security_hub.batch_import_findings(Findings=findings)
                
                return jsonify({
                    'message': f'Successfully sent {len(findings)} findings to AWS Security Hub',
                    'findings_sent': len(findings),
                    'failed_count': response.get('FailedCount', 0),
                    'success_count': response.get('SuccessCount', len(findings))
                }), 200
            else:
                return jsonify({
                    'message': 'No high-severity findings to send to AWS Security Hub'
                }), 200
                
        except ClientError as e:
            app.logger.error(f'AWS Security Hub error: {str(e)}')
            return jsonify({'error': f'AWS Security Hub integration failed: {str(e)}'}), 500
        except Exception as e:
            app.logger.error(f'AWS integration error: {str(e)}')
            return jsonify({'error': f'Failed to send to AWS Security Hub: {str(e)}'}), 500

def map_severity_to_aws(risk_level):
    """Map risk levels to AWS Security Hub severity"""
    mapping = {
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
        'informational': 'INFORMATIONAL'
    }
    return mapping.get(risk_level.lower(), 'MEDIUM')

# =============================================================================
# SEPTEMBER 2ND FEATURES - VULNERABILITY TAGGING AND SESSION ANALYTICS
# =============================================================================

# 1. VULNERABILITY TAGGING SYSTEM
class VulnTag(db.Model):
    """Vulnerability tags for categorization"""
    __tablename__ = 'vuln_tags'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    vuln_id = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tag = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(7), default='#007bff')  # Hex color
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_vulnerability_tagging(app):
    """Initialize vulnerability tagging system"""
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities/<vuln_id>/tags', methods=['POST'])
    @jwt_required()
    def add_vulnerability_tag(scan_id, vuln_id):
        """Add a tag to a vulnerability"""
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
            tag_name = data.get('tag')
            tag_color = data.get('color', '#007bff')
            
            if not tag_name:
                return jsonify({'error': 'Tag name is required'}), 400
            
            # Check if tag already exists for this vulnerability
            existing_tag = VulnTag.query.filter_by(
                scan_id=scan_id,
                vuln_id=vuln_id,
                tag=tag_name
            ).first()
            
            if existing_tag:
                return jsonify({'error': 'Tag already exists for this vulnerability'}), 400
            
            # Create new tag
            vuln_tag = VulnTag(
                scan_id=scan_id,
                vuln_id=vuln_id,
                user_id=user_id,
                tag=tag_name,
                color=tag_color
            )
            
            db.session.add(vuln_tag)
            db.session.commit()
            
            # Emit real-time update
            try:
                from app import socketio
                socketio.emit('vulnerability_tag_added', {
                    'scan_id': scan_id,
                    'vuln_id': vuln_id,
                    'tag': tag_name,
                    'color': tag_color,
                    'user_id': user_id,
                    'created_at': vuln_tag.created_at.isoformat()
                }, room=f'team_{scan.team_id}' if scan.team_id else f'user_{user_id}')
            except:
                pass
            
            return jsonify({
                'message': 'Tag added successfully',
                'tag_id': vuln_tag.id
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to add tag: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities/<vuln_id>/tags', methods=['GET'])
    @jwt_required()
    def get_vulnerability_tags(scan_id, vuln_id):
        """Get tags for a vulnerability"""
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
            tags = VulnTag.query.filter_by(scan_id=scan_id, vuln_id=vuln_id).all()
            
            return jsonify([{
                'id': tag.id,
                'tag': tag.tag,
                'color': tag.color,
                'user_id': tag.user_id,
                'created_at': tag.created_at.isoformat()
            } for tag in tags]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get tags: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/tags/export', methods=['GET'])
    @jwt_required()
    def export_tagged_vulnerabilities(scan_id):
        """Export tagged vulnerabilities as CSV"""
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
            tag_filter = request.args.get('tag')
            
            # Get tags
            query = VulnTag.query.filter_by(scan_id=scan_id)
            if tag_filter:
                query = query.filter_by(tag=tag_filter)
            
            tags = query.all()
            
            # Create CSV
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow([
                'Vulnerability ID', 'Tag', 'Color', 'Tagged By User ID', 
                'Created At', 'Vulnerability Name', 'Severity', 'Description'
            ])
            
            # Get vulnerability details
            vuln_details = {}
            if scan.results:
                for alert in scan.results.get('alerts', []):
                    vuln_id = alert.get('pluginid', alert.get('name', ''))
                    vuln_details[vuln_id] = {
                        'name': alert.get('name', 'Unknown'),
                        'severity': alert.get('risk', 'Unknown'),
                        'description': alert.get('desc', 'No description')
                    }
            
            for tag in tags:
                vuln_info = vuln_details.get(tag.vuln_id, {
                    'name': 'Unknown',
                    'severity': 'Unknown',
                    'description': 'No description'
                })
                
                writer.writerow([
                    tag.vuln_id,
                    tag.tag,
                    tag.color,
                    tag.user_id,
                    tag.created_at.isoformat(),
                    vuln_info['name'],
                    vuln_info['severity'],
                    vuln_info['description']
                ])
            
            filename = f'tagged_vulnerabilities_scan_{scan_id}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
            
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
            
        except Exception as e:
            return jsonify({'error': f'Failed to export tagged vulnerabilities: {str(e)}'}), 500

# =============================================================================
# SEPTEMBER 3RD FEATURES - 2FA AND ADVANCED INTEGRATIONS
# =============================================================================

# 1. TWO-FACTOR AUTHENTICATION (2FA)
def init_two_factor_auth(app):
    """Initialize Two-Factor Authentication"""
    
    @app.route('/api/2fa/setup', methods=['POST'])
    @jwt_required()
    def setup_2fa():
        """Set up 2FA for user"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        try:
            # Check if 2FA is already enabled
            if getattr(user, 'totp_enabled', False):
                return jsonify({'error': '2FA is already enabled'}), 400
            
            # Generate TOTP secret
            totp_secret = random_base32()
            
            # Store secret temporarily (will be confirmed when verified)
            if not hasattr(user, 'totp_secret'):
                # Add totp_secret to user preferences if column doesn't exist
                user.preferences = user.preferences or {}
                user.preferences['totp_secret_temp'] = totp_secret
            else:
                user.totp_secret = totp_secret
            
            db.session.commit()
            
            # Generate QR code
            totp = TOTP(totp_secret)
            provisioning_uri = totp.provisioning_uri(
                name=user.email,
                issuer_name='WebSecPen Security Platform'
            )
            
            # Create QR code image
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
                'qr_code_uri': provisioning_uri,
                'qr_code_image': f'data:image/png;base64,{qr_code_data}',
                'secret': totp_secret,
                'backup_codes': generate_backup_codes(),
                'instructions': [
                    '1. Install an authenticator app (Google Authenticator, Authy, etc.)',
                    '2. Scan the QR code or enter the secret manually',
                    '3. Enter the 6-digit code from your app to verify',
                    '4. Save the backup codes in a secure location'
                ]
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to setup 2FA: {str(e)}'}), 500
    
    @app.route('/api/2fa/verify', methods=['POST'])
    @jwt_required()
    def verify_2fa():
        """Verify and enable 2FA"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        try:
            data = request.get_json()
            verification_code = data.get('code')
            
            if not verification_code:
                return jsonify({'error': 'Verification code is required'}), 400
            
            # Get the temporary secret
            if hasattr(user, 'totp_secret') and user.totp_secret:
                totp_secret = user.totp_secret
            elif user.preferences and 'totp_secret_temp' in user.preferences:
                totp_secret = user.preferences['totp_secret_temp']
            else:
                return jsonify({'error': '2FA setup not initialized'}), 400
            
            # Verify the code
            totp = TOTP(totp_secret)
            if totp.verify(verification_code):
                # Enable 2FA
                if hasattr(user, 'totp_enabled'):
                    user.totp_enabled = True
                    user.totp_secret = totp_secret
                else:
                    user.preferences = user.preferences or {}
                    user.preferences['totp_enabled'] = True
                    user.preferences['totp_secret'] = totp_secret
                    # Remove temporary secret
                    if 'totp_secret_temp' in user.preferences:
                        del user.preferences['totp_secret_temp']
                
                db.session.commit()
                
                # Log the 2FA enablement
                audit_log = AuditLog(
                    user_id=user_id,
                    action='2fa_enabled',
                    details={'method': 'TOTP'}
                )
                db.session.add(audit_log)
                db.session.commit()
                
                return jsonify({
                    'message': '2FA has been successfully enabled',
                    'enabled': True
                }), 200
            else:
                return jsonify({'error': 'Invalid verification code'}), 400
                
        except Exception as e:
            return jsonify({'error': f'Failed to verify 2FA: {str(e)}'}), 500
    
    @app.route('/api/2fa/disable', methods=['POST'])
    @jwt_required()
    def disable_2fa():
        """Disable 2FA"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        try:
            data = request.get_json()
            verification_code = data.get('code')
            password = data.get('password')
            
            if not verification_code or not password:
                return jsonify({'error': 'Verification code and password are required'}), 400
            
            # Verify password
            if not check_password_hash(user.password, password):
                return jsonify({'error': 'Invalid password'}), 401
            
            # Verify 2FA code
            totp_secret = getattr(user, 'totp_secret', user.preferences.get('totp_secret') if user.preferences else None)
            if not totp_secret:
                return jsonify({'error': '2FA is not enabled'}), 400
            
            totp = TOTP(totp_secret)
            if not totp.verify(verification_code):
                return jsonify({'error': 'Invalid verification code'}), 400
            
            # Disable 2FA
            if hasattr(user, 'totp_enabled'):
                user.totp_enabled = False
                user.totp_secret = None
            else:
                user.preferences = user.preferences or {}
                user.preferences['totp_enabled'] = False
                if 'totp_secret' in user.preferences:
                    del user.preferences['totp_secret']
            
            db.session.commit()
            
            # Log the 2FA disablement
            audit_log = AuditLog(
                user_id=user_id,
                action='2fa_disabled',
                details={'method': 'TOTP'}
            )
            db.session.add(audit_log)
            db.session.commit()
            
            return jsonify({
                'message': '2FA has been disabled',
                'enabled': False
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to disable 2FA: {str(e)}'}), 500

def generate_backup_codes():
    """Generate backup codes for 2FA"""
    codes = []
    for _ in range(10):
        code = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
        formatted_code = f'{code[:4]}-{code[4:]}'
        codes.append(formatted_code)
    return codes

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_integration_credentials(user_id, integration_name):
    """Get decrypted credentials for an integration"""
    try:
        from aug24_29_features import IntegrationApiKey, fernet
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

# =============================================================================
# MAIN INITIALIZATION FUNCTION
# =============================================================================

def init_final_features_routes(app):
    """Initialize all final advanced features"""
    
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
    init_audit_export(app)
    init_vulnerability_filters(app)
    init_rapid7_integration(app)
    init_retention_analytics(app)
    init_scan_comparison(app)
    init_role_escalation(app)
    init_aws_security_hub(app)
    init_vulnerability_tagging(app)
    init_two_factor_auth(app)
    
    print("✅ Final advanced features (Aug 30 - Sep 3) initialized successfully!")
    print("🔧 Features: Audit Export, Vulnerability Filters, Advanced Integrations, 2FA, Analytics")
    
    return app 