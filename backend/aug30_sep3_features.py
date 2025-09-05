# aug30_sep3_features.py - Final Comprehensive Features for WebSecPen (Aug 30 - Sep 3, 2025)
# Audit Export, Vulnerability Filters, 2FA, Analytics, and Enterprise Integrations

import os
import json
import secrets
import hashlib
import time
import redis
import csv
import boto3
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from io import StringIO, BytesIO
import base64

from flask import Flask, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt, create_access_token
from flask_socketio import emit
from sqlalchemy import and_, or_
from werkzeug.security import check_password_hash
from botocore.exceptions import ClientError

from models import db, User, Scan, TeamMember, Team

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
class AuditLog(db.Model):
    """Enhanced audit logging system"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))  # scan, user, team, etc.
    resource_id = db.Column(db.String(50))
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    severity = db.Column(db.String(20), default='info')  # info, warning, error, critical

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
            # Get query parameters
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            action_filter = request.args.get('action')
            severity_filter = request.args.get('severity')
            user_filter = request.args.get('user_id')
            
            # Build query
            query = AuditLog.query
            
            if start_date:
                query = query.filter(AuditLog.timestamp >= datetime.fromisoformat(start_date))
            if end_date:
                query = query.filter(AuditLog.timestamp <= datetime.fromisoformat(end_date))
            if action_filter:
                query = query.filter(AuditLog.action.ilike(f'%{action_filter}%'))
            if severity_filter:
                query = query.filter(AuditLog.severity == severity_filter)
            if user_filter:
                query = query.filter(AuditLog.user_id == int(user_filter))
            
            logs = query.order_by(AuditLog.timestamp.desc()).all()
            
            # Generate CSV
            output = StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'ID', 'User ID', 'Action', 'Resource Type', 'Resource ID',
                'Details', 'IP Address', 'User Agent', 'Timestamp', 'Severity'
            ])
            
            # Write data
            for log in logs:
                writer.writerow([
                    log.id,
                    log.user_id,
                    log.action,
                    log.resource_type,
                    log.resource_id,
                    json.dumps(log.details) if log.details else '',
                    log.ip_address,
                    log.user_agent,
                    log.timestamp.isoformat(),
                    log.severity
                ])
            
            # Create response
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f'audit_logs_{timestamp}.csv'
            
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
            days = int(request.args.get('days', 30))
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get basic stats
            total_logs = AuditLog.query.filter(AuditLog.timestamp >= start_date).count()
            
            # Group by action
            action_stats = db.session.query(
                AuditLog.action,
                db.func.count(AuditLog.id).label('count')
            ).filter(AuditLog.timestamp >= start_date).group_by(AuditLog.action).all()
            
            # Group by severity
            severity_stats = db.session.query(
                AuditLog.severity,
                db.func.count(AuditLog.id).label('count')
            ).filter(AuditLog.timestamp >= start_date).group_by(AuditLog.severity).all()
            
            # Daily activity
            daily_stats = db.session.query(
                db.func.date(AuditLog.timestamp).label('date'),
                db.func.count(AuditLog.id).label('count')
            ).filter(AuditLog.timestamp >= start_date).group_by(
                db.func.date(AuditLog.timestamp)
            ).order_by('date').all()
            
            return jsonify({
                'total_logs': total_logs,
                'date_range': {
                    'start': start_date.isoformat(),
                    'end': datetime.utcnow().isoformat(),
                    'days': days
                },
                'actions': [{'action': stat.action, 'count': stat.count} for stat in action_stats],
                'severities': [{'severity': stat.severity, 'count': stat.count} for stat in severity_stats],
                'daily_activity': [{'date': str(stat.date), 'count': stat.count} for stat in daily_stats]
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get audit stats: {str(e)}'}), 500

def log_audit_event(user_id, action, resource_type=None, resource_id=None, details=None, severity='info', request_obj=None):
    """Helper function to log audit events"""
    try:
        ip_address = None
        user_agent = None
        
        if request_obj:
            ip_address = request_obj.environ.get('REMOTE_ADDR')
            user_agent = request_obj.headers.get('User-Agent')
        
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            severity=severity
        )
        
        db.session.add(audit_log)
        db.session.commit()
        
        return audit_log
        
    except Exception as e:
        print(f"Failed to log audit event: {e}")
        return None

# 2. VULNERABILITY SEVERITY FILTERS
def init_vulnerability_filters(app):
    """Initialize vulnerability filtering system"""
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities', methods=['GET'])
    @jwt_required()
    def get_filtered_vulnerabilities(scan_id):
        """Get vulnerabilities with advanced filtering"""
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
            # Get filter parameters
            severity = request.args.get('severity')
            confidence = request.args.get('confidence')
            vuln_type = request.args.get('type')
            status = request.args.get('status')
            tag = request.args.get('tag')
            search = request.args.get('search')
            
            # Start with all vulnerabilities
            vulnerabilities = scan.results.get('alerts', []) if scan.results else []
            
            # Apply filters
            if severity:
                severities = severity.split(',')
                vulnerabilities = [v for v in vulnerabilities if v.get('risk', '').lower() in [s.lower() for s in severities]]
            
            if confidence:
                confidences = confidence.split(',')
                vulnerabilities = [v for v in vulnerabilities if v.get('confidence', '').lower() in [c.lower() for c in confidences]]
            
            if vuln_type:
                types = vuln_type.split(',')
                vulnerabilities = [v for v in vulnerabilities if any(t.lower() in v.get('name', '').lower() for t in types)]
            
            if search:
                search_lower = search.lower()
                vulnerabilities = [v for v in vulnerabilities if 
                    search_lower in v.get('name', '').lower() or
                    search_lower in v.get('desc', '').lower() or
                    search_lower in v.get('url', '').lower()
                ]
            
            # Apply status filter if specified
            if status:
                from aug24_29_features import VulnerabilityStatus
                statuses = status.split(',')
                filtered_by_status = []
                
                for vuln in vulnerabilities:
                    vuln_id = vuln.get('pluginid', vuln.get('name', ''))
                    vuln_status = VulnerabilityStatus.query.filter_by(
                        scan_id=scan_id,
                        vuln_id=str(vuln_id)
                    ).first()
                    
                    current_status = vuln_status.status if vuln_status else 'open'
                    if current_status in statuses:
                        vuln['status'] = current_status
                        filtered_by_status.append(vuln)
                
                vulnerabilities = filtered_by_status
            
            # Apply tag filter if specified
            if tag:
                from aug30_sep3_features import VulnTag
                tags = tag.split(',')
                filtered_by_tag = []
                
                for vuln in vulnerabilities:
                    vuln_id = vuln.get('pluginid', vuln.get('name', ''))
                    vuln_tags = VulnTag.query.filter_by(
                        scan_id=scan_id,
                        vuln_id=str(vuln_id)
                    ).all()
                    
                    if any(vt.tag in tags for vt in vuln_tags):
                        vuln['tags'] = [vt.tag for vt in vuln_tags]
                        filtered_by_tag.append(vuln)
                
                vulnerabilities = filtered_by_tag
            
            # Add metadata
            for vuln in vulnerabilities:
                vuln_id = vuln.get('pluginid', vuln.get('name', ''))
                
                # Add status if not already added
                if 'status' not in vuln:
                    from aug24_29_features import VulnerabilityStatus
                    vuln_status = VulnerabilityStatus.query.filter_by(
                        scan_id=scan_id,
                        vuln_id=str(vuln_id)
                    ).first()
                    vuln['status'] = vuln_status.status if vuln_status else 'open'
                
                # Add tags if not already added
                if 'tags' not in vuln:
                    from aug30_sep3_features import VulnTag
                    vuln_tags = VulnTag.query.filter_by(
                        scan_id=scan_id,
                        vuln_id=str(vuln_id)
                    ).all()
                    vuln['tags'] = [vt.tag for vt in vuln_tags]
            
            # Cache filtered results
            if redis_client:
                cache_key = f'filtered_vulns:{scan_id}:{hashlib.md5(str(request.args).encode()).hexdigest()}'
                redis_client.setex(cache_key, 300, json.dumps(vulnerabilities))  # 5 minute cache
            
            return jsonify({
                'scan_id': scan_id,
                'total_vulnerabilities': len(vulnerabilities),
                'filters_applied': {
                    'severity': severity,
                    'confidence': confidence,
                    'type': vuln_type,
                    'status': status,
                    'tag': tag,
                    'search': search
                },
                'vulnerabilities': vulnerabilities
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to filter vulnerabilities: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities/summary', methods=['GET'])
    @jwt_required()
    def get_vulnerability_summary(scan_id):
        """Get vulnerability summary statistics"""
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
            vulnerabilities = scan.results.get('alerts', []) if scan.results else []
            
            # Count by severity
            severity_counts = defaultdict(int)
            confidence_counts = defaultdict(int)
            type_counts = defaultdict(int)
            status_counts = defaultdict(int)
            
            for vuln in vulnerabilities:
                severity_counts[vuln.get('risk', 'Unknown')] += 1
                confidence_counts[vuln.get('confidence', 'Unknown')] += 1
                type_counts[vuln.get('name', 'Unknown')] += 1
                
                # Get status
                vuln_id = vuln.get('pluginid', vuln.get('name', ''))
                from aug24_29_features import VulnerabilityStatus
                vuln_status = VulnerabilityStatus.query.filter_by(
                    scan_id=scan_id,
                    vuln_id=str(vuln_id)
                ).first()
                status = vuln_status.status if vuln_status else 'open'
                status_counts[status] += 1
            
            return jsonify({
                'total_vulnerabilities': len(vulnerabilities),
                'severity_breakdown': dict(severity_counts),
                'confidence_breakdown': dict(confidence_counts),
                'type_breakdown': dict(type_counts),
                'status_breakdown': dict(status_counts),
                'scan_info': {
                    'scan_id': scan.id,
                    'target_url': scan.target_url,
                    'created_at': scan.created_at.isoformat(),
                    'status': scan.status
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get summary: {str(e)}'}), 500

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
            import requests
            
            rapid7_url = os.environ.get('RAPID7_API_URL', 'https://us.api.insight.rapid7.com')
            api_key = rapid7_credentials.get('api_key')
            
            created_findings = []
            alerts = scan.results.get('alerts', []) if scan.results else []
            
            for alert in alerts:
                finding_data = {
                    'name': f'WebSecPen Scan {scan.id}',
                    'engineName': 'WebSecPen',
                    'startedTime': scan.created_at.isoformat(),
                    'assets': [{
                        'name': scan.target_url,
                        'ip': scan.target_url,
                        'vulnerabilities': [{
                            'id': alert.get('pluginid', alert.get('name', '')),
                            'title': alert.get('name', 'Unknown Vulnerability'),
                            'description': alert.get('desc', 'No description available'),
                            'severity': map_severity_to_rapid7(alert.get('risk', 'Unknown')),
                            'cvss': calculate_cvss_score(alert),
                            'solution': alert.get('solution', 'No solution provided')
                        }]
                    }]
                }
                
                # Send to Rapid7
                response = requests.post(
                    f'{rapid7_url}/api/3/scans',
                    headers={
                        'Authorization': f'Bearer {api_key}',
                        'Content-Type': 'application/json'
                    },
                    json=finding_data,
                    timeout=30
                )
                
                if response.status_code == 201:
                    result = response.json()
                    created_findings.append({
                        'vulnerability': alert.get('name'),
                        'status': 'created',
                        'rapid7_id': result.get('id'),
                        'scan_id': result.get('scanId')
                    })
                else:
                    created_findings.append({
                        'vulnerability': alert.get('name'),
                        'status': 'failed',
                        'error': f'HTTP {response.status_code}'
                    })
            
            # Log audit event
            log_audit_event(
                user_id=user_id,
                action='rapid7_integration',
                resource_type='scan',
                resource_id=scan_id,
                details={'findings_sent': len(created_findings)},
                request_obj=request
            )
            
            return jsonify({
                'message': f'Rapid7 integration completed',
                'findings_created': len([f for f in created_findings if f['status'] == 'created']),
                'findings_failed': len([f for f in created_findings if f['status'] == 'failed']),
                'findings': created_findings
            }), 200
            
        except Exception as e:
            app.logger.error(f'Rapid7 integration error: {str(e)}')
            return jsonify({'error': f'Rapid7 integration failed: {str(e)}'}), 500

def map_severity_to_rapid7(risk_level):
    """Map OWASP ZAP risk levels to Rapid7 severity"""
    mapping = {
        'high': 'critical',
        'medium': 'moderate',
        'low': 'severe',
        'informational': 'moderate'
    }
    return mapping.get(risk_level.lower(), 'moderate')

def calculate_cvss_score(alert):
    """Calculate CVSS score based on alert data"""
    risk = alert.get('risk', '').lower()
    confidence = alert.get('confidence', '').lower()
    
    base_scores = {
        'high': 8.5,
        'medium': 5.5,
        'low': 2.5,
        'informational': 1.0
    }
    
    confidence_multipliers = {
        'high': 1.0,
        'medium': 0.9,
        'low': 0.7,
        'false positive': 0.1
    }
    
    base_score = base_scores.get(risk, 5.0)
    multiplier = confidence_multipliers.get(confidence, 0.8)
    
    return round(base_score * multiplier, 1)

# 4. USER RETENTION DASHBOARD
def init_retention_analytics(app):
    """Initialize user retention analytics"""
    
    @app.route('/api/admin/retention/metrics', methods=['GET'])
    @jwt_required()
    def get_retention_metrics():
        """Get comprehensive user retention metrics"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            days = int(request.args.get('days', 30))
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get user registration data
            users = User.query.filter(User.created_at >= start_date).all()
            
            # Get scan activity
            scans = Scan.query.filter(Scan.created_at >= start_date).all()
            
            # Calculate retention metrics
            daily_metrics = defaultdict(lambda: {
                'new_users': 0,
                'active_users': set(),
                'scans_count': 0,
                'returning_users': set()
            })
            
            # Process user registrations
            for user in users:
                date = user.created_at.strftime('%Y-%m-%d')
                daily_metrics[date]['new_users'] += 1
            
            # Process scan activity
            for scan in scans:
                date = scan.created_at.strftime('%Y-%m-%d')
                daily_metrics[date]['active_users'].add(scan.user_id)
                daily_metrics[date]['scans_count'] += 1
                
                # Check if user was active before (returning user)
                previous_scans = Scan.query.filter(
                    Scan.user_id == scan.user_id,
                    Scan.created_at < scan.created_at
                ).first()
                if previous_scans:
                    daily_metrics[date]['returning_users'].add(scan.user_id)
            
            # Format data for response
            sorted_dates = sorted(daily_metrics.keys())
            
            return jsonify({
                'date_range': {
                    'start': start_date.isoformat(),
                    'end': datetime.utcnow().isoformat(),
                    'days': days
                },
                'dates': sorted_dates,
                'new_users': [daily_metrics[d]['new_users'] for d in sorted_dates],
                'active_users': [len(daily_metrics[d]['active_users']) for d in sorted_dates],
                'returning_users': [len(daily_metrics[d]['returning_users']) for d in sorted_dates],
                'scans_count': [daily_metrics[d]['scans_count'] for d in sorted_dates],
                'summary': {
                    'total_new_users': sum(daily_metrics[d]['new_users'] for d in sorted_dates),
                    'total_scans': sum(daily_metrics[d]['scans_count'] for d in sorted_dates),
                    'average_daily_active_users': sum(len(daily_metrics[d]['active_users']) for d in sorted_dates) / len(sorted_dates) if sorted_dates else 0
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
            url = request.args.get('url')
            scan_ids = request.args.get('scan_ids')  # Comma-separated list
            
            if not url and not scan_ids:
                return jsonify({'error': 'Either URL or scan_ids must be provided'}), 400
            
            # Get scans to compare
            if scan_ids:
                scan_id_list = [int(sid.strip()) for sid in scan_ids.split(',')]
                scans = Scan.query.filter(
                    Scan.id.in_(scan_id_list),
                    or_(
                        Scan.user_id == user_id,
                        Scan.team_id.in_(
                            db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                        )
                    )
                ).order_by(Scan.created_at.desc()).all()
            else:
                scans = Scan.query.filter(
                    Scan.target_url == url,
                    or_(
                        Scan.user_id == user_id,
                        Scan.team_id.in_(
                            db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                        )
                    )
                ).order_by(Scan.created_at.desc()).limit(10).all()
            
            if len(scans) < 2:
                return jsonify({'error': 'At least 2 scans are required for comparison'}), 400
            
            # Analyze vulnerability changes across scans
            comparison_data = analyze_vulnerability_changes(scans)
            
            return jsonify({
                'comparison_type': 'url' if url else 'specific_scans',
                'target_url': url,
                'scans_compared': len(scans),
                'scan_info': [{
                    'scan_id': scan.id,
                    'created_at': scan.created_at.isoformat(),
                    'status': scan.status,
                    'vulnerability_count': len(scan.results.get('alerts', [])) if scan.results else 0
                } for scan in scans],
                'vulnerability_analysis': comparison_data
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to compare scans: {str(e)}'}), 500

def analyze_vulnerability_changes(scans):
    """Analyze how vulnerabilities change across scan runs"""
    
    # Track vulnerabilities across scans
    vulnerability_timeline = defaultdict(list)
    
    for scan in scans:
        alerts = scan.results.get('alerts', []) if scan.results else []
        scan_vulns = set()
        
        for alert in alerts:
            vuln_signature = f"{alert.get('name', '')}:{alert.get('url', '')}:{alert.get('param', '')}"
            scan_vulns.add(vuln_signature)
            
            vulnerability_timeline[vuln_signature].append({
                'scan_id': scan.id,
                'scan_date': scan.created_at.isoformat(),
                'severity': alert.get('risk', 'Unknown'),
                'confidence': alert.get('confidence', 'Unknown'),
                'description': alert.get('desc', ''),
                'status': 'present'
            })
        
        # Mark vulnerabilities not found in this scan
        all_vulns = set(vulnerability_timeline.keys())
        missing_vulns = all_vulns - scan_vulns
        
        for vuln_sig in missing_vulns:
            if vulnerability_timeline[vuln_sig]:  # Only if we've seen it before
                vulnerability_timeline[vuln_sig].append({
                    'scan_id': scan.id,
                    'scan_date': scan.created_at.isoformat(),
                    'status': 'resolved'
                })
    
    # Analyze trends
    trends = {
        'new_vulnerabilities': [],
        'resolved_vulnerabilities': [],
        'persistent_vulnerabilities': [],
        'severity_changes': []
    }
    
    for vuln_sig, timeline in vulnerability_timeline.items():
        if len(timeline) == 1:
            if timeline[0]['status'] == 'present':
                trends['new_vulnerabilities'].append({
                    'signature': vuln_sig,
                    'first_seen': timeline[0]['scan_date'],
                    'severity': timeline[0]['severity']
                })
        else:
            # Check for resolution
            if timeline[-1]['status'] == 'resolved':
                trends['resolved_vulnerabilities'].append({
                    'signature': vuln_sig,
                    'last_seen': timeline[-2]['scan_date'],
                    'resolved_date': timeline[-1]['scan_date']
                })
            elif all(entry['status'] == 'present' for entry in timeline):
                trends['persistent_vulnerabilities'].append({
                    'signature': vuln_sig,
                    'first_seen': timeline[0]['scan_date'],
                    'occurrences': len(timeline)
                })
            
            # Check for severity changes
            severities = [entry['severity'] for entry in timeline if entry['status'] == 'present']
            if len(set(severities)) > 1:
                trends['severity_changes'].append({
                    'signature': vuln_sig,
                    'severity_timeline': severities
                })
    
    return {
        'total_unique_vulnerabilities': len(vulnerability_timeline),
        'trends': trends,
        'vulnerability_timeline': dict(vulnerability_timeline)
    }

# 2. ROLE ESCALATION WORKFLOWS
class RoleRequest(db.Model):
    """Role escalation requests"""
    __tablename__ = 'role_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    requested_role = db.Column(db.String(50), nullable=False)
    current_role = db.Column(db.String(50), nullable=False)
    justification = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, cancelled
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    review_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)

def init_role_escalation(app):
    """Initialize role escalation workflows"""
    
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
                return jsonify({'error': 'requested_role is required'}), 400
            
            # Check if user already has a pending request
            existing_request = RoleRequest.query.filter_by(
                user_id=user_id,
                status='pending'
            ).first()
            
            if existing_request:
                return jsonify({'error': 'You already have a pending role request'}), 400
            
            # Create request
            role_request = RoleRequest(
                user_id=user_id,
                requested_role=requested_role,
                current_role=user.role or 'user',
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
                    'requested_role': requested_role,
                    'current_role': user.role or 'user',
                    'justification': justification,
                    'created_at': role_request.created_at.isoformat()
                }, room='admin')
            except:
                pass
            
            # Log audit event
            log_audit_event(
                user_id=user_id,
                action='role_request_created',
                resource_type='role_request',
                resource_id=role_request.id,
                details={
                    'requested_role': requested_role,
                    'current_role': user.role or 'user'
                },
                request_obj=request
            )
            
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
            status_filter = request.args.get('status', 'pending')
            
            query = RoleRequest.query
            if status_filter != 'all':
                query = query.filter_by(status=status_filter)
            
            requests_list = query.order_by(RoleRequest.created_at.desc()).all()
            
            return jsonify([{
                'id': req.id,
                'user_id': req.user_id,
                'user_email': User.query.get(req.user_id).email,
                'requested_role': req.requested_role,
                'current_role': req.current_role,
                'justification': req.justification,
                'status': req.status,
                'reviewed_by': req.reviewed_by,
                'review_notes': req.review_notes,
                'created_at': req.created_at.isoformat(),
                'reviewed_at': req.reviewed_at.isoformat() if req.reviewed_at else None
            } for req in requests_list]), 200
            
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
                return jsonify({'error': 'Role request is not pending'}), 400
            
            data = request.get_json() or {}
            review_notes = data.get('review_notes', '')
            admin_user_id = get_jwt_identity()
            
            # Update request status
            role_request.status = 'approved' if action == 'approve' else 'rejected'
            role_request.reviewed_by = admin_user_id
            role_request.review_notes = review_notes
            role_request.reviewed_at = datetime.utcnow()
            
            # If approved, update user role
            if action == 'approve':
                user = User.query.get(role_request.user_id)
                if user:
                    old_role = user.role
                    user.role = role_request.requested_role
                    
                    # Log role change
                    log_audit_event(
                        user_id=admin_user_id,
                        action='role_changed',
                        resource_type='user',
                        resource_id=user.id,
                        details={
                            'old_role': old_role,
                            'new_role': user.role,
                            'request_id': request_id
                        },
                        severity='warning',
                        request_obj=request
                    )
            
            db.session.commit()
            
            # Notify user
            try:
                from app import socketio
                socketio.emit('role_request_update', {
                    'request_id': request_id,
                    'status': role_request.status,
                    'review_notes': review_notes,
                    'reviewed_at': role_request.reviewed_at.isoformat()
                }, room=f'user_{role_request.user_id}')
            except:
                pass
            
            return jsonify({
                'message': f'Role request {action}d successfully',
                'request_id': request_id,
                'status': role_request.status
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to {action} role request: {str(e)}'}), 500

# =============================================================================
# SEPTEMBER 1ST FEATURES - VULNERABILITY TAGGING AND SESSION ANALYTICS
# =============================================================================

# 1. VULNERABILITY TAGGING SYSTEM
class VulnTag(db.Model):
    """Vulnerability tags for categorization"""
    __tablename__ = 'vulnerability_tags'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    vuln_id = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tag = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(7), default='#007bff')  # Hex color code
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_vulnerability_tagging(app):
    """Initialize vulnerability tagging system"""
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities/<vuln_id>/tags', methods=['POST'])
    @jwt_required()
    def add_vulnerability_tag(scan_id, vuln_id):
        """Add a tag to a vulnerability"""
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
            data = request.get_json()
            tag = data.get('tag')
            color = data.get('color', '#007bff')
            description = data.get('description', '')
            
            if not tag:
                return jsonify({'error': 'Tag is required'}), 400
            
            # Check if tag already exists for this vulnerability
            existing_tag = VulnTag.query.filter_by(
                scan_id=scan_id,
                vuln_id=vuln_id,
                tag=tag,
                user_id=user_id
            ).first()
            
            if existing_tag:
                return jsonify({'error': 'Tag already exists for this vulnerability'}), 400
            
            # Create tag
            vuln_tag = VulnTag(
                scan_id=scan_id,
                vuln_id=vuln_id,
                user_id=user_id,
                tag=tag,
                color=color,
                description=description
            )
            
            db.session.add(vuln_tag)
            db.session.commit()
            
            # Emit real-time update
            try:
                from app import socketio
                socketio.emit('vulnerability_tag_added', {
                    'scan_id': scan_id,
                    'vuln_id': vuln_id,
                    'tag': tag,
                    'color': color,
                    'user_id': user_id,
                    'created_at': vuln_tag.created_at.isoformat()
                }, room=f'team_{scan.team_id}' if scan.team_id else f'user_{user_id}')
            except:
                pass
            
            return jsonify({
                'message': 'Tag added successfully',
                'tag_id': vuln_tag.id,
                'tag': tag,
                'color': color
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to add tag: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/vulnerabilities/<vuln_id>/tags', methods=['GET'])
    @jwt_required()
    def get_vulnerability_tags(scan_id, vuln_id):
        """Get all tags for a vulnerability"""
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
            tags = VulnTag.query.filter_by(
                scan_id=scan_id,
                vuln_id=vuln_id
            ).order_by(VulnTag.created_at.desc()).all()
            
            return jsonify([{
                'id': tag.id,
                'tag': tag.tag,
                'color': tag.color,
                'description': tag.description,
                'user_id': tag.user_id,
                'created_at': tag.created_at.isoformat()
            } for tag in tags]), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get tags: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/tags/export', methods=['GET'])
    @jwt_required()
    def export_tagged_vulnerabilities(scan_id):
        """Export vulnerabilities with specific tags as CSV"""
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
            tag_filter = request.args.get('tag')
            
            # Get tagged vulnerabilities
            query = VulnTag.query.filter_by(scan_id=scan_id)
            if tag_filter:
                query = query.filter_by(tag=tag_filter)
            
            tagged_vulns = query.all()
            
            # Generate CSV
            output = StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'Vulnerability ID', 'Tag', 'Tag Color', 'Tag Description',
                'Tagged By User ID', 'Tagged At', 'Vulnerability Name',
                'Severity', 'Confidence', 'URL', 'Description'
            ])
            
            # Get vulnerability details
            vulnerabilities = scan.results.get('alerts', []) if scan.results else []
            vuln_lookup = {
                alert.get('pluginid', alert.get('name', '')): alert 
                for alert in vulnerabilities
            }
            
            # Write data
            for tag in tagged_vulns:
                vuln_data = vuln_lookup.get(tag.vuln_id, {})
                
                writer.writerow([
                    tag.vuln_id,
                    tag.tag,
                    tag.color,
                    tag.description,
                    tag.user_id,
                    tag.created_at.isoformat(),
                    vuln_data.get('name', 'Unknown'),
                    vuln_data.get('risk', 'Unknown'),
                    vuln_data.get('confidence', 'Unknown'),
                    vuln_data.get('url', ''),
                    vuln_data.get('desc', '')
                ])
            
            # Create response
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            tag_suffix = f'_{tag_filter}' if tag_filter else ''
            filename = f'tagged_vulnerabilities_scan_{scan_id}{tag_suffix}_{timestamp}.csv'
            
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
            
        except Exception as e:
            return jsonify({'error': f'Failed to export tagged vulnerabilities: {str(e)}'}), 500

# 2. USER SESSION ANALYTICS
class SessionLog(db.Model):
    """User session tracking"""
    __tablename__ = 'session_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(128), nullable=False)
    login_time = db.Column(db.DateTime, nullable=False)
    logout_time = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    activity_count = db.Column(db.Integer, default=0)  # Number of actions during session
    last_activity = db.Column(db.DateTime)

def init_session_analytics(app):
    """Initialize session analytics"""
    
    @app.route('/api/session/start', methods=['POST'])
    @jwt_required()
    def start_session_tracking():
        """Start tracking a user session"""
        user_id = get_jwt_identity()
        
        try:
            data = request.get_json() or {}
            session_id = data.get('session_id', secrets.token_hex(16))
            
            session_log = SessionLog(
                user_id=user_id,
                session_id=session_id,
                login_time=datetime.utcnow(),
                ip_address=request.environ.get('REMOTE_ADDR'),
                user_agent=request.headers.get('User-Agent'),
                last_activity=datetime.utcnow()
            )
            
            db.session.add(session_log)
            db.session.commit()
            
            return jsonify({
                'session_id': session_log.id,
                'tracking_id': session_id
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to start session tracking: {str(e)}'}), 500
    
    @app.route('/api/session/<int:session_log_id>/activity', methods=['POST'])
    @jwt_required()
    def log_session_activity(session_log_id):
        """Log activity within a session"""
        user_id = get_jwt_identity()
        
        try:
            session_log = SessionLog.query.filter_by(
                id=session_log_id,
                user_id=user_id
            ).first()
            
            if not session_log:
                return jsonify({'error': 'Session not found'}), 404
            
            session_log.activity_count += 1
            session_log.last_activity = datetime.utcnow()
            db.session.commit()
            
            return jsonify({'message': 'Activity logged'}), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to log activity: {str(e)}'}), 500
    
    @app.route('/api/session/<int:session_log_id>/end', methods=['POST'])
    @jwt_required()
    def end_session_tracking(session_log_id):
        """End session tracking"""
        user_id = get_jwt_identity()
        
        try:
            session_log = SessionLog.query.filter_by(
                id=session_log_id,
                user_id=user_id
            ).first()
            
            if not session_log:
                return jsonify({'error': 'Session not found'}), 404
            
            if session_log.logout_time:
                return jsonify({'message': 'Session already ended'}), 200
            
            session_log.logout_time = datetime.utcnow()
            session_log.duration_seconds = int(
                (session_log.logout_time - session_log.login_time).total_seconds()
            )
            
            db.session.commit()
            
            return jsonify({
                'message': 'Session ended',
                'duration_seconds': session_log.duration_seconds
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to end session: {str(e)}'}), 500
    
    @app.route('/api/admin/session/analytics', methods=['GET'])
    @jwt_required()
    def get_session_analytics():
        """Get session analytics for admins"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            days = int(request.args.get('days', 30))
            start_date = datetime.utcnow() - timedelta(days=days)
            
            sessions = SessionLog.query.filter(
                SessionLog.login_time >= start_date
            ).all()
            
            # Calculate analytics
            daily_sessions = defaultdict(lambda: {
                'session_count': 0,
                'unique_users': set(),
                'total_duration': 0,
                'avg_activity': 0
            })
            
            total_duration = 0
            active_sessions = 0
            
            for session in sessions:
                date = session.login_time.strftime('%Y-%m-%d')
                daily_sessions[date]['session_count'] += 1
                daily_sessions[date]['unique_users'].add(session.user_id)
                
                if session.duration_seconds:
                    daily_sessions[date]['total_duration'] += session.duration_seconds
                    total_duration += session.duration_seconds
                    active_sessions += 1
                
                daily_sessions[date]['avg_activity'] += session.activity_count
            
            # Format for response
            sorted_dates = sorted(daily_sessions.keys())
            
            return jsonify({
                'date_range': {
                    'start': start_date.isoformat(),
                    'end': datetime.utcnow().isoformat(),
                    'days': days
                },
                'dates': sorted_dates,
                'daily_sessions': [daily_sessions[d]['session_count'] for d in sorted_dates],
                'unique_daily_users': [len(daily_sessions[d]['unique_users']) for d in sorted_dates],
                'avg_session_duration': [
                    daily_sessions[d]['total_duration'] / daily_sessions[d]['session_count'] 
                    if daily_sessions[d]['session_count'] > 0 else 0 
                    for d in sorted_dates
                ],
                'avg_activity_per_session': [
                    daily_sessions[d]['avg_activity'] / daily_sessions[d]['session_count']
                    if daily_sessions[d]['session_count'] > 0 else 0
                    for d in sorted_dates
                ],
                'summary': {
                    'total_sessions': len(sessions),
                    'average_duration_minutes': (total_duration / active_sessions / 60) if active_sessions > 0 else 0,
                    'total_unique_users': len(set(s.user_id for s in sessions))
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get session analytics: {str(e)}'}), 500

# =============================================================================
# SEPTEMBER 2ND FEATURES - ADVANCED SCHEDULING AND 2FA
# =============================================================================

# 1. TWO-FACTOR AUTHENTICATION (2FA)
def init_two_factor_auth(app):
    """Initialize two-factor authentication"""
    
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
            if hasattr(user, 'totp_enabled') and user.totp_enabled:
                return jsonify({'error': '2FA is already enabled'}), 400
            
            # Generate secret
            secret = random_base32()
            
            # Store secret temporarily (user needs to verify before enabling)
            if not hasattr(user, 'preferences'):
                user.preferences = {}
            if user.preferences is None:
                user.preferences = {}
            
            user.preferences['totp_secret_pending'] = secret
            db.session.commit()
            
            # Generate QR code URI
            totp = TOTP(secret)
            qr_uri = totp.provisioning_uri(
                name=user.email,
                issuer_name='WebSecPen Security Platform'
            )
            
            # Generate QR code image as base64
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(qr_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img_buffer = BytesIO()
            img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            qr_code_data = base64.b64encode(img_buffer.getvalue()).decode()
            
            return jsonify({
                'secret': secret,
                'qr_code_uri': qr_uri,
                'qr_code_image': f'data:image/png;base64,{qr_code_data}',
                'instructions': [
                    '1. Install an authenticator app (Google Authenticator, Authy, etc.)',
                    '2. Scan the QR code or manually enter the secret',
                    '3. Enter the 6-digit code from your app to verify setup'
                ]
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to setup 2FA: {str(e)}'}), 500
    
    @app.route('/api/2fa/verify', methods=['POST'])
    @jwt_required()
    def verify_2fa_setup():
        """Verify and enable 2FA"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        try:
            data = request.get_json()
            code = data.get('code')
            
            if not code:
                return jsonify({'error': 'Verification code is required'}), 400
            
            # Get pending secret
            if not user.preferences or 'totp_secret_pending' not in user.preferences:
                return jsonify({'error': '2FA setup not initiated'}), 400
            
            secret = user.preferences['totp_secret_pending']
            
            # Verify code
            totp = TOTP(secret)
            if not totp.verify(code, valid_window=2):  # Allow 2 time windows for clock skew
                return jsonify({'error': 'Invalid verification code'}), 400
            
            # Enable 2FA
            if not hasattr(user, 'totp_secret'):
                # Add columns if they don't exist (migration needed)
                user.preferences['totp_secret'] = secret
                user.preferences['totp_enabled'] = True
            else:
                user.totp_secret = secret
                user.totp_enabled = True
            
            # Remove pending secret
            user.preferences.pop('totp_secret_pending', None)
            db.session.commit()
            
            # Log audit event
            log_audit_event(
                user_id=user_id,
                action='2fa_enabled',
                resource_type='user',
                resource_id=user_id,
                severity='warning',
                request_obj=request
            )
            
            return jsonify({
                'message': '2FA enabled successfully',
                'backup_codes': generate_backup_codes(user_id)  # Generate backup codes
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to verify 2FA: {str(e)}'}), 500
    
    @app.route('/api/2fa/disable', methods=['POST'])
    @jwt_required()
    def disable_2fa():
        """Disable 2FA for user"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        try:
            data = request.get_json()
            code = data.get('code')
            password = data.get('password')
            
            if not code or not password:
                return jsonify({'error': 'Current 2FA code and password are required'}), 400
            
            # Verify password
            if not check_password_hash(user.password, password):
                return jsonify({'error': 'Invalid password'}), 401
            
            # Check if 2FA is enabled
            totp_enabled = getattr(user, 'totp_enabled', user.preferences.get('totp_enabled', False) if user.preferences else False)
            if not totp_enabled:
                return jsonify({'error': '2FA is not enabled'}), 400
            
            # Verify current 2FA code
            secret = getattr(user, 'totp_secret', user.preferences.get('totp_secret') if user.preferences else None)
            if secret:
                totp = TOTP(secret)
                if not totp.verify(code, valid_window=2):
                    return jsonify({'error': 'Invalid 2FA code'}), 400
            
            # Disable 2FA
            if hasattr(user, 'totp_secret'):
                user.totp_secret = None
                user.totp_enabled = False
            
            if user.preferences:
                user.preferences.pop('totp_secret', None)
                user.preferences.pop('totp_enabled', None)
                user.preferences.pop('backup_codes', None)
            
            db.session.commit()
            
            # Log audit event
            log_audit_event(
                user_id=user_id,
                action='2fa_disabled',
                resource_type='user',
                resource_id=user_id,
                severity='warning',
                request_obj=request
            )
            
            return jsonify({'message': '2FA disabled successfully'}), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to disable 2FA: {str(e)}'}), 500

def generate_backup_codes(user_id):
    """Generate backup codes for 2FA"""
    backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
    
    # Store hashed backup codes
    user = User.query.get(user_id)
    if user:
        if not user.preferences:
            user.preferences = {}
        user.preferences['backup_codes'] = [hashlib.sha256(code.encode()).hexdigest() for code in backup_codes]
        db.session.commit()
    
    return backup_codes

# Enhanced login with 2FA support
def init_enhanced_login(app):
    """Initialize enhanced login with 2FA support"""
    
    @app.route('/api/login', methods=['POST'])
    def enhanced_login():
        """Enhanced login with 2FA support"""
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            totp_code = data.get('totp_code')
            backup_code = data.get('backup_code')
            
            if not email or not password:
                return jsonify({'error': 'Email and password are required'}), 400
            
            # Find user
            user = User.query.filter_by(email=email).first()
            if not user or not check_password_hash(user.password, password):
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Check if 2FA is enabled
            totp_enabled = getattr(user, 'totp_enabled', user.preferences.get('totp_enabled', False) if user.preferences else False)
            
            if totp_enabled:
                secret = getattr(user, 'totp_secret', user.preferences.get('totp_secret') if user.preferences else None)
                
                if not secret:
                    return jsonify({'error': '2FA configuration error'}), 500
                
                verified = False
                
                # Try TOTP code first
                if totp_code:
                    totp = TOTP(secret)
                    verified = totp.verify(totp_code, valid_window=2)
                
                # Try backup code if TOTP failed
                if not verified and backup_code:
                    backup_codes = user.preferences.get('backup_codes', []) if user.preferences else []
                    backup_hash = hashlib.sha256(backup_code.upper().encode()).hexdigest()
                    
                    if backup_hash in backup_codes:
                        # Remove used backup code
                        backup_codes.remove(backup_hash)
                        user.preferences['backup_codes'] = backup_codes
                        db.session.commit()
                        verified = True
                
                if not verified:
                    return jsonify({
                        'error': 'Invalid or missing 2FA code',
                        'requires_2fa': True
                    }), 401
            
            # Create access token
            additional_claims = {
                'is_admin': user.role == 'admin',
                'role': user.role or 'user'
            }
            
            access_token = create_access_token(
                identity=user.id,
                additional_claims=additional_claims
            )
            
            # Start session tracking
            session_log = SessionLog(
                user_id=user.id,
                session_id=secrets.token_hex(16),
                login_time=datetime.utcnow(),
                ip_address=request.environ.get('REMOTE_ADDR'),
                user_agent=request.headers.get('User-Agent'),
                last_activity=datetime.utcnow()
            )
            
            db.session.add(session_log)
            db.session.commit()
            
            # Log audit event
            log_audit_event(
                user_id=user.id,
                action='user_login',
                details={
                    '2fa_used': totp_enabled,
                    'backup_code_used': backup_code is not None and totp_enabled
                },
                request_obj=request
            )
            
            return jsonify({
                'access_token': access_token,
                'session_id': session_log.id,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'role': user.role or 'user',
                    '2fa_enabled': totp_enabled
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Login failed: {str(e)}'}), 500

# =============================================================================
# HELPER FUNCTIONS FOR INTEGRATIONS
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

def init_aug30_sep3_routes(app):
    """Initialize all August 30 - September 3 features"""
    
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
    init_vulnerability_tagging(app)
    init_session_analytics(app)
    init_two_factor_auth(app)
    init_enhanced_login(app)
    
    print("✅ August 30 - September 3 features initialized successfully!")
    print("🔧 Features: Audit Export, Vulnerability Filters, 2FA, Role Escalation, Tagging, Session Analytics, Advanced Integrations")
    
    return app 