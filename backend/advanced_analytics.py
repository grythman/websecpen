# advanced_analytics.py - Advanced Analytics and Integrations for WebSecPen (Aug 16, 2025)
import os
import json
import requests
import pybreaker
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from flask import Flask, jsonify, request, has_request_context
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from flask_socketio import SocketIO, emit, join_room
from transformers import pipeline
from models import db, User, Scan, AuditLog, TeamMember

# Circuit breakers for external API reliability
zap_breaker = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60, name='ZAP_API')
huggingface_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=120, name='HuggingFace_API')

# Initialize services
socketio = None
remediation_generator = None

def init_advanced_analytics(app):
    """Initialize advanced analytics and integrations"""
    global socketio, remediation_generator
    
    # Initialize SocketIO for real-time collaboration
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    # Initialize AI remediation generator
    try:
        remediation_generator = pipeline(
            'text-generation', 
            model='distilgpt2',  # Faster than GPT-2
            max_length=100
        )
    except Exception as e:
        print(f"Warning: Could not initialize remediation generator: {e}")
    
    return socketio

def log_api_call(action):
    """Decorator to log API calls for analytics"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_id = None
            endpoint = None
            
            try:
                if has_request_context():
                    user_id = get_jwt_identity()
                    endpoint = request.path
                
                result = f(*args, **kwargs)
                
                # Log the API call
                if endpoint:
                    log = AuditLog(
                        user_id=user_id,
                        action=action,
                        details={
                            'endpoint': endpoint,
                            'method': request.method,
                            'status': 'success'
                        }
                    )
                    db.session.add(log)
                    db.session.commit()
                
                return result
                
            except Exception as e:
                # Log failed API calls too
                if endpoint:
                    log = AuditLog(
                        user_id=user_id,
                        action=f"{action}_failed",
                        details={
                            'endpoint': endpoint,
                            'method': request.method,
                            'error': str(e),
                            'status': 'error'
                        }
                    )
                    db.session.add(log)
                    db.session.commit()
                raise
        return wrapped
    return decorator

@zap_breaker
def start_zap_scan_with_config(url, scan_config):
    """Start ZAP scan with custom configuration and circuit breaker"""
    try:
        # This would integrate with your existing ZAP scanner
        # For now, we'll simulate the scan with config
        scan_type = scan_config.get('scan_type', 'spider')
        max_depth = scan_config.get('max_depth', 10)
        ajax_spider = scan_config.get('ajax_spider', False)
        scan_policy = scan_config.get('scan_policy', 'default')
        
        # Mock scan result for now - replace with actual ZAP integration
        scan_id = f"scan_{datetime.utcnow().timestamp()}"
        
        # Log the scan configuration
        print(f"Starting {scan_type} scan for {url} with depth {max_depth}, AJAX: {ajax_spider}, Policy: {scan_policy}")
        
        return scan_id
        
    except Exception as e:
        raise Exception(f"ZAP scan failed: {str(e)}")

def send_to_splunk(scan_data):
    """Send scan results to Splunk via HTTP Event Collector"""
    try:
        splunk_url = os.environ.get('SPLUNK_HEC_URL')
        splunk_token = os.environ.get('SPLUNK_HEC_TOKEN')
        
        if not splunk_url or not splunk_token:
            return False
        
        payload = {
            'event': {
                'scan_id': scan_data.get('scan_id'),
                'url': scan_data.get('url'),
                'results': scan_data.get('results'),
                'user_id': scan_data.get('user_id'),
                'team_id': scan_data.get('team_id'),
                'timestamp': scan_data.get('timestamp'),
                'vulnerability_count': len(scan_data.get('results', [])),
                'source': 'WebSecPen'
            },
            'sourcetype': 'securescan:vulnerability',
            'index': 'security'
        }
        
        headers = {
            'Authorization': f'Splunk {splunk_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            splunk_url,
            headers=headers,
            json=payload,
            timeout=10
        )
        
        return response.status_code == 200
        
    except Exception as e:
        print(f"Splunk integration error: {e}")
        return False

@huggingface_breaker
def generate_remediation_suggestion(vulnerability):
    """Generate AI-powered remediation suggestions"""
    if not remediation_generator:
        return "Remediation generator not available"
    
    try:
        vuln_type = vulnerability.get('type', 'Unknown')
        vuln_desc = vulnerability.get('description', '')
        
        prompt = f"Fix {vuln_type} vulnerability: {vuln_desc[:100]}. Solution:"
        
        result = remediation_generator(
            prompt,
            max_length=len(prompt) + 50,
            num_return_sequences=1,
            temperature=0.7,
            do_sample=True,
            pad_token_id=remediation_generator.tokenizer.eos_token_id
        )[0]
        
        # Extract just the generated part
        generated_text = result['generated_text'][len(prompt):].strip()
        
        return generated_text if generated_text else "Update your security configuration to prevent this vulnerability."
        
    except Exception as e:
        return f"Could not generate suggestion: {str(e)}"

def init_advanced_routes(app):
    """Initialize all advanced analytics routes"""
    
    # =============================================================================
    # 1. USER ACTIVITY HEATMAPS
    # =============================================================================
    
    @app.route('/api/admin/heatmap', methods=['GET'])
    @jwt_required()
    @log_api_call('admin_heatmap')
    def get_activity_heatmap():
        """Get user activity heatmap data for admin dashboard"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        # Get data for last 7 days
        days = request.args.get('days', 7, type=int)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        logs = AuditLog.query.filter(AuditLog.timestamp >= start_date).all()
        
        # Build heatmap data structure
        heatmap = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            day = log.timestamp.strftime('%Y-%m-%d')
            hour = log.timestamp.hour
            heatmap[day][hour] += 1
        
        # Convert to format expected by frontend
        sorted_days = sorted(heatmap.keys())
        hours = list(range(24))
        
        # Create 2D array: [day][hour] = count
        data = []
        for day in sorted_days:
            day_data = [heatmap[day].get(hour, 0) for hour in hours]
            data.append(day_data)
        
        return jsonify({
            'days': sorted_days,
            'hours': hours,
            'data': data,
            'total_requests': sum(sum(day_data) for day_data in data)
        }), 200
    
    @app.route('/api/admin/analytics/endpoints', methods=['GET'])
    @jwt_required()
    @log_api_call('admin_endpoint_analytics')
    def get_endpoint_analytics():
        """Get endpoint usage analytics"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        days = request.args.get('days', 30, type=int)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        logs = AuditLog.query.filter(AuditLog.timestamp >= start_date).all()
        
        endpoint_counts = defaultdict(int)
        error_counts = defaultdict(int)
        
        for log in logs:
            endpoint = log.details.get('endpoint', 'unknown')
            endpoint_counts[endpoint] += 1
            
            if log.details.get('status') == 'error':
                error_counts[endpoint] += 1
        
        # Convert to list format for frontend
        analytics = []
        for endpoint, count in sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True):
            analytics.append({
                'endpoint': endpoint,
                'requests': count,
                'errors': error_counts.get(endpoint, 0),
                'error_rate': round((error_counts.get(endpoint, 0) / count) * 100, 2) if count > 0 else 0
            })
        
        return jsonify({
            'endpoints': analytics,
            'total_requests': sum(endpoint_counts.values()),
            'total_errors': sum(error_counts.values())
        }), 200
    
    # =============================================================================
    # 2. CUSTOM SCAN CONFIGURATIONS
    # =============================================================================
    
    @app.route('/api/scan/start', methods=['POST'])
    @jwt_required()
    @log_api_call('scan_start')
    def start_custom_scan():
        """Start scan with custom configuration"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        url = data.get('url')
        team_id = data.get('team_id')
        
        # Enhanced scan configuration
        scan_config = data.get('config', {
            'scan_type': 'spider',
            'max_depth': 10,
            'ajax_spider': False,
            'scan_policy': 'default',
            'include_alpha': False,
            'include_beta': False,
            'custom_headers': {},
            'authentication': None,
            'exclusion_patterns': []
        })
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Check team permissions if team scan
        if team_id:
            member = TeamMember.query.filter_by(team_id=team_id, user_id=user_id).first()
            if not member or 'scan' not in (member.permissions or []):
                return jsonify({'error': 'Permission denied for team scan'}), 403
        
        try:
            # Start scan with circuit breaker protection
            scan_id = start_zap_scan_with_config(url, scan_config)
            
            # Create scan record
            scan = Scan(
                user_id=user_id,
                team_id=team_id,
                target_url=url,
                scan_type=scan_config.get('scan_type', 'spider'),
                status='running',
                scan_config=scan_config
            )
            
            db.session.add(scan)
            db.session.commit()
            
            # Notify team members via WebSocket if team scan
            if team_id and socketio:
                socketio.emit('new_scan', {
                    'scan_id': scan.id,
                    'url': url,
                    'status': 'running',
                    'config': scan_config
                }, room=f'team_{team_id}')
            
            return jsonify({
                'scan_id': scan.id,
                'status': 'running',
                'config': scan_config
            }), 201
            
        except pybreaker.CircuitBreakerError:
            return jsonify({
                'error': 'Scanning service temporarily unavailable. Please try again later.'
            }), 503
        except Exception as e:
            return jsonify({'error': f'Failed to start scan: {str(e)}'}), 500
    
    @app.route('/api/scan/presets', methods=['GET'])
    @jwt_required()
    @log_api_call('scan_presets')
    def get_scan_presets():
        """Get predefined scan configuration presets"""
        presets = {
            'quick': {
                'name': 'Quick Scan',
                'description': 'Fast spider scan with limited depth',
                'config': {
                    'scan_type': 'spider',
                    'max_depth': 3,
                    'ajax_spider': False,
                    'scan_policy': 'default'
                }
            },
            'comprehensive': {
                'name': 'Comprehensive Scan',
                'description': 'Deep scan with active vulnerability detection',
                'config': {
                    'scan_type': 'active',
                    'max_depth': 15,
                    'ajax_spider': True,
                    'scan_policy': 'comprehensive',
                    'include_alpha': True,
                    'include_beta': False
                }
            },
            'ajax_heavy': {
                'name': 'AJAX Application Scan',
                'description': 'Optimized for modern web applications',
                'config': {
                    'scan_type': 'spider',
                    'max_depth': 10,
                    'ajax_spider': True,
                    'scan_policy': 'modern_web'
                }
            }
        }
        
        return jsonify({'presets': presets}), 200
    
    # =============================================================================
    # 3. AI-POWERED REMEDIATION SUGGESTIONS
    # =============================================================================
    
    @app.route('/api/scan/<int:scan_id>/remediations', methods=['GET'])
    @jwt_required()
    @log_api_call('scan_remediations')
    def get_scan_remediations(scan_id):
        """Get AI-generated remediation suggestions for scan results"""
        user_id = get_jwt_identity()
        
        # Check scan access (user or team member)
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
        
        if scan.status != 'completed' or not scan.results:
            return jsonify({'error': 'Scan not completed or no results available'}), 400
        
        try:
            remediations = []
            vulnerabilities = scan.results.get('alerts', []) if scan.results else []
            
            for vuln in vulnerabilities[:10]:  # Limit to 10 to avoid long processing
                suggestion = generate_remediation_suggestion(vuln)
                
                remediations.append({
                    'vulnerability_type': vuln.get('name', 'Unknown'),
                    'severity': vuln.get('risk', 'Unknown'),
                    'description': vuln.get('desc', 'No description available'),
                    'remediation': suggestion,
                    'url': vuln.get('url', scan.target_url)
                })
            
            return jsonify({
                'scan_id': scan_id,
                'remediations': remediations,
                'total_vulnerabilities': len(vulnerabilities),
                'generated_at': datetime.utcnow().isoformat()
            }), 200
            
        except pybreaker.CircuitBreakerError:
            return jsonify({
                'error': 'AI service temporarily unavailable',
                'remediations': []
            }), 503
        except Exception as e:
            return jsonify({'error': f'Failed to generate remediations: {str(e)}'}), 500
    
    # =============================================================================
    # 4. REAL-TIME TEAM COLLABORATION (WebSocket Events)
    # =============================================================================
    
    @socketio.on('join_team')
    def handle_join_team(data):
        """Handle user joining team room for real-time updates"""
        try:
            team_id = data.get('team_id')
            user_id = get_jwt_identity()
            
            # Verify user is team member
            member = TeamMember.query.filter_by(team_id=team_id, user_id=user_id).first()
            if member:
                join_room(f'team_{team_id}')
                emit('joined_team', {'team_id': team_id, 'status': 'success'})
            else:
                emit('error', {'message': 'Not authorized for this team'})
                
        except Exception as e:
            emit('error', {'message': f'Failed to join team: {str(e)}'})
    
    @socketio.on('scan_update')
    def handle_scan_update(data):
        """Handle scan status updates for team members"""
        try:
            scan_id = data.get('scan_id')
            status = data.get('status')
            
            scan = Scan.query.get(scan_id)
            if scan and scan.team_id:
                socketio.emit('scan_status_update', {
                    'scan_id': scan_id,
                    'status': status,
                    'url': scan.target_url,
                    'timestamp': datetime.utcnow().isoformat()
                }, room=f'team_{scan.team_id}')
                
        except Exception as e:
            emit('error', {'message': f'Failed to update scan: {str(e)}'})
    
    # =============================================================================
    # 5. SIEM INTEGRATION
    # =============================================================================
    
    @app.route('/api/scan/<int:scan_id>/export/splunk', methods=['POST'])
    @jwt_required()
    @log_api_call('splunk_export')
    def export_to_splunk(scan_id):
        """Export scan results to Splunk SIEM"""
        user_id = get_jwt_identity()
        
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
            scan_data = {
                'scan_id': scan.id,
                'url': scan.target_url,
                'results': scan.results,
                'user_id': scan.user_id,
                'team_id': scan.team_id,
                'timestamp': scan.completed_at.isoformat() if scan.completed_at else scan.created_at.isoformat()
            }
            
            success = send_to_splunk(scan_data)
            
            if success:
                return jsonify({
                    'message': 'Successfully exported to Splunk',
                    'scan_id': scan_id
                }), 200
            else:
                return jsonify({
                    'error': 'Failed to export to Splunk. Check configuration.'
                }), 500
                
        except Exception as e:
            return jsonify({'error': f'Splunk export failed: {str(e)}'}), 500
    
    @app.route('/api/admin/integrations/status', methods=['GET'])
    @jwt_required()
    @log_api_call('integrations_status')
    def get_integrations_status():
        """Get status of external integrations"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        status = {
            'zap_api': {
                'name': 'OWASP ZAP Scanner',
                'status': 'open' if zap_breaker.current_state == 'closed' else zap_breaker.current_state,
                'failure_count': zap_breaker.fail_counter,
                'last_failure': str(zap_breaker.last_failure) if zap_breaker.last_failure else None
            },
            'huggingface_api': {
                'name': 'AI Remediation Service',
                'status': 'open' if huggingface_breaker.current_state == 'closed' else huggingface_breaker.current_state,
                'failure_count': huggingface_breaker.fail_counter,
                'last_failure': str(huggingface_breaker.last_failure) if huggingface_breaker.last_failure else None
            },
            'splunk_hec': {
                'name': 'Splunk Integration',
                'status': 'configured' if os.environ.get('SPLUNK_HEC_URL') else 'not_configured',
                'url': os.environ.get('SPLUNK_HEC_URL', 'Not configured')
            }
        }
        
        return jsonify({'integrations': status}), 200
    
    return app 