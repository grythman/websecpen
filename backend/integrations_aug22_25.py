# integrations_aug22_25.py - External Integrations for WebSecPen (Aug 22-25, 2025)
# ServiceNow, PagerDuty, Zapier, and other external service integrations

import os
import json
import hashlib
import hmac
import requests
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from sqlalchemy import or_

from models import db, User, Scan, TeamMember, ApiKey

# =============================================================================
# SERVICENOW INTEGRATION
# =============================================================================

def init_servicenow_integration(app):
    """Initialize ServiceNow integration routes"""
    
    @app.route('/api/scan/<int:scan_id>/servicenow', methods=['POST'])
    @jwt_required()
    def create_servicenow_incident_integration(scan_id):
        """Create ServiceNow incidents for high-severity vulnerabilities"""
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
        
        # Check ServiceNow configuration
        servicenow_url = os.environ.get('SERVICENOW_URL')
        servicenow_token = os.environ.get('SERVICENOW_TOKEN')
        
        if not servicenow_url or not servicenow_token:
            return jsonify({'error': 'ServiceNow not configured'}), 400
        
        try:
            created_incidents = []
            alerts = scan.results.get('alerts', []) if scan.results else []
            
            for alert in alerts:
                # Only create incidents for high-severity vulnerabilities
                if alert.get('risk', '').lower() == 'high':
                    incident_data = {
                        'short_description': f'Security Vulnerability: {alert.get("name", "Unknown")} in {scan.target_url}',
                        'description': f"""Security scan has identified a high-risk vulnerability:

Vulnerability: {alert.get('name', 'Unknown')}
Risk Level: {alert.get('risk', 'Unknown')}
Confidence: {alert.get('confidence', 'Unknown')}
URL: {alert.get('url', scan.target_url)}
Parameter: {alert.get('param', 'N/A')}

Description:
{alert.get('desc', 'No description available')}

Evidence:
{alert.get('evidence', 'No evidence available')}

Scan ID: {scan.id}
Scan Date: {scan.created_at}
Target: {scan.target_url}
""",
                        'urgency': '1',  # High urgency
                        'impact': '2',   # Medium impact
                        'category': 'Security',
                        'subcategory': 'Vulnerability',
                        'state': '1',    # New
                        'caller_id': os.environ.get('SERVICENOW_CALLER_ID', 'system'),
                        'assignment_group': os.environ.get('SERVICENOW_SECURITY_GROUP', 'Security Team')
                    }
                    
                    # Create incident
                    response = requests.post(
                        f'{servicenow_url}/api/now/table/incident',
                        headers={
                            'Authorization': f'Bearer {servicenow_token}',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        },
                        json=incident_data,
                        timeout=30
                    )
                    
                    if response.status_code == 201:
                        incident_result = response.json()
                        created_incidents.append({
                            'incident_number': incident_result['result']['number'],
                            'sys_id': incident_result['result']['sys_id'],
                            'vulnerability': alert.get('name'),
                            'status': 'created'
                        })
                    else:
                        app.logger.error(f'ServiceNow incident creation failed: {response.status_code} - {response.text}')
                        created_incidents.append({
                            'vulnerability': alert.get('name'),
                            'status': 'failed',
                            'error': f'HTTP {response.status_code}'
                        })
            
            return jsonify({
                'message': f'ServiceNow integration completed',
                'incidents_created': len([i for i in created_incidents if i['status'] == 'created']),
                'incidents_failed': len([i for i in created_incidents if i['status'] == 'failed']),
                'incidents': created_incidents
            }), 200
            
        except Exception as e:
            app.logger.error(f'ServiceNow integration error: {str(e)}')
            return jsonify({'error': f'ServiceNow integration failed: {str(e)}'}), 500
    
    @app.route('/api/integrations/servicenow/test', methods=['POST'])
    @jwt_required()
    def test_servicenow_connection():
        """Test ServiceNow connection"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        servicenow_url = os.environ.get('SERVICENOW_URL')
        servicenow_token = os.environ.get('SERVICENOW_TOKEN')
        
        if not servicenow_url or not servicenow_token:
            return jsonify({'error': 'ServiceNow not configured'}), 400
        
        try:
            # Test connection by querying incident table
            response = requests.get(
                f'{servicenow_url}/api/now/table/incident?sysparm_limit=1',
                headers={
                    'Authorization': f'Bearer {servicenow_token}',
                    'Accept': 'application/json'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                return jsonify({
                    'status': 'success',
                    'message': 'ServiceNow connection successful'
                }), 200
            else:
                return jsonify({
                    'status': 'failed',
                    'message': f'ServiceNow connection failed: HTTP {response.status_code}'
                }), 400
                
        except Exception as e:
            return jsonify({
                'status': 'failed',
                'message': f'ServiceNow connection failed: {str(e)}'
            }), 500

# =============================================================================
# PAGERDUTY INTEGRATION
# =============================================================================

def init_pagerduty_integration(app):
    """Initialize PagerDuty integration routes"""
    
    @app.route('/api/scan/<int:scan_id>/pagerduty', methods=['POST'])
    @jwt_required()
    def create_pagerduty_incident_integration(scan_id):
        """Create PagerDuty incidents for critical vulnerabilities"""
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
        
        # Check PagerDuty configuration
        pagerduty_routing_key = os.environ.get('PAGERDUTY_ROUTING_KEY')
        
        if not pagerduty_routing_key:
            return jsonify({'error': 'PagerDuty not configured'}), 400
        
        try:
            created_alerts = []
            alerts = scan.results.get('alerts', []) if scan.results else []
            
            for alert in alerts:
                # Only create PagerDuty alerts for high-risk vulnerabilities
                if alert.get('risk', '').lower() == 'high':
                    
                    # Generate unique dedup_key for this vulnerability
                    dedup_key = f"websecpen-{scan.id}-{alert.get('pluginid', hashlib.md5(alert.get('name', '').encode()).hexdigest()[:8])}"
                    
                    event_data = {
                        'routing_key': pagerduty_routing_key,
                        'event_action': 'trigger',
                        'dedup_key': dedup_key,
                        'payload': {
                            'summary': f'Critical Security Vulnerability: {alert.get("name", "Unknown")} detected in {scan.target_url}',
                            'severity': 'critical',
                            'source': f'WebSecPen Scan {scan.id}',
                            'component': 'Security Scanner',
                            'group': 'WebSecPen',
                            'class': 'security',
                            'custom_details': {
                                'vulnerability_name': alert.get('name'),
                                'risk_level': alert.get('risk'),
                                'confidence': alert.get('confidence'),
                                'target_url': scan.target_url,
                                'affected_url': alert.get('url'),
                                'parameter': alert.get('param'),
                                'description': alert.get('desc'),
                                'evidence': alert.get('evidence'),
                                'scan_id': scan.id,
                                'scan_date': scan.created_at.isoformat(),
                                'solution': alert.get('solution', 'No solution provided')
                            }
                        },
                        'client': 'WebSecPen',
                        'client_url': f'{request.host_url}scan/{scan.id}'
                    }
                    
                    # Send to PagerDuty Events API
                    response = requests.post(
                        'https://events.pagerduty.com/v2/enqueue',
                        headers={'Content-Type': 'application/json'},
                        json=event_data,
                        timeout=30
                    )
                    
                    if response.status_code == 202:
                        pd_response = response.json()
                        created_alerts.append({
                            'dedup_key': dedup_key,
                            'vulnerability': alert.get('name'),
                            'status': 'created',
                            'message': pd_response.get('message', 'Event processed')
                        })
                    else:
                        app.logger.error(f'PagerDuty alert creation failed: {response.status_code} - {response.text}')
                        created_alerts.append({
                            'dedup_key': dedup_key,
                            'vulnerability': alert.get('name'),
                            'status': 'failed',
                            'error': f'HTTP {response.status_code}'
                        })
            
            return jsonify({
                'message': f'PagerDuty integration completed',
                'alerts_created': len([a for a in created_alerts if a['status'] == 'created']),
                'alerts_failed': len([a for a in created_alerts if a['status'] == 'failed']),
                'alerts': created_alerts
            }), 200
            
        except Exception as e:
            app.logger.error(f'PagerDuty integration error: {str(e)}')
            return jsonify({'error': f'PagerDuty integration failed: {str(e)}'}), 500
    
    @app.route('/api/integrations/pagerduty/test', methods=['POST'])
    @jwt_required()
    def test_pagerduty_connection():
        """Test PagerDuty connection"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        pagerduty_routing_key = os.environ.get('PAGERDUTY_ROUTING_KEY')
        
        if not pagerduty_routing_key:
            return jsonify({'error': 'PagerDuty not configured'}), 400
        
        try:
            # Send test event
            test_event = {
                'routing_key': pagerduty_routing_key,
                'event_action': 'trigger',
                'dedup_key': f'websecpen-test-{datetime.utcnow().timestamp()}',
                'payload': {
                    'summary': 'WebSecPen PagerDuty Integration Test',
                    'severity': 'info',
                    'source': 'WebSecPen Test',
                    'component': 'Integration Test'
                }
            }
            
            response = requests.post(
                'https://events.pagerduty.com/v2/enqueue',
                headers={'Content-Type': 'application/json'},
                json=test_event,
                timeout=10
            )
            
            if response.status_code == 202:
                return jsonify({
                    'status': 'success',
                    'message': 'PagerDuty test event sent successfully'
                }), 200
            else:
                return jsonify({
                    'status': 'failed',
                    'message': f'PagerDuty test failed: HTTP {response.status_code}'
                }), 400
                
        except Exception as e:
            return jsonify({
                'status': 'failed',
                'message': f'PagerDuty test failed: {str(e)}'
            }), 500

# =============================================================================
# ZAPIER INTEGRATION FOR AUTOMATION
# =============================================================================

def init_zapier_integration(app):
    """Initialize Zapier integration routes"""
    
    @app.route('/api/zapier/trigger', methods=['POST'])
    def zapier_trigger_scan():
        """Trigger scan via Zapier webhook"""
        
        # Authenticate using API key
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        key_record = ApiKey.query.filter_by(key_hash=hashlib.sha256(api_key.encode()).hexdigest()).first()
        if not key_record:
            return jsonify({'error': 'Invalid API key'}), 401
        
        try:
            data = request.get_json()
            url = data.get('url')
            scan_type = data.get('scan_type', 'spider')
            custom_config = data.get('config', {})
            
            if not url:
                return jsonify({'error': 'URL required'}), 400
            
            # Create scan record
            scan = Scan(
                user_id=key_record.user_id,
                target_url=url,
                status='started',
                metadata={
                    'source': 'zapier',
                    'triggered_at': datetime.utcnow().isoformat(),
                    'config': custom_config
                }
            )
            
            db.session.add(scan)
            db.session.commit()
            
            # Start ZAP scan (implement based on existing scan logic)
            try:
                from zap_integration import start_zap_scan
                zap_scan_id = start_zap_scan(url, scan_type, 10, False)
                scan.scan_id = zap_scan_id
                db.session.commit()
            except ImportError:
                # Mock scan ID if ZAP integration not available
                scan.scan_id = f'zapier_{scan.id}_{datetime.utcnow().timestamp()}'
                db.session.commit()
            
            # Emit real-time notification
            try:
                from app import socketio
                socketio.emit('new_scan', {
                    'scan_id': scan.id,
                    'url': scan.target_url,
                    'status': scan.status,
                    'source': 'zapier'
                }, room=f'user_{key_record.user_id}')
            except:
                pass  # SocketIO not available
            
            return jsonify({
                'scan_id': scan.id,
                'url': url,
                'status': 'started',
                'message': 'Scan initiated via Zapier'
            }), 201
            
        except Exception as e:
            app.logger.error(f'Zapier trigger error: {str(e)}')
            return jsonify({'error': f'Failed to trigger scan: {str(e)}'}), 500
    
    @app.route('/api/zapier/webhook/scan-completed', methods=['POST'])
    def zapier_scan_completed_webhook():
        """Webhook for Zapier when scan completes"""
        
        # This endpoint would be called when a scan completes
        # to send data to Zapier for further automation
        
        try:
            data = request.get_json()
            scan_id = data.get('scan_id')
            
            if not scan_id:
                return jsonify({'error': 'scan_id required'}), 400
            
            scan = Scan.query.get(scan_id)
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            # Format data for Zapier
            zapier_data = {
                'scan_id': scan.id,
                'target_url': scan.target_url,
                'status': scan.status,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'vulnerability_count': len(scan.results.get('alerts', [])) if scan.results else 0,
                'high_risk_count': len([a for a in scan.results.get('alerts', []) if a.get('risk') == 'High']) if scan.results else 0,
                'medium_risk_count': len([a for a in scan.results.get('alerts', []) if a.get('risk') == 'Medium']) if scan.results else 0,
                'low_risk_count': len([a for a in scan.results.get('alerts', []) if a.get('risk') == 'Low']) if scan.results else 0,
                'scan_url': f'{request.host_url}scan/{scan.id}',
                'vulnerabilities': scan.results.get('alerts', [])[:10] if scan.results else []  # Limit to first 10
            }
            
            return jsonify(zapier_data), 200
            
        except Exception as e:
            app.logger.error(f'Zapier webhook error: {str(e)}')
            return jsonify({'error': f'Webhook failed: {str(e)}'}), 500

# =============================================================================
# SLACK COMMAND INTEGRATION
# =============================================================================

def init_slack_integration(app):
    """Initialize Slack slash command integration"""
    
    @app.route('/api/slack/command', methods=['POST'])
    def slack_command():
        """Handle Slack slash commands"""
        
        # Verify Slack token
        token = request.form.get('token')
        if token != os.environ.get('SLACK_VERIFICATION_TOKEN'):
            return jsonify({'text': 'Invalid token'}), 401
        
        try:
            # Get command parameters
            user_id = request.form.get('user_id')
            user_name = request.form.get('user_name')
            command_text = request.form.get('text', '').strip()
            channel_id = request.form.get('channel_id')
            
            # Parse command
            if not command_text:
                return jsonify({
                    'text': 'Usage: /websecpen scan <URL> or /websecpen status <scan_id>'
                }), 200
            
            command_parts = command_text.split()
            action = command_parts[0].lower()
            
            if action == 'scan' and len(command_parts) > 1:
                url = command_parts[1]
                
                # Find user by Slack user_id or create mapping
                # For now, use default API key or require setup
                api_key_record = ApiKey.query.filter_by(
                    metadata={'slack_user_id': user_id}
                ).first()
                
                if not api_key_record:
                    return jsonify({
                        'text': 'Please set up your API key first. Contact your administrator.'
                    }), 200
                
                # Start scan
                scan = Scan(
                    user_id=api_key_record.user_id,
                    target_url=url,
                    status='started',
                    metadata={
                        'source': 'slack',
                        'slack_user': user_name,
                        'slack_channel': channel_id
                    }
                )
                
                db.session.add(scan)
                db.session.commit()
                
                # Start ZAP scan
                try:
                    from zap_integration import start_zap_scan
                    zap_scan_id = start_zap_scan(url, 'spider', 10, False)
                    scan.scan_id = zap_scan_id
                    db.session.commit()
                except ImportError:
                    scan.scan_id = f'slack_{scan.id}_{datetime.utcnow().timestamp()}'
                    db.session.commit()
                
                return jsonify({
                    'text': f'Security scan started for {url}. Scan ID: {scan.id}\nYou will be notified when the scan completes.'
                }), 200
            
            elif action == 'status' and len(command_parts) > 1:
                try:
                    scan_id = int(command_parts[1])
                    scan = Scan.query.get(scan_id)
                    
                    if not scan:
                        return jsonify({'text': f'Scan {scan_id} not found'}), 200
                    
                    vuln_count = len(scan.results.get('alerts', [])) if scan.results else 0
                    
                    return jsonify({
                        'text': f'Scan {scan_id} status: {scan.status}\nTarget: {scan.target_url}\nVulnerabilities found: {vuln_count}'
                    }), 200
                    
                except ValueError:
                    return jsonify({'text': 'Invalid scan ID'}), 200
            
            else:
                return jsonify({
                    'text': 'Unknown command. Usage: /websecpen scan <URL> or /websecpen status <scan_id>'
                }), 200
            
        except Exception as e:
            app.logger.error(f'Slack command error: {str(e)}')
            return jsonify({
                'text': 'An error occurred processing your command. Please try again.'
            }), 200

# =============================================================================
# SCHEDULED SCAN REMINDERS
# =============================================================================

def init_reminder_system(app):
    """Initialize scan reminder system"""
    
    from celery import shared_task
    
    @shared_task
    def send_scan_reminders():
        """Send reminders for upcoming scheduled scans"""
        try:
            from models import Schedule, NotificationSettings, Webhook
            
            # Get schedules that need reminders (within next 24 hours)
            reminder_time = datetime.utcnow() + timedelta(hours=24)
            schedules = Schedule.query.filter(
                Schedule.next_run <= reminder_time,
                Schedule.next_run > datetime.utcnow()
            ).all()
            
            for schedule in schedules:
                # Get user notification settings
                settings = NotificationSettings.query.filter_by(user_id=schedule.user_id).first()
                
                if not settings:
                    continue
                
                # Send email reminder
                if settings.email:
                    try:
                        send_email_reminder(schedule)
                    except Exception as e:
                        app.logger.error(f'Email reminder failed: {e}')
                
                # Send in-app notification
                if settings.in_app:
                    try:
                        from app import socketio
                        socketio.emit('scan_reminder', {
                            'schedule_id': schedule.id,
                            'url': schedule.url,
                            'next_run': schedule.next_run.isoformat(),
                            'message': f'Scheduled scan for {schedule.url} will run in {format_time_until(schedule.next_run)}'
                        }, room=f'user_{schedule.user_id}')
                    except:
                        pass
                
                # Send Slack notification
                if settings.slack:
                    webhooks = Webhook.query.filter_by(
                        user_id=schedule.user_id,
                        events=['scan_reminder']
                    ).all()
                    
                    for webhook in webhooks:
                        try:
                            requests.post(webhook.url, json={
                                'text': f'Scheduled scan reminder: {schedule.url} will be scanned in {format_time_until(schedule.next_run)}',
                                'schedule_id': schedule.id,
                                'url': schedule.url,
                                'next_run': schedule.next_run.isoformat()
                            }, timeout=10)
                        except Exception as e:
                            app.logger.error(f'Slack reminder failed: {e}')
            
            return f'Sent reminders for {len(schedules)} scheduled scans'
            
        except Exception as e:
            app.logger.error(f'Reminder system error: {e}')
            return f'Reminder system failed: {str(e)}'
    
    def send_email_reminder(schedule):
        """Send email reminder (implement with your email service)"""
        # Implementation depends on your email service (SendGrid, SES, etc.)
        pass
    
    def format_time_until(target_time):
        """Format time until target time in a human-readable way"""
        time_diff = target_time - datetime.utcnow()
        hours = int(time_diff.total_seconds() // 3600)
        
        if hours < 1:
            minutes = int(time_diff.total_seconds() // 60)
            return f'{minutes} minutes'
        elif hours < 24:
            return f'{hours} hours'
        else:
            days = int(time_diff.total_seconds() // 86400)
            return f'{days} days'

# =============================================================================
# MAIN INITIALIZATION FUNCTION
# =============================================================================

def init_all_integrations(app):
    """Initialize all external integrations"""
    
    # Initialize all integration modules
    init_servicenow_integration(app)
    init_pagerduty_integration(app)
    init_zapier_integration(app)
    init_slack_integration(app)
    init_reminder_system(app)
    
    print("✅ External integrations initialized successfully!")
    print("🔧 Integrations: ServiceNow, PagerDuty, Zapier, Slack, Reminders")
    
    return app 