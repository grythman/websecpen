# aug19_enhancements.py - Enhanced Features for WebSecPen (Aug 19, 2025)
# Scan Diffing, GitHub Integration, Vulnerability Retesting, and Enhanced Analytics

import os
import json
import hmac
import hashlib
import secrets
import requests
from datetime import datetime, timedelta
from collections import defaultdict
from difflib import unified_diff
from functools import wraps
from flask import Flask, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
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
# 1. SCAN RESULT DIFFING
# =============================================================================

def init_scan_diffing_routes(app):
    """Initialize scan result diffing routes"""
    
    @app.route('/api/scan/<int:scan_id>/diff', methods=['GET'])
    @jwt_required()
    def get_scan_diff(scan_id):
        """Compare scan results with previous scan of the same URL"""
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
        
        try:
            # Find previous scan for the same URL
            previous_scan = Scan.query.filter(
                Scan.target_url == scan.target_url,
                Scan.id < scan_id,
                Scan.status == 'completed',
                db.or_(
                    Scan.user_id == user_id,
                    Scan.team_id.in_(
                        db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                    )
                )
            ).order_by(Scan.created_at.desc()).first()
            
            if not previous_scan:
                return jsonify({
                    'diff': [],
                    'message': 'No previous scan found for comparison',
                    'comparison_available': False
                }), 200
            
            # Normalize results for comparison
            current_results = scan.results or {}
            prev_results = previous_scan.results or {}
            
            # Convert to JSON strings for diffing
            current_json = json.dumps(current_results, sort_keys=True, indent=2)
            prev_json = json.dumps(prev_results, sort_keys=True, indent=2)
            
            # Generate unified diff
            diff = list(unified_diff(
                prev_json.splitlines(keepends=True),
                current_json.splitlines(keepends=True),
                fromfile=f'Previous Scan (ID: {previous_scan.id})',
                tofile=f'Current Scan (ID: {scan_id})',
                lineterm=''
            ))
            
            # Analyze changes
            changes_summary = analyze_vulnerability_changes(prev_results, current_results)
            
            return jsonify({
                'diff': diff,
                'previous_scan_id': previous_scan.id,
                'previous_scan_date': previous_scan.created_at.isoformat(),
                'current_scan_date': scan.created_at.isoformat(),
                'comparison_available': True,
                'changes_summary': changes_summary
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to generate diff: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/diff/summary', methods=['GET'])
    @jwt_required()
    def get_scan_diff_summary(scan_id):
        """Get a summary of changes between scans"""
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
        
        try:
            # Get scan history for the URL
            scan_history = Scan.query.filter(
                Scan.target_url == scan.target_url,
                Scan.status == 'completed',
                db.or_(
                    Scan.user_id == user_id,
                    Scan.team_id.in_(
                        db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                    )
                )
            ).order_by(Scan.created_at.desc()).limit(10).all()
            
            trend_data = []
            for i, scan_item in enumerate(scan_history):
                alerts = scan_item.results.get('alerts', []) if scan_item.results else []
                severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
                
                for alert in alerts:
                    risk = alert.get('risk', 'Informational')
                    if risk in severity_counts:
                        severity_counts[risk] += 1
                
                trend_data.append({
                    'scan_id': scan_item.id,
                    'scan_date': scan_item.created_at.isoformat(),
                    'total_vulnerabilities': len(alerts),
                    'severity_breakdown': severity_counts
                })
            
            return jsonify({
                'url': scan.target_url,
                'scan_history_count': len(scan_history),
                'trend_data': trend_data,
                'latest_scan_id': scan_id
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get diff summary: {str(e)}'}), 500

def analyze_vulnerability_changes(prev_results, current_results):
    """Analyze changes between two scan results"""
    prev_alerts = prev_results.get('alerts', []) if prev_results else []
    current_alerts = current_results.get('alerts', []) if current_results else []
    
    # Create vulnerability signatures for comparison
    prev_signatures = set()
    current_signatures = set()
    
    for alert in prev_alerts:
        signature = f"{alert.get('name', '')}_{alert.get('url', '')}_{alert.get('param', '')}"
        prev_signatures.add(signature)
    
    for alert in current_alerts:
        signature = f"{alert.get('name', '')}_{alert.get('url', '')}_{alert.get('param', '')}"
        current_signatures.add(signature)
    
    # Calculate changes
    new_vulnerabilities = len(current_signatures - prev_signatures)
    fixed_vulnerabilities = len(prev_signatures - current_signatures)
    persistent_vulnerabilities = len(prev_signatures & current_signatures)
    
    return {
        'new_vulnerabilities': new_vulnerabilities,
        'fixed_vulnerabilities': fixed_vulnerabilities,
        'persistent_vulnerabilities': persistent_vulnerabilities,
        'total_previous': len(prev_signatures),
        'total_current': len(current_signatures),
        'change_percentage': round(((len(current_signatures) - len(prev_signatures)) / max(len(prev_signatures), 1)) * 100, 1)
    }

# =============================================================================
# 2. GITHUB INTEGRATION FOR CI/CD
# =============================================================================

def init_github_integration_routes(app):
    """Initialize GitHub integration routes"""
    
    @app.route('/api/webhook/github', methods=['POST'])
    def github_webhook():
        """Handle GitHub webhook events"""
        try:
            # Verify GitHub signature
            signature = request.headers.get('X-Hub-Signature-256')
            if not signature:
                return jsonify({'error': 'Missing signature'}), 401
            
            secret = os.environ.get('GITHUB_WEBHOOK_SECRET', '').encode()
            if not secret:
                return jsonify({'error': 'Webhook secret not configured'}), 500
            
            digest = 'sha256=' + hmac.new(secret, request.data, hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(signature, digest):
                return jsonify({'error': 'Invalid signature'}), 401
            
            payload = request.get_json()
            event_type = request.headers.get('X-GitHub-Event')
            
            if event_type == 'push':
                return handle_push_event(payload)
            elif event_type == 'pull_request':
                return handle_pull_request_event(payload)
            else:
                return jsonify({'message': f'Event {event_type} ignored'}), 200
                
        except Exception as e:
            print(f"GitHub webhook error: {e}")
            return jsonify({'error': 'Webhook processing failed'}), 500
    
    def handle_push_event(payload):
        """Handle GitHub push events"""
        try:
            repo = payload['repository']['full_name']
            commit = payload['after']
            branch = payload['ref'].split('/')[-1]
            
            # Only process main/master branch pushes
            if branch not in ['main', 'master']:
                return jsonify({'message': 'Branch ignored'}), 200
            
            # Extract repository URL for scanning
            repo_url = payload['repository']['html_url']
            
            # TODO: This would need to be mapped to a deployed URL
            # For now, we'll use a placeholder or configuration
            scan_url = os.environ.get(f'GITHUB_SCAN_URL_{repo.replace("/", "_")}', repo_url)
            
            # Create scan with GitHub context
            github_token = os.environ.get('GITHUB_TOKEN')
            if not github_token:
                return jsonify({'error': 'GitHub token not configured'}), 500
            
            # Start automated scan
            from zap_integration import start_zap_scan
            scan_id = start_zap_scan(scan_url, 'spider', 10, False)
            
            # Create scan record with GitHub metadata
            scan = Scan(
                user_id=1,  # System user for automated scans
                target_url=scan_url,
                scan_id=scan_id,
                status='started',
                metadata={
                    'github_repo': repo,
                    'github_commit': commit,
                    'github_branch': branch,
                    'github_event': 'push',
                    'automated': True
                }
            )
            db.session.add(scan)
            db.session.commit()
            
            # Post comment to commit
            comment_url = f'https://api.github.com/repos/{repo}/commits/{commit}/comments'
            comment_body = f"""🔍 **Security Scan Initiated**
            
Scan ID: `{scan.id}`
Target URL: `{scan_url}`
Status: Started

The security scan will be completed shortly. Results will be posted when available.

---
*Powered by WebSecPen*"""
            
            requests.post(
                comment_url,
                headers={
                    'Authorization': f'Bearer {github_token}',
                    'Accept': 'application/vnd.github.v3+json'
                },
                json={'body': comment_body},
                timeout=10
            )
            
            return jsonify({
                'message': 'Scan initiated',
                'scan_id': scan.id,
                'repository': repo,
                'commit': commit
            }), 200
            
        except Exception as e:
            print(f"Push event error: {e}")
            return jsonify({'error': 'Failed to process push event'}), 500
    
    def handle_pull_request_event(payload):
        """Handle GitHub pull request events"""
        try:
            if payload['action'] not in ['opened', 'synchronize']:
                return jsonify({'message': 'PR action ignored'}), 200
            
            repo = payload['repository']['full_name']
            pr_number = payload['pull_request']['number']
            
            # Get PR URL for scanning (would need deployment mapping)
            pr_url = os.environ.get(f'GITHUB_PR_URL_{repo.replace("/", "_")}', 
                                  payload['pull_request']['html_url'])
            
            # Start scan
            from zap_integration import start_zap_scan
            scan_id = start_zap_scan(pr_url, 'spider', 5, False)  # Lighter scan for PRs
            
            scan = Scan(
                user_id=1,
                target_url=pr_url,
                scan_id=scan_id,
                status='started',
                metadata={
                    'github_repo': repo,
                    'github_pr': pr_number,
                    'github_event': 'pull_request',
                    'automated': True
                }
            )
            db.session.add(scan)
            db.session.commit()
            
            return jsonify({
                'message': 'PR scan initiated',
                'scan_id': scan.id,
                'repository': repo,
                'pr_number': pr_number
            }), 200
            
        except Exception as e:
            print(f"PR event error: {e}")
            return jsonify({'error': 'Failed to process PR event'}), 500
    
    @app.route('/api/webhook/github/config', methods=['GET'])
    @jwt_required()
    def get_github_webhook_config():
        """Get GitHub webhook configuration"""
        return jsonify({
            'webhook_url': f'{request.host_url}api/webhook/github',
            'events': ['push', 'pull_request'],
            'content_type': 'application/json',
            'secret_required': True,
            'setup_instructions': {
                'step1': 'Go to your GitHub repository settings',
                'step2': 'Navigate to Webhooks section',
                'step3': f'Add webhook URL: {request.host_url}api/webhook/github',
                'step4': 'Select "application/json" content type',
                'step5': 'Add your webhook secret to environment variables',
                'step6': 'Select "Push events" and "Pull request events"'
            }
        }), 200

# =============================================================================
# 3. AUTOMATED VULNERABILITY RETESTING
# =============================================================================

def init_vulnerability_retesting_routes(app):
    """Initialize vulnerability retesting routes"""
    
    @app.route('/api/scan/<int:scan_id>/retest/<vuln_id>', methods=['POST'])
    @jwt_required()
    def retest_vulnerability(scan_id, vuln_id):
        """Retest a specific vulnerability to verify if it's fixed"""
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
            return jsonify({'error': 'Original scan not completed'}), 400
        
        try:
            # Find the specific vulnerability
            alerts = scan.results.get('alerts', []) if scan.results else []
            target_vuln = None
            
            for alert in alerts:
                if alert.get('pluginid') == vuln_id or str(alert.get('id', '')) == vuln_id:
                    target_vuln = alert
                    break
            
            if not target_vuln:
                return jsonify({'error': 'Vulnerability not found in scan results'}), 404
            
            # Create retest scan with specific vulnerability focus
            retest_scan = Scan(
                user_id=user_id,
                team_id=scan.team_id,
                target_url=scan.target_url,
                status='started',
                metadata={
                    'parent_scan_id': scan_id,
                    'retest_vulnerability': vuln_id,
                    'retest_type': 'vulnerability_verification',
                    'original_vulnerability': {
                        'name': target_vuln.get('name'),
                        'risk': target_vuln.get('risk'),
                        'url': target_vuln.get('url'),
                        'param': target_vuln.get('param')
                    }
                }
            )
            
            db.session.add(retest_scan)
            db.session.commit()
            
            # Start focused scan using ZAP
            from zap_integration import start_focused_retest
            zap_scan_id = start_focused_retest(
                target_url=scan.target_url,
                vulnerability_data=target_vuln,
                scan_record_id=retest_scan.id
            )
            
            retest_scan.scan_id = zap_scan_id
            db.session.commit()
            
            # Emit real-time notification
            try:
                from app import socketio
                socketio.emit('retest_started', {
                    'retest_scan_id': retest_scan.id,
                    'original_scan_id': scan_id,
                    'vulnerability_name': target_vuln.get('name'),
                    'target_url': scan.target_url
                }, room=f'user_{user_id}')
            except:
                pass  # SocketIO not available
            
            return jsonify({
                'message': 'Vulnerability retest initiated',
                'retest_scan_id': retest_scan.id,
                'original_scan_id': scan_id,
                'vulnerability_name': target_vuln.get('name'),
                'estimated_completion': (datetime.utcnow() + timedelta(minutes=5)).isoformat()
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to start retest: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/retest/status', methods=['GET'])
    @jwt_required()
    def get_retest_status(scan_id):
        """Get status of retests for a scan"""
        user_id = get_jwt_identity()
        
        # Get all retest scans for this parent scan
        retests = Scan.query.filter(
            Scan.metadata['parent_scan_id'].astext == str(scan_id),
            db.or_(
                Scan.user_id == user_id,
                Scan.team_id.in_(
                    db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                )
            )
        ).all()
        
        retest_status = []
        for retest in retests:
            metadata = retest.metadata or {}
            retest_status.append({
                'retest_scan_id': retest.id,
                'status': retest.status,
                'vulnerability_name': metadata.get('original_vulnerability', {}).get('name'),
                'created_at': retest.created_at.isoformat(),
                'completed_at': retest.completed_at.isoformat() if retest.completed_at else None,
                'result_summary': analyze_retest_results(retest) if retest.status == 'completed' else None
            })
        
        return jsonify({
            'original_scan_id': scan_id,
            'retest_count': len(retests),
            'retests': retest_status
        }), 200

def analyze_retest_results(retest_scan):
    """Analyze retest results to determine if vulnerability is fixed"""
    if not retest_scan.results:
        return {'status': 'unknown', 'message': 'No results available'}
    
    alerts = retest_scan.results.get('alerts', [])
    metadata = retest_scan.metadata or {}
    original_vuln = metadata.get('original_vulnerability', {})
    
    # Check if the same vulnerability type is still present
    for alert in alerts:
        if (alert.get('name') == original_vuln.get('name') and
            alert.get('url') == original_vuln.get('url')):
            return {
                'status': 'still_vulnerable',
                'message': 'Vulnerability is still present',
                'confidence': 'high'
            }
    
    # Check for similar vulnerabilities
    similar_count = 0
    for alert in alerts:
        if alert.get('name') == original_vuln.get('name'):
            similar_count += 1
    
    if similar_count > 0:
        return {
            'status': 'partially_fixed',
            'message': f'Similar vulnerabilities found ({similar_count})',
            'confidence': 'medium'
        }
    
    return {
        'status': 'likely_fixed',
        'message': 'Vulnerability not detected in retest',
        'confidence': 'high'
    }

# =============================================================================
# 4. ENHANCED VULNERABILITY ANALYTICS
# =============================================================================

def init_enhanced_analytics_routes(app):
    """Initialize enhanced vulnerability analytics routes"""
    
    @app.route('/api/analytics/vulnerability/timeline', methods=['GET'])
    @jwt_required()
    def get_vulnerability_timeline():
        """Get vulnerability discovery timeline"""
        user_id = get_jwt_identity()
        days = int(request.args.get('days', 30))
        start_date = datetime.utcnow() - timedelta(days=days)
        
        try:
            scans = Scan.query.filter(
                Scan.created_at >= start_date,
                Scan.status == 'completed',
                db.or_(
                    Scan.user_id == user_id,
                    Scan.team_id.in_(
                        db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                    )
                )
            ).order_by(Scan.created_at).all()
            
            timeline_data = defaultdict(lambda: defaultdict(int))
            vulnerability_types = set()
            
            for scan in scans:
                date_key = scan.created_at.strftime('%Y-%m-%d')
                alerts = scan.results.get('alerts', []) if scan.results else []
                
                for alert in alerts:
                    vuln_type = alert.get('name', 'Unknown')[:30]  # Truncate for readability
                    risk_level = alert.get('risk', 'Informational')
                    
                    timeline_data[date_key][f"{vuln_type}_{risk_level}"] += 1
                    vulnerability_types.add(f"{vuln_type}_{risk_level}")
            
            # Convert to chart-friendly format
            dates = sorted(timeline_data.keys())
            datasets = []
            
            for vuln_type in sorted(vulnerability_types):
                data_points = [timeline_data[date].get(vuln_type, 0) for date in dates]
                if sum(data_points) > 0:  # Only include types with data
                    datasets.append({
                        'label': vuln_type.replace('_', ' - '),
                        'data': data_points
                    })
            
            return jsonify({
                'dates': dates,
                'datasets': datasets,
                'total_scans': len(scans),
                'date_range': {
                    'start': start_date.isoformat(),
                    'end': datetime.utcnow().isoformat(),
                    'days': days
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to generate timeline: {str(e)}'}), 500
    
    @app.route('/api/analytics/vulnerability/heatmap', methods=['GET'])
    @jwt_required()
    def get_vulnerability_heatmap():
        """Get vulnerability heatmap by URL and type"""
        user_id = get_jwt_identity()
        
        try:
            scans = Scan.query.filter(
                Scan.status == 'completed',
                db.or_(
                    Scan.user_id == user_id,
                    Scan.team_id.in_(
                        db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user_id)
                    )
                )
            ).all()
            
            url_vuln_matrix = defaultdict(lambda: defaultdict(int))
            all_vuln_types = set()
            all_urls = set()
            
            for scan in scans:
                url = scan.target_url
                alerts = scan.results.get('alerts', []) if scan.results else []
                
                all_urls.add(url)
                
                for alert in alerts:
                    vuln_type = alert.get('name', 'Unknown')[:25]
                    all_vuln_types.add(vuln_type)
                    url_vuln_matrix[url][vuln_type] += 1
            
            # Convert to matrix format
            urls = sorted(all_urls)
            vuln_types = sorted(all_vuln_types)
            
            matrix_data = []
            for i, url in enumerate(urls):
                for j, vuln_type in enumerate(vuln_types):
                    count = url_vuln_matrix[url][vuln_type]
                    if count > 0:
                        matrix_data.append({
                            'x': j,
                            'y': i,
                            'v': count,
                            'url': url,
                            'vulnerability': vuln_type
                        })
            
            return jsonify({
                'urls': urls,
                'vulnerability_types': vuln_types,
                'matrix_data': matrix_data,
                'total_combinations': len(matrix_data)
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to generate heatmap: {str(e)}'}), 500

# =============================================================================
# MAIN INITIALIZATION FUNCTION
# =============================================================================

def init_aug19_enhancement_routes(app):
    """Initialize all August 19th enhancement features"""
    
    # Initialize Redis
    redis_available = init_redis()
    if not redis_available:
        print("Warning: Redis not available. Some features may not work properly.")
    
    # Initialize all feature routes
    init_scan_diffing_routes(app)
    init_github_integration_routes(app)
    init_vulnerability_retesting_routes(app)
    init_enhanced_analytics_routes(app)
    
    print("✅ August 19th Enhancement features initialized successfully!")
    print("🔧 Features: Scan Diffing, GitHub Integration, Vulnerability Retesting, Enhanced Analytics")
    
    return app 