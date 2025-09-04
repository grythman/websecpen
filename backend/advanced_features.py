# advanced_features.py - Advanced features for WebSecPen
import os
import csv
import json
import subprocess
from io import StringIO
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from transformers import pipeline
from pyfcm import FCMNotification
from models import db, User, Scan, Feedback

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

def send_push_notification(user, title, body, data=None):
    """Send push notification to user"""
    if not fcm_service or not user.fcm_token:
        return False
    
    try:
        result = fcm_service.notify_single_device(
            registration_id=user.fcm_token,
            message_title=title,
            message_body=body,
            data_message=data or {}
        )
        return result.get('success', 0) > 0
    except Exception as e:
        print(f"Push notification error: {e}")
        return False

def analyze_sentiment(text):
    """Analyze sentiment of text"""
    if not sentiment_analyzer:
        return {'label': 'UNKNOWN', 'score': 0.0}
    
    try:
        result = sentiment_analyzer(text[:512])  # Limit text length
        return result[0] if isinstance(result, list) else result
    except Exception as e:
        print(f"Sentiment analysis error: {e}")
        return {'label': 'ERROR', 'score': 0.0}

def run_snyk_scan(project_path):
    """Run Snyk scan on project"""
    try:
        # Run Snyk test command
        result = subprocess.run(
            ['snyk', 'test', '--json', '--file', f'{project_path}/package.json'],
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        if result.returncode == 0:
            return {'success': True, 'vulnerabilities': []}
        else:
            # Parse JSON output even on non-zero exit (Snyk returns 1 when vulns found)
            try:
                snyk_data = json.loads(result.stdout)
                return {
                    'success': True,
                    'vulnerabilities': snyk_data.get('vulnerabilities', []),
                    'summary': snyk_data.get('summary', {}),
                    'raw_output': result.stdout
                }
            except json.JSONDecodeError:
                return {
                    'success': False,
                    'error': 'Failed to parse Snyk output',
                    'raw_output': result.stdout
                }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Snyk scan timeout'}
    except FileNotFoundError:
        return {'success': False, 'error': 'Snyk CLI not found'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def init_advanced_routes(app):
    """Initialize advanced feature routes"""
    
    # Initialize services when routes are registered
    init_services()
    
    # FEATURE 1: PUSH NOTIFICATIONS
    @app.route('/api/notifications/register', methods=['POST'])
    @jwt_required()
    def register_notification_token():
        """Register FCM token for push notifications"""
        user_id = get_jwt_identity()
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'error': 'Token is required'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.fcm_token = token
        db.session.commit()
        
        # Send test notification
        if fcm_service:
            send_push_notification(
                user,
                'Notifications Enabled',
                'You will now receive scan completion notifications!'
            )
        
        return jsonify({'message': 'Token registered successfully'}), 200
    
    @app.route('/api/notifications/unregister', methods=['POST'])
    @jwt_required()
    def unregister_notification_token():
        """Unregister FCM token"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user:
            user.fcm_token = None
            db.session.commit()
        
        return jsonify({'message': 'Notifications disabled'}), 200
    
    @app.route('/api/notifications/test', methods=['POST'])
    @jwt_required()
    def test_notification():
        """Send test notification"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        success = send_push_notification(
            user,
            'Test Notification',
            'This is a test notification from WebSecPen!'
        )
        
        return jsonify({
            'message': 'Test notification sent' if success else 'Failed to send notification',
            'success': success
        }), 200 if success else 400
    
    # FEATURE 2: EXPORTABLE TREND REPORTS
    @app.route('/api/scan/trends/export', methods=['GET'])
    @jwt_required()
    def export_trends():
        """Export vulnerability trends as CSV"""
        user_id = get_jwt_identity()
        days = request.args.get('days', 30, type=int)
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        scans = Scan.query.filter(
            Scan.user_id == user_id,
            Scan.created_at >= start_date,
            Scan.status == 'completed'
        ).all()
        
        # Generate CSV data
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Date', 'Vulnerability Type', 'Severity', 'Count', 'Scan URL'])
        
        trends = defaultdict(lambda: defaultdict(int))
        
        for scan in scans:
            date = scan.created_at.strftime('%Y-%m-%d')
            if scan.results:
                for vuln in scan.results:
                    vuln_type = vuln.get('type', 'Unknown')
                    severity = vuln.get('severity', 'Unknown')
                    key = f"{vuln_type}_{severity}"
                    trends[date][key] += 1
        
        # Write data rows
        for date in sorted(trends.keys()):
            for vuln_key, count in trends[date].items():
                vuln_type, severity = vuln_key.split('_', 1)
                # Find a scan for this date to get URL
                scan_url = next(
                    (s.target_url for s in scans if s.created_at.strftime('%Y-%m-%d') == date),
                    'N/A'
                )
                writer.writerow([date, vuln_type, severity, count, scan_url])
        
        # Create response
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment;filename=vulnerability_trends_{days}days.csv'
            }
        )
    
    @app.route('/api/scan/trends/export/json', methods=['GET'])
    @jwt_required()
    def export_trends_json():
        """Export vulnerability trends as JSON"""
        user_id = get_jwt_identity()
        days = request.args.get('days', 30, type=int)
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        scans = Scan.query.filter(
            Scan.user_id == user_id,
            Scan.created_at >= start_date,
            Scan.status == 'completed'
        ).all()
        
        # Prepare export data
        export_data = {
            'export_date': datetime.utcnow().isoformat(),
            'period': f'{days} days',
            'total_scans': len(scans),
            'scans': []
        }
        
        for scan in scans:
            scan_data = {
                'id': scan.id,
                'url': scan.target_url,
                'date': scan.created_at.isoformat(),
                'vulnerabilities': scan.results or [],
                'summary': {
                    'total': scan.vulnerabilities_count,
                    'high': scan.high_severity_count,
                    'medium': scan.medium_severity_count,
                    'low': scan.low_severity_count
                }
            }
            export_data['scans'].append(scan_data)
        
        return Response(
            json.dumps(export_data, indent=2),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment;filename=vulnerability_trends_{days}days.json'
            }
        )
    
    # FEATURE 3: SNYK INTEGRATION
    @app.route('/api/scan/snyk', methods=['POST'])
    @jwt_required()
    def start_snyk_scan():
        """Start Snyk dependency scan"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        project_path = data.get('project_path', './frontend')
        
        # Run Snyk scan
        result = run_snyk_scan(project_path)
        
        # Store results in a file for later retrieval
        if result['success']:
            with open('snyk-report.json', 'w') as f:
                json.dump(result, f, indent=2)
        
        return jsonify(result), 200 if result['success'] else 400
    
    @app.route('/api/admin/snyk-results', methods=['GET'])
    @jwt_required()
    def get_snyk_results():
        """Get latest Snyk scan results"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            with open('snyk-report.json', 'r') as f:
                results = json.load(f)
            return jsonify(results), 200
        except FileNotFoundError:
            return jsonify({
                'vulnerabilities': [],
                'summary': {'total': 0},
                'message': 'No Snyk scan results available'
            }), 200
        except Exception as e:
            return jsonify({'error': f'Failed to read Snyk results: {str(e)}'}), 500
    
    # FEATURE 4: FEEDBACK SENTIMENT ANALYSIS
    @app.route('/api/admin/feedback/analyze', methods=['GET'])
    @jwt_required()
    def analyze_feedback():
        """Analyze feedback sentiment"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        # Get all feedback
        feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).limit(100).all()
        
        analysis = []
        sentiment_summary = {'POSITIVE': 0, 'NEGATIVE': 0, 'NEUTRAL': 0}
        
        for feedback in feedbacks:
            sentiment = analyze_sentiment(feedback.feedback)
            
            # Normalize label names
            label = sentiment.get('label', 'UNKNOWN').upper()
            if 'POS' in label:
                label = 'POSITIVE'
            elif 'NEG' in label:
                label = 'NEGATIVE'
            else:
                label = 'NEUTRAL'
            
            sentiment_summary[label] = sentiment_summary.get(label, 0) + 1
            
            analysis.append({
                'id': feedback.id,
                'feedback': feedback.feedback[:200],  # Truncate for display
                'type': feedback.type,
                'created_at': feedback.created_at.isoformat(),
                'sentiment': {
                    'label': label,
                    'score': sentiment.get('score', 0.0),
                    'confidence': sentiment.get('score', 0.0)
                }
            })
        
        return jsonify({
            'analysis': analysis,
            'summary': sentiment_summary,
            'total_feedback': len(analysis)
        }), 200
    
    @app.route('/api/admin/feedback/summary', methods=['GET'])
    @jwt_required()
    def feedback_summary():
        """Get feedback summary statistics"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        # Get feedback counts by type and time period
        total_feedback = Feedback.query.count()
        recent_feedback = Feedback.query.filter(
            Feedback.created_at >= datetime.utcnow() - timedelta(days=30)
        ).count()
        
        # Group by type
        type_counts = db.session.query(
            Feedback.type,
            db.func.count(Feedback.id)
        ).group_by(Feedback.type).all()
        
        return jsonify({
            'total_feedback': total_feedback,
            'recent_feedback': recent_feedback,
            'by_type': {type_name: count for type_name, count in type_counts}
        }), 200
    
    # Enhanced scan result endpoint with notifications
    def enhance_scan_result_endpoint(original_func):
        """Decorator to enhance scan result endpoint with notifications"""
        def wrapper(scan_id):
            # Get original response
            response = original_func(scan_id)
            
            # If scan is completed, send push notification
            if isinstance(response, tuple) and len(response) == 2:
                data, status_code = response
                if status_code == 200 and isinstance(data.get_json(), dict):
                    scan_data = data.get_json()
                    if scan_data.get('status') == 'completed':
                        # Get user and send notification
                        user_id = get_jwt_identity()
                        user = User.query.get(user_id)
                        
                        if user and user.fcm_token:
                            vuln_count = scan_data.get('vulnerabilities_count', 0)
                            send_push_notification(
                                user,
                                'Scan Completed!',
                                f'Found {vuln_count} vulnerabilities in {scan_data.get("target_url", "your scan")}',
                                {'scan_id': str(scan_id), 'type': 'scan_completed'}
                            )
            
            return response
        return wrapper
    
    return {
        'send_push_notification': send_push_notification,
        'analyze_sentiment': analyze_sentiment,
        'run_snyk_scan': run_snyk_scan,
        'enhance_scan_result_endpoint': enhance_scan_result_endpoint
    } 