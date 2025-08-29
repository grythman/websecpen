from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress
from datetime import datetime, timedelta
import re
import random
import os

# Monitoring and error tracking
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

# Import our models, scanner, and NLP service
from models import db, User, Scan, Vulnerability, Feedback, init_db, create_sample_data
from scanner import scan_manager
from nlp_service import analyze_scan_results

app = Flask(__name__)

# Initialize Sentry for error monitoring
sentry_dsn = os.getenv('SENTRY_DSN')
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration(transaction_style='endpoint')],
        traces_sample_rate=1.0,
        environment=os.getenv('FLASK_ENV', 'development')
    )

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///websecpen.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_CSRF_PROTECT'] = False  # Disable CSRF for API usage
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# Initialize extensions
CORS(app)
jwt = JWTManager(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)
compress = Compress(app)

# Initialize database
init_db(app)

@app.route('/')
def home():
    return {"message": "WebSecPen API - Security Scanning Platform", "version": "1.0.0"}

# Authentication endpoints
@app.route('/auth/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Create JWT token
            access_token = create_access_token(identity=user.id)
            
            return jsonify({
                'access_token': access_token,
                'user': user.to_dict(),
                'message': 'Login successful'
            }), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
            
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'User with this email already exists'}), 409
        
        # Create new user
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Create JWT token
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'access_token': access_token,
            'user': user.to_dict(),
            'message': 'User registered successfully'
        }), 201
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/auth/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get current user profile"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'user': user.to_dict()}), 200
        
    except Exception as e:
        print(f"Profile error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Scan endpoints (updated with database integration)
@app.route('/scan/start', methods=['POST'])
@jwt_required()
@limiter.limit("5 per minute")
def start_scan():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        url = data.get('url')
        scan_type = data.get('scan_type')

        # Validation
        if not url or not scan_type:
            return jsonify({'error': 'Missing url or scan_type'}), 400
            
        # URL validation
        url_pattern = r'^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&=]*)$'
        if not re.match(url_pattern, url):
            return jsonify({'error': 'Invalid URL format'}), 400
            
        # Scan type validation
        valid_scan_types = ['XSS', 'SQLi', 'CSRF', 'Directory']
        if scan_type not in valid_scan_types:
            return jsonify({'error': f'Invalid scan type. Supported types: {", ".join(valid_scan_types)}'}), 400

        # Create new scan record
        scan = Scan(
            user_id=user_id,
            target_url=url,
            scan_type=scan_type,
            status='pending',
            scan_config=data.get('config', {})
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Integrate with our security scanner (Task 16 complete!)
        def progress_callback(scan_id, results):
            """Update scan progress in database"""
            current_scan = Scan.query.get(scan_id)
            if current_scan:
                current_scan.status = results.get('status', 'running')
                current_scan.pages_scanned = results.get('pages_scanned', 0)
                current_scan.requests_made = results.get('requests_made', 0)
                
                if results.get('status') == 'completed':
                    current_scan.completed_at = datetime.utcnow()
                    current_scan.duration_seconds = int(results.get('duration', 0))
                    
                    # Process vulnerabilities
                    vulns = results.get('vulnerabilities', [])
                    current_scan.vulnerabilities_count = len(vulns)
                    
                    # Count by severity
                    current_scan.high_severity_count = len([v for v in vulns if v.get('severity') == 'High'])
                    current_scan.medium_severity_count = len([v for v in vulns if v.get('severity') == 'Medium'])
                    current_scan.low_severity_count = len([v for v in vulns if v.get('severity') == 'Low'])
                    
                    # Calculate risk score
                    current_scan.calculate_risk_score()
                    
                    # Store raw results
                    current_scan.results = results
                    
                    # Generate NLP analysis of vulnerabilities
                    nlp_analysis = analyze_scan_results(vulns)
                    current_scan.nlp_summary = nlp_analysis.get('summary', 'Analysis not available')
                    
                    # Store additional NLP insights in results
                    results['nlp_analysis'] = nlp_analysis
                    current_scan.results = results
                    
                    # Create individual vulnerability records
                    for vuln_data in vulns:
                        vulnerability = Vulnerability(
                            scan_id=scan_id,
                            name=vuln_data.get('title', 'Unknown'),
                            description=vuln_data.get('description', ''),
                            risk_level=vuln_data.get('severity', 'Low'),
                            confidence=str(vuln_data.get('confidence', 0)),
                            url=vuln_data.get('url', ''),
                            parameter=vuln_data.get('parameter', ''),
                            method=vuln_data.get('method', 'GET'),
                            attack=vuln_data.get('payload', ''),
                            evidence=vuln_data.get('evidence', ''),
                            solution=vuln_data.get('solution', '')
                        )
                        db.session.add(vulnerability)
                
                elif results.get('status') == 'failed':
                    current_scan.error_message = results.get('error', 'Scan failed')
                
                # Update progress percentage
                if results.get('requests_made', 0) > 0:
                    current_scan.progress_percentage = min(100, (results.get('requests_made', 0) * 10))
                
                db.session.commit()
        
        # Start the actual security scan
        scan.status = 'running'
        scan.started_at = datetime.utcnow()
        db.session.commit()
        
        # Start scan in background
        scan_manager.start_scan(scan.id, url, scan_type, progress_callback)
        
        print(f"Starting {scan_type} scan for {url} with ID {scan.id}")
        
        return jsonify({
            'scan_id': scan.id, 
            'status': scan.status,
            'message': f'{scan_type} scan initiated for {url}',
            'estimated_duration': '2-5 minutes'
        }), 200
        
    except Exception as e:
        print(f"Error starting scan: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/result/<scan_id>', methods=['GET'])
@jwt_required()
def get_scan_result(scan_id):
    """Get detailed scan results"""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # If scan is still running, return status
        if scan.status in ['pending', 'running']:
            return jsonify({
                'scan_id': scan.id,
                'status': scan.status,
                'progress_percentage': scan.progress_percentage,
                'message': 'Scan in progress'
            }), 200
        
        # Return full results
        result = scan.to_dict()
        
        # Include vulnerabilities if any
        if scan.vulnerabilities:
            result['vulnerabilities'] = [vuln.to_dict() for vuln in scan.vulnerabilities]
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"Error getting scan result: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/status/<scan_id>', methods=['GET'])
@jwt_required()
def get_scan_status(scan_id):
    """Get current status of a scan"""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify({
            'scan_id': scan.id,
            'status': scan.status,
            'progress_percentage': scan.progress_percentage,
            'pages_scanned': scan.pages_scanned,
            'vulnerabilities_found': scan.vulnerabilities_count,
            'duration': scan.get_duration()
        }), 200
        
    except Exception as e:
        print(f"Error getting scan status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scans', methods=['GET'])
@jwt_required()
def get_all_scans():
    """Get all scans for the current user"""
    try:
        user_id = get_jwt_identity()
        
        # Get query parameters for filtering/pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        status_filter = request.args.get('status', None)
        scan_type_filter = request.args.get('scan_type', None)
        
        # Build query
        query = Scan.query.filter_by(user_id=user_id)
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        if scan_type_filter:
            query = query.filter_by(scan_type=scan_type_filter)
        
        # Order by creation date (newest first)
        query = query.order_by(Scan.created_at.desc())
        
        # Paginate results
        scans_pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        scans_data = [scan.to_dict() for scan in scans_pagination.items]
        
        return jsonify({
            'scans': scans_data,
            'total': scans_pagination.total,
            'pages': scans_pagination.pages,
            'current_page': page,
            'per_page': per_page
        }), 200
        
    except Exception as e:
        print(f"Error getting scans: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/analyze/<scan_id>', methods=['GET'])
@jwt_required()
def get_nlp_analysis(scan_id):
    """Get detailed NLP analysis for a specific scan"""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != 'completed':
            return jsonify({'error': 'Scan not completed yet'}), 400
        
        # Get vulnerabilities for analysis
        vulnerabilities = []
        for vuln in scan.vulnerabilities:
            vulnerabilities.append(vuln.to_dict())
        
        # Generate fresh NLP analysis
        nlp_analysis = analyze_scan_results(vulnerabilities)
        
        return jsonify({
            'scan_id': scan.id,
            'target_url': scan.target_url,
            'vulnerability_count': len(vulnerabilities),
            'nlp_analysis': nlp_analysis
        }), 200
        
    except Exception as e:
        print(f"Error getting NLP analysis: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Feedback endpoints
@app.route('/feedback', methods=['POST'])
@jwt_required(optional=True)
@limiter.limit("10 per hour")
def submit_feedback():
    """Submit user feedback (anonymous or authenticated)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body required'}), 400
        
        feedback_text = data.get('feedback', '').strip()
        feedback_type = data.get('type', 'general').strip()
        
        if not feedback_text:
            return jsonify({'error': 'Feedback text is required'}), 400
        
        if len(feedback_text) > 5000:
            return jsonify({'error': 'Feedback too long (max 5000 characters)'}), 400
        
        # Validate feedback type
        valid_types = ['general', 'bug', 'feature', 'security', 'performance']
        if feedback_type not in valid_types:
            feedback_type = 'general'
        
        user_id = get_jwt_identity()
        
        feedback = Feedback(
            user_id=user_id,
            feedback=feedback_text,
            type=feedback_type,
            priority='medium',
            status='new'
        )
        
        db.session.add(feedback)
        db.session.commit()
        
        # Log feedback submission for monitoring
        print(f"Feedback submitted: ID {feedback.id}, Type: {feedback_type}, User: {user_id or 'Anonymous'}")
        
        return jsonify({
            'message': 'Feedback submitted successfully',
            'feedback_id': feedback.id
        }), 201
        
    except Exception as e:
        print(f"Error submitting feedback: {str(e)}")
        return jsonify({'error': 'Failed to submit feedback'}), 500

@app.route('/feedback', methods=['GET'])
@jwt_required()
def get_feedback():
    """Get feedback submissions (admin only)"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        # Get feedback with pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status_filter = request.args.get('status', 'all')
        type_filter = request.args.get('type', 'all')
        
        query = Feedback.query
        
        if status_filter != 'all':
            query = query.filter(Feedback.status == status_filter)
        
        if type_filter != 'all':
            query = query.filter(Feedback.type == type_filter)
        
        feedback_items = query.order_by(Feedback.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'feedback': [item.to_dict() for item in feedback_items.items],
            'total': feedback_items.total,
            'pages': feedback_items.pages,
            'current_page': page,
            'per_page': per_page
        }), 200
        
    except Exception as e:
        print(f"Error getting feedback: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/progress/<scan_id>', methods=['GET'])
@jwt_required()
@limiter.limit("30 per minute")
def scan_progress(scan_id):
    """Get real-time scan progress"""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Calculate progress based on scan status and time elapsed
        progress_data = {
            'scan_id': scan.id,
            'status': scan.status,
            'progress_percentage': 0,
            'estimated_time_remaining': None,
            'pages_scanned': scan.pages_scanned or 0,
            'requests_made': scan.requests_made or 0,
            'vulnerabilities_found': scan.vulnerabilities_count or 0,
            'started_at': scan.started_at.isoformat() if scan.started_at else None
        }
        
        if scan.status == 'completed':
            progress_data['progress_percentage'] = 100
        elif scan.status == 'running':
            # Estimate progress based on time elapsed (rough estimate)
            if scan.started_at:
                elapsed_minutes = (datetime.utcnow() - scan.started_at).total_seconds() / 60
                # Assume average scan takes 5 minutes
                estimated_progress = min(90, int(elapsed_minutes * 20))
                progress_data['progress_percentage'] = estimated_progress
                
                if estimated_progress < 90:
                    remaining_minutes = max(1, 5 - elapsed_minutes)
                    progress_data['estimated_time_remaining'] = f"{remaining_minutes:.1f} minutes"
        elif scan.status == 'failed':
            progress_data['progress_percentage'] = 0
            progress_data['error'] = 'Scan failed'
        
        return jsonify(progress_data), 200
        
    except Exception as e:
        print(f"Error getting scan progress: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        db_status = 'healthy'
    except Exception as e:
        db_status = f'error: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'service': 'WebSecPen API',
        'version': '1.0.0',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization token required'}), 401

# Global error handlers with Sentry integration
@app.errorhandler(Exception)
def handle_general_exception(e):
    """Handle all unhandled exceptions"""
    # Send to Sentry if configured
    if sentry_dsn:
        sentry_sdk.capture_exception(e)
    
    print(f"Unhandled exception: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def handle_rate_limit_exceeded(e):
    """Handle rate limit exceeded errors"""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'retry_after': getattr(e, 'retry_after', 60)
    }), 429

@app.errorhandler(400)
def handle_bad_request(e):
    """Handle bad request errors"""
    return jsonify({'error': 'Bad request', 'message': str(e)}), 400

@app.errorhandler(500)
def handle_internal_error(e):
    """Handle internal server errors"""
    if sentry_dsn:
        sentry_sdk.capture_exception(e)
    
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    with app.app_context():
        # Create sample data for testing
        create_sample_data()
    
    print("WebSecPen API starting...")
    print("Available endpoints:")
    print("- POST /auth/login - User login")
    print("- POST /auth/register - User registration")
    print("- GET /auth/profile - Get user profile")
    print("- POST /scan/start - Start new scan")
    print("- GET /scan/result/<id> - Get scan results")
    print("- GET /scan/status/<id> - Get scan status")
    print("- GET /scans - Get all user scans")
    print("- GET /health - Health check")
    print("\nDefault users:")
    print("- admin@websecpen.com / admin123 (admin)")
    print("- test@example.com / test123 (user)")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
