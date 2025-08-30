# enhanced_app.py - Enhanced WebSecPen Backend with Advanced Features
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt, verify_jwt_in_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress
from flask_socketio import SocketIO
from flask_restx import Api, Resource, fields, Namespace
from datetime import datetime, timedelta
import re
import random
import os
import uuid
import logging
import time # Added missing import for time.time()

# Monitoring and error tracking
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

# Import our models, scanner, and NLP service
from models import db, User, Scan, Vulnerability, Feedback, ApiKey, init_db, create_sample_data
from scanner import scan_manager
from nlp_service import analyze_scan_results
from monitoring import performance_monitor, alert_manager
from chat_service import initialize_chat_service

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///websecpen.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
CORS(app)
jwt = JWTManager(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)
compress = Compress(app)

# Initialize SocketIO for real-time chat
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# Initialize API documentation with Swagger
api = Api(
    app,
    title='WebSecPen API',
    version='2.0',
    description='AI-Powered Security Scanning Platform API',
    doc='/docs/',
    prefix='/api'
)

# Initialize chat service
chat_service = initialize_chat_service(socketio)

# API Namespaces
auth_ns = api.namespace('auth', description='Authentication operations')
scan_ns = api.namespace('scan', description='Security scanning operations')
admin_ns = api.namespace('admin', description='Admin operations')
monitor_ns = api.namespace('monitor', description='Monitoring and metrics')

# API Models for documentation
auth_model = api.model('Auth', {
    'email': fields.String(required=True, description='User email'),
    'password': fields.String(required=True, description='User password')
})

scan_model = api.model('Scan', {
    'url': fields.String(required=True, description='Target URL to scan'),
    'scan_type': fields.String(description='Type of scan (XSS, SQLi, comprehensive)'),
    'max_depth': fields.Integer(description='Maximum scan depth'),
    'include_sql': fields.Boolean(description='Include SQL injection tests'),
    'include_xss': fields.Boolean(description='Include XSS tests')
})

api_key_model = api.model('ApiKey', {
    'name': fields.String(required=True, description='API key name/description'),
    'permissions': fields.Raw(description='Specific permissions for the key'),
    'rate_limit': fields.Integer(description='Requests per hour limit'),
    'expires_at': fields.DateTime(description='Expiration date')
})

# ===========================
# AUTHENTICATION DECORATORS
# ===========================

def api_key_or_jwt_required(f):
    """Decorator that accepts either API key or JWT token"""
    def wrapper(*args, **kwargs):
        # Check for API key first
        api_key = request.headers.get('X-API-Key')
        if api_key:
            key_obj = ApiKey.query.filter_by(key=api_key).first()
            if key_obj and key_obj.is_valid():
                key_obj.increment_usage()
                request.current_user_id = key_obj.user_id
                request.auth_method = 'api_key'
                return f(*args, **kwargs)
            else:
                return jsonify({'error': 'Invalid or expired API key'}), 401
        
        # Fallback to JWT
        try:
            verify_jwt_in_request()
            request.current_user_id = get_jwt_identity()
            request.auth_method = 'jwt'
            return f(*args, **kwargs)
        except Exception:
            return jsonify({'error': 'Authentication required (API key or JWT token)'}), 401
    
    wrapper.__name__ = f.__name__
    return wrapper

def get_current_user_id():
    """Get current user ID from request context"""
    return getattr(request, 'current_user_id', None)

def require_role(required_role):
    """Decorator to require specific user role"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            user_id = get_current_user_id()
            if not user_id:
                return jsonify({'error': 'Authentication required'}), 401
            
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Admin can access everything
            if user.is_admin:
                return f(*args, **kwargs)
            
            # Check specific role requirements
            if required_role == 'premium' and getattr(user, 'role', 'free') not in ['premium', 'admin']:
                return jsonify({'error': 'Premium subscription required'}), 403
            elif required_role == 'admin' and not user.is_admin:
                return jsonify({'error': 'Admin access required'}), 403
            
            return f(*args, **kwargs)
        
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# ===========================
# MONITORING ENDPOINTS
# ===========================

@monitor_ns.route('/metrics')
class MetricsEndpoint(Resource):
    def get(self):
        """Get Prometheus metrics"""
        return Response(
            performance_monitor.get_prometheus_metrics(),
            mimetype='text/plain'
        )

@monitor_ns.route('/health')
class HealthEndpoint(Resource):
    def get(self):
        """Get application health status"""
        return performance_monitor.get_health_status()

@monitor_ns.route('/performance')
class PerformanceEndpoint(Resource):
    @jwt_required()
    @require_role('admin')
    def get(self):
        """Get detailed performance summary (admin only)"""
        return performance_monitor.get_performance_summary()

@monitor_ns.route('/alerts')
class AlertsEndpoint(Resource):
    @jwt_required()
    @require_role('admin')
    def get(self):
        """Get recent alerts (admin only)"""
        hours = request.args.get('hours', 24, type=int)
        alerts = alert_manager.get_recent_alerts(hours)
        current_alerts = alert_manager.check_alerts(performance_monitor)
        
        return {
            'recent_alerts': [
                {
                    **alert,
                    'timestamp': alert['timestamp'].isoformat()
                } for alert in alerts
            ],
            'current_alerts': [
                {
                    **alert,
                    'timestamp': alert['timestamp'].isoformat()
                } for alert in current_alerts
            ],
            'alert_count': len(alerts) + len(current_alerts)
        }

@monitor_ns.route('/chat/stats')
class ChatStatsEndpoint(Resource):
    @jwt_required()
    @require_role('admin')
    def get(self):
        """Get chat system statistics (admin only)"""
        return chat_service.get_chat_stats()

# ===========================
# ENHANCED AUTH ENDPOINTS
# ===========================

@auth_ns.route('/register')
class Register(Resource):
    @api.expect(auth_model)
    @performance_monitor.track_request('auth_register')
    def post(self):
        """Register a new user"""
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            name = data.get('name', '')
            
            if not email or not password:
                return {'error': 'Email and password required'}, 400
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                return {'error': 'Email already registered'}, 400
            
            # Create new user
            user = User(
                email=email,
                first_name=name.split(' ')[0] if name else '',
                last_name=name.split(' ', 1)[1] if ' ' in name else '',
                role='free',  # Default role
                scan_limit=5  # Free tier limit
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            # Send welcome email
            try:
                from email_service import email_service
                email_service.send_welcome_notification(
                    user_email=user.email,
                    user_name=name or user.email.split('@')[0]
                )
            except Exception as e:
                logger.warning(f"Failed to send welcome email: {e}")
            
            # Create access token
            access_token = create_access_token(identity=user.id)
            
            return {
                'message': 'User registered successfully',
                'access_token': access_token,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': f"{user.first_name} {user.last_name}".strip(),
                    'role': user.role,
                    'scan_limit': user.scan_limit
                }
            }, 201
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            db.session.rollback()
            return {'error': 'Registration failed'}, 500

@auth_ns.route('/login')
class Login(Resource):
    @api.expect(auth_model)
    @performance_monitor.track_request('auth_login')
    def post(self):
        """Login user"""
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            
            if not email or not password:
                return {'error': 'Email and password required'}, 400
            
            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password):
                # Update last login
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                # Update active users metric
                performance_monitor.update_active_users(
                    User.query.filter(User.last_login > datetime.utcnow() - timedelta(minutes=30)).count()
                )
                
                access_token = create_access_token(identity=user.id)
                
                return {
                    'access_token': access_token,
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'name': f"{user.first_name} {user.last_name}".strip(),
                        'role': getattr(user, 'role', 'free'),
                        'is_admin': user.is_admin,
                        'scan_limit': getattr(user, 'scan_limit', 5)
                    }
                }, 200
            else:
                return {'error': 'Invalid credentials'}, 401
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return {'error': 'Login failed'}, 500

# ===========================
# API KEY MANAGEMENT
# ===========================

@admin_ns.route('/apikey')
class ApiKeyManagement(Resource):
    @jwt_required()
    @api.expect(api_key_model)
    @performance_monitor.track_request('admin_create_api_key')
    def post(self):
        """Generate new API key"""
        try:
            user_id = get_jwt_identity()
            data = request.get_json()
            
            # Generate unique API key
            api_key = f"wsp_{uuid.uuid4().hex}"
            
            # Create API key record
            key_obj = ApiKey(
                user_id=user_id,
                key=api_key,
                name=data.get('name', 'Default API Key'),
                permissions=data.get('permissions'),
                rate_limit=data.get('rate_limit', 1000),
                expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None
            )
            
            db.session.add(key_obj)
            db.session.commit()
            
            return {
                'message': 'API key created successfully',
                'api_key': api_key,
                'key_info': key_obj.to_dict()
            }, 201
            
        except Exception as e:
            logger.error(f"API key creation error: {e}")
            db.session.rollback()
            return {'error': 'Failed to create API key'}, 500
    
    @jwt_required()
    @performance_monitor.track_request('admin_list_api_keys')
    def get(self):
        """List user's API keys"""
        try:
            user_id = get_jwt_identity()
            keys = ApiKey.query.filter_by(user_id=user_id).all()
            
            return {
                'api_keys': [key.to_dict() for key in keys],
                'total': len(keys)
            }, 200
            
        except Exception as e:
            logger.error(f"API key listing error: {e}")
            return {'error': 'Failed to list API keys'}, 500

# ===========================
# ENHANCED SCAN ENDPOINTS
# ===========================

@scan_ns.route('/start')
class ScanStart(Resource):
    @api.expect(scan_model)
    @api_key_or_jwt_required
    @limiter.limit("10 per minute")
    @performance_monitor.track_request('scan_start')
    def post(self):
        """Start a new security scan"""
        try:
            user_id = get_current_user_id()
            user = User.query.get(user_id)
            
            if not user:
                return {'error': 'User not found'}, 404
            
            # Check scan limits for free users
            if getattr(user, 'role', 'free') == 'free':
                scan_count = Scan.query.filter_by(user_id=user_id).count()
                scan_limit = getattr(user, 'scan_limit', 5)
                
                if scan_count >= scan_limit:
                    return {
                        'error': f'Scan limit reached ({scan_limit} scans). Upgrade to premium for unlimited scans.',
                        'upgrade_url': '/upgrade'
                    }, 403
            
            data = request.get_json()
            target_url = data.get('url')
            scan_type = data.get('scan_type', 'comprehensive')
            
            if not target_url:
                return {'error': 'Target URL is required'}, 400
            
            # Validate URL format
            if not re.match(r'^https?://', target_url):
                return {'error': 'Invalid URL format'}, 400
            
            # Advanced scan configuration
            scan_config = {
                'max_depth': data.get('max_depth', 10),
                'include_sql': data.get('include_sql', True),
                'include_xss': data.get('include_xss', True),
                'include_csrf': data.get('include_csrf', True),
                'include_directory': data.get('include_directory', True),
                'aggressive_mode': data.get('aggressive_mode', False),
                'custom_headers': data.get('custom_headers', {}),
                'scan_delay': data.get('scan_delay', 1)
            }
            
            # Create scan record
            scan = Scan(
                user_id=user_id,
                target_url=target_url,
                scan_type=scan_type,
                status='pending',
                scan_config=scan_config
            )
            
            db.session.add(scan)
            db.session.flush()  # Get the scan ID
            
            # Start scan in background
            scan_id = scan.id
            
            def progress_callback(scan_id, results):
                with app.app_context():
                    try:
                        current_scan = Scan.query.get(scan_id)
                        if current_scan:
                            current_scan.status = results.get('status', 'running')
                            current_scan.progress_percentage = results.get('progress', 0)
                            current_scan.vulnerabilities_count = len(results.get('vulnerabilities', []))
                            
                            if results.get('status') == 'completed':
                                current_scan.completed_at = datetime.utcnow()
                                current_scan.results = results
                                
                                # Trigger NLP analysis
                                vulnerabilities = results.get('vulnerabilities', [])
                                if vulnerabilities:
                                    nlp_start = time.time()
                                    nlp_analysis = analyze_scan_results(vulnerabilities)
                                    nlp_duration = time.time() - nlp_start
                                    
                                    current_scan.nlp_summary = nlp_analysis.get('summary', '')
                                    current_scan.risk_score = nlp_analysis.get('avg_priority_score', 0) / 10  # Scale to 0-10
                                    
                                    performance_monitor.track_nlp_processing('vulnerability_analysis', nlp_duration)
                                
                                # Send email notification
                                try:
                                    from email_service import email_service
                                    email_service.send_scan_completion_notification(
                                        user_email=user.email,
                                        scan_id=scan_id,
                                        target_url=target_url,
                                        scan_type=scan_type,
                                        vulnerabilities_count=current_scan.vulnerabilities_count or 0,
                                        risk_score=current_scan.risk_score or 0
                                    )
                                    performance_monitor.track_email('scan_completion', True)
                                except Exception as e:
                                    logger.warning(f"Failed to send scan completion email: {e}")
                                    performance_monitor.track_email('scan_completion', False)
                            
                            db.session.commit()
                    except Exception as e:
                        logger.error(f"Progress callback error: {e}")
                        db.session.rollback()
            
            # Start scan with monitoring
            with performance_monitor.track_scan(scan_type):
                scan_manager.start_scan(scan_id, target_url, scan_type, scan_config, progress_callback)
            
            db.session.commit()
            
            return {
                'message': 'Scan started successfully',
                'scan_id': scan_id,
                'status': 'pending',
                'estimated_duration': f"{scan_config.get('max_depth', 10) * 30} seconds"
            }, 201
            
        except Exception as e:
            logger.error(f"Scan start error: {e}")
            db.session.rollback()
            return {'error': 'Failed to start scan'}, 500

@scan_ns.route('/progress/<int:scan_id>')
class ScanProgress(Resource):
    @api_key_or_jwt_required
    @limiter.limit("30 per minute")
    @performance_monitor.track_request('scan_progress')
    def get(self, scan_id):
        """Get scan progress and status"""
        try:
            user_id = get_current_user_id()
            scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
            
            if not scan:
                return {'error': 'Scan not found'}, 404
            
            # Calculate estimated time remaining
            estimated_remaining = None
            if scan.status == 'running' and scan.started_at:
                elapsed = (datetime.utcnow() - scan.started_at).total_seconds()
                if scan.progress_percentage > 0:
                    total_estimated = elapsed / (scan.progress_percentage / 100)
                    estimated_remaining = total_estimated - elapsed
            
            return {
                'scan_id': scan_id,
                'status': scan.status,
                'progress_percentage': scan.progress_percentage or 0,
                'vulnerabilities_found': scan.vulnerabilities_count or 0,
                'pages_scanned': scan.pages_scanned or 0,
                'requests_made': scan.requests_made or 0,
                'estimated_remaining_seconds': max(0, estimated_remaining) if estimated_remaining else None,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'error_message': scan.error_message
            }, 200
            
        except Exception as e:
            logger.error(f"Scan progress error: {e}")
            return {'error': 'Failed to get scan progress'}, 500

# ===========================
# USER ROLE MANAGEMENT
# ===========================

@admin_ns.route('/users/<int:user_id>/role')
class UserRoleManagement(Resource):
    @jwt_required()
    @require_role('admin')
    @performance_monitor.track_request('admin_update_user_role')
    def put(self, user_id):
        """Update user role (admin only)"""
        try:
            data = request.get_json()
            new_role = data.get('role')
            new_scan_limit = data.get('scan_limit')
            
            if new_role not in ['free', 'premium', 'admin']:
                return {'error': 'Invalid role'}, 400
            
            user = User.query.get(user_id)
            if not user:
                return {'error': 'User not found'}, 404
            
            # Update user attributes (check if columns exist)
            if hasattr(user, 'role'):
                user.role = new_role
            if hasattr(user, 'scan_limit') and new_scan_limit:
                user.scan_limit = new_scan_limit
            
            # Set admin status based on role
            user.is_admin = (new_role == 'admin')
            
            db.session.commit()
            
            return {
                'message': f'User role updated to {new_role}',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'role': new_role,
                    'is_admin': user.is_admin,
                    'scan_limit': getattr(user, 'scan_limit', 5)
                }
            }, 200
            
        except Exception as e:
            logger.error(f"Role update error: {e}")
            db.session.rollback()
            return {'error': 'Failed to update user role'}, 500

# ===========================
# REMEDIATION SUGGESTIONS
# ===========================

REMEDIATION_MAP = {
    'XSS': {
        'description': 'Cross-Site Scripting vulnerability detected',
        'remediation': [
            'Sanitize all user inputs using proper encoding',
            'Implement Content Security Policy (CSP) headers',
            'Use template engines with automatic escaping',
            'Validate input on both client and server side'
        ],
        'risk_level': 'High',
        'cwe': 'CWE-79'
    },
    'SQL Injection': {
        'description': 'SQL Injection vulnerability detected',
        'remediation': [
            'Use parameterized queries or prepared statements',
            'Implement input validation and sanitization',
            'Apply principle of least privilege to database accounts',
            'Use stored procedures where appropriate'
        ],
        'risk_level': 'Critical',
        'cwe': 'CWE-89'
    },
    'CSRF': {
        'description': 'Cross-Site Request Forgery vulnerability detected',
        'remediation': [
            'Implement anti-CSRF tokens',
            'Verify referrer headers',
            'Use SameSite cookie attributes',
            'Require re-authentication for sensitive actions'
        ],
        'risk_level': 'Medium',
        'cwe': 'CWE-352'
    },
    'Directory Traversal': {
        'description': 'Directory Traversal vulnerability detected',
        'remediation': [
            'Validate and sanitize file paths',
            'Use whitelist of allowed files/directories',
            'Implement proper access controls',
            'Avoid direct file system access based on user input'
        ],
        'risk_level': 'High',
        'cwe': 'CWE-22'
    }
}

@scan_ns.route('/result/<int:scan_id>')
class ScanResult(Resource):
    @api_key_or_jwt_required
    @performance_monitor.track_request('scan_result')
    def get(self, scan_id):
        """Get detailed scan results with remediation suggestions"""
        try:
            user_id = get_current_user_id()
            scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
            
            if not scan:
                return {'error': 'Scan not found'}, 404
            
            if scan.status != 'completed':
                return {'error': 'Scan not completed yet'}, 400
            
            # Get vulnerabilities with remediation suggestions
            vulnerabilities = scan.results.get('vulnerabilities', []) if scan.results else []
            
            # Enhance vulnerabilities with remediation info
            enhanced_vulnerabilities = []
            for vuln in vulnerabilities[:100]:  # Limit to 100 for performance
                vuln_type = vuln.get('type', 'Unknown')
                
                enhanced_vuln = {
                    **vuln,
                    'remediation_info': REMEDIATION_MAP.get(vuln_type, {
                        'description': f'{vuln_type} vulnerability detected',
                        'remediation': ['Review and mitigate manually'],
                        'risk_level': 'Medium',
                        'cwe': 'Unknown'
                    })
                }
                
                enhanced_vulnerabilities.append(enhanced_vuln)
            
            # Get NLP analysis
            nlp_summary = scan.nlp_summary or 'Analysis not available'
            
            return {
                'scan_id': scan_id,
                'status': scan.status,
                'target_url': scan.target_url,
                'scan_type': scan.scan_type,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'duration_seconds': scan.duration_seconds,
                'vulnerabilities': enhanced_vulnerabilities,
                'vulnerability_summary': {
                    'total': len(enhanced_vulnerabilities),
                    'critical': len([v for v in enhanced_vulnerabilities if v.get('remediation_info', {}).get('risk_level') == 'Critical']),
                    'high': len([v for v in enhanced_vulnerabilities if v.get('remediation_info', {}).get('risk_level') == 'High']),
                    'medium': len([v for v in enhanced_vulnerabilities if v.get('remediation_info', {}).get('risk_level') == 'Medium']),
                    'low': len([v for v in enhanced_vulnerabilities if v.get('remediation_info', {}).get('risk_level') == 'Low'])
                },
                'risk_score': scan.risk_score or 0,
                'nlp_summary': nlp_summary,
                'pages_scanned': scan.pages_scanned or 0,
                'requests_made': scan.requests_made or 0
            }, 200
            
        except Exception as e:
            logger.error(f"Scan result error: {e}")
            return {'error': 'Failed to get scan results'}, 500

# ===========================
# ERROR HANDLERS
# ===========================

@app.errorhandler(Exception)
def handle_general_exception(e):
    if sentry_dsn:
        sentry_sdk.capture_exception(e)
    logger.error(f"Unhandled exception: {str(e)}")
    performance_monitor.error_count += 1
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def handle_rate_limit_exceeded(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'retry_after': '60 seconds'
    }), 429

@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({'error': 'Bad request', 'message': str(e)}), 400

@app.errorhandler(500)
def handle_internal_error(e):
    if sentry_dsn:
        sentry_sdk.capture_exception(e)
    return jsonify({'error': 'Internal server error'}), 500

# ===========================
# APPLICATION STARTUP
# ===========================

@app.before_first_request
def initialize_app():
    """Initialize application on first request"""
    try:
        # Create database tables
        with app.app_context():
            init_db()
            
            # Create sample data if in development
            if os.getenv('FLASK_ENV') == 'development':
                create_sample_data()
        
        logger.info("Application initialized successfully")
        
    except Exception as e:
        logger.error(f"Application initialization failed: {e}")

if __name__ == '__main__':
    # Development server with SocketIO
    socketio.run(
        app,
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development'
    ) 