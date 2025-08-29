from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from datetime import datetime, timedelta
import re
import random
import os

# Import our models
from models import db, User, Scan, Vulnerability, init_db, create_sample_data

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///websecpen.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
CORS(app)
jwt = JWTManager(app)

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
        
        # TODO: Integrate with OWASP ZAP (Task 16)
        # For now, update status to running
        scan.status = 'running'
        scan.started_at = datetime.utcnow()
        db.session.commit()
        
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
