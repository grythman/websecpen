# models.py - Database models for WebSecPen
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and scan ownership"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(80), nullable=True)
    last_name = db.Column(db.String(80), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'total_scans': len(self.scans)
        }
    
    def __repr__(self):
        return f'<User {self.email}>'

class Scan(db.Model):
    """Scan model for security scan records"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False, index=True)  # XSS, SQLi, CSRF, Directory
    status = db.Column(db.String(20), default='pending', index=True)  # pending, running, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True, index=True)
    duration_seconds = db.Column(db.Integer, nullable=True)
    
    # Scan configuration
    scan_config = db.Column(db.JSON, nullable=True)  # Additional scan parameters
    
    # Results
    results = db.Column(db.JSON, nullable=True)  # Raw scan results from ZAP
    vulnerabilities_count = db.Column(db.Integer, default=0)
    high_severity_count = db.Column(db.Integer, default=0)
    medium_severity_count = db.Column(db.Integer, default=0)
    low_severity_count = db.Column(db.Integer, default=0)
    info_severity_count = db.Column(db.Integer, default=0)
    
    # NLP Analysis
    nlp_summary = db.Column(db.Text, nullable=True)  # HuggingFace generated summary
    risk_score = db.Column(db.Float, nullable=True)  # 0-10 risk score
    
    # Progress tracking
    pages_scanned = db.Column(db.Integer, default=0)
    requests_made = db.Column(db.Integer, default=0)
    progress_percentage = db.Column(db.Integer, default=0)
    
    # Error handling
    error_message = db.Column(db.Text, nullable=True)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def set_results(self, zap_results):
        """Process and store ZAP scan results"""
        self.results = zap_results
        
        # Count vulnerabilities by severity
        if zap_results and 'alerts' in zap_results:
            alerts = zap_results['alerts']
            self.vulnerabilities_count = len(alerts)
            
            # Count by risk level
            for alert in alerts:
                risk = alert.get('risk', '').lower()
                if risk == 'high':
                    self.high_severity_count += 1
                elif risk == 'medium':
                    self.medium_severity_count += 1
                elif risk == 'low':
                    self.low_severity_count += 1
                else:
                    self.info_severity_count += 1
    
    def calculate_risk_score(self):
        """Calculate overall risk score based on vulnerabilities"""
        if self.vulnerabilities_count == 0:
            self.risk_score = 0.0
        else:
            # Weighted scoring: High=3, Medium=2, Low=1, Info=0.5
            weighted_score = (
                self.high_severity_count * 3 +
                self.medium_severity_count * 2 +
                self.low_severity_count * 1 +
                self.info_severity_count * 0.5
            )
            # Normalize to 0-10 scale
            self.risk_score = min(10.0, weighted_score / max(1, self.vulnerabilities_count) * 2)
    
    def get_duration(self):
        """Get scan duration in human-readable format"""
        if self.duration_seconds:
            minutes = self.duration_seconds // 60
            seconds = self.duration_seconds % 60
            if minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        return None
    
    def to_dict(self):
        """Convert scan object to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.get_duration(),
            'duration_seconds': self.duration_seconds,
            'vulnerabilities_count': self.vulnerabilities_count,
            'high_severity_count': self.high_severity_count,
            'medium_severity_count': self.medium_severity_count,
            'low_severity_count': self.low_severity_count,
            'info_severity_count': self.info_severity_count,
            'risk_score': self.risk_score,
            'pages_scanned': self.pages_scanned,
            'requests_made': self.requests_made,
            'progress_percentage': self.progress_percentage,
            'nlp_summary': self.nlp_summary,
            'error_message': self.error_message
        }
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.target_url} ({self.status})>'

class Vulnerability(db.Model):
    """Individual vulnerability found in scans"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    
    # Vulnerability details
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    risk_level = db.Column(db.String(20), nullable=False, index=True)  # High, Medium, Low, Informational
    confidence = db.Column(db.String(20), nullable=True)
    
    # Location information
    url = db.Column(db.String(500), nullable=True)
    parameter = db.Column(db.String(255), nullable=True)
    method = db.Column(db.String(10), nullable=True)  # GET, POST, etc.
    
    # Technical details
    cwe_id = db.Column(db.Integer, nullable=True)  # Common Weakness Enumeration ID
    wasc_id = db.Column(db.Integer, nullable=True)  # Web Application Security Consortium ID
    reference = db.Column(db.Text, nullable=True)  # Reference URLs
    
    # Evidence
    attack = db.Column(db.Text, nullable=True)  # Attack string used
    evidence = db.Column(db.Text, nullable=True)  # Evidence found
    
    # Additional data
    other_info = db.Column(db.Text, nullable=True)
    solution = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert vulnerability to dictionary"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'name': self.name,
            'description': self.description,
            'risk_level': self.risk_level,
            'confidence': self.confidence,
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'cwe_id': self.cwe_id,
            'wasc_id': self.wasc_id,
            'reference': self.reference,
            'attack': self.attack,
            'evidence': self.evidence,
            'other_info': self.other_info,
            'solution': self.solution,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<Vulnerability {self.name} ({self.risk_level})>'

class Feedback(db.Model):
    """Feedback model for user suggestions and bug reports"""
    __tablename__ = 'feedback'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    feedback = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='general')  # general, bug, feature
    priority = db.Column(db.String(20), default='medium')  # low, medium, high
    status = db.Column(db.String(20), default='new')  # new, reviewed, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='feedback_submissions')
    
    def to_dict(self):
        """Convert feedback object to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'feedback': self.feedback,
            'type': self.type,
            'priority': self.priority,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user_email': self.user.email if self.user else 'Anonymous'
        }
    
    def __repr__(self):
        return f'<Feedback {self.id} ({self.type})>'

# Database initialization functions
def init_db(app):
    """Initialize database with app context"""
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        admin_user = User.query.filter_by(email='admin@websecpen.com').first()
        if not admin_user:
            admin_user = User(
                email='admin@websecpen.com',
                first_name='Admin',
                last_name='User',
                is_admin=True
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created: admin@websecpen.com / admin123")

def create_sample_data():
    """Create sample data for testing"""
    # Create test user
    test_user = User.query.filter_by(email='test@example.com').first()
    if not test_user:
        test_user = User(
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
        test_user.set_password('test123')
        db.session.add(test_user)
        db.session.commit()
    
    # Create sample scan
    sample_scan = Scan.query.filter_by(target_url='https://example.com').first()
    if not sample_scan:
        sample_scan = Scan(
            user_id=test_user.id,
            target_url='https://example.com',
            scan_type='XSS',
            status='completed',
            vulnerabilities_count=3,
            high_severity_count=1,
            medium_severity_count=1,
            low_severity_count=1,
            pages_scanned=25,
            requests_made=150,
            progress_percentage=100,
            duration_seconds=180,
            risk_score=6.5,
            nlp_summary='Multiple XSS vulnerabilities detected in form inputs and URL parameters.'
        )
        db.session.add(sample_scan)
        db.session.commit()
        print("Sample data created successfully") 