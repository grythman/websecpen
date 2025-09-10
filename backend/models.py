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
    role = db.Column(db.String(20), default='free', index=True)  # free, premium, admin
    scan_limit = db.Column(db.Integer, default=5)  # Monthly scan limit
    language_preference = db.Column(db.String(10), default='en')  # i18n support
    fcm_token = db.Column(db.String(255), nullable=True)  # Firebase Cloud Messaging token
    
    # Profile customization fields
    avatar_url = db.Column(db.String(255), nullable=True)
    preferences = db.Column(db.JSON, default=lambda: {"notifications": True, "has_seen_tutorial": False})
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')
    referrals_made = db.relationship('Referral', foreign_keys='Referral.referrer_id', backref='referrer', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='admin', lazy=True)
    schedules = db.relationship('Schedule', backref='user', lazy=True, cascade='all, delete-orphan')
    
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
            'is_admin': self.is_admin,
            'role': self.role,
            'scan_limit': self.scan_limit,
            'language_preference': self.language_preference,
            'avatar_url': self.avatar_url,
            'preferences': self.preferences or {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    
    def __repr__(self):
        return f'<User {self.email}>'

class Scan(db.Model):
    """Scan model for security scan records"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    target_url = db.Column(db.String(500), nullable=False, index=True)
    scan_type = db.Column(db.String(50), nullable=False, index=True)  # XSS, SQLi, CSRF, Directory
    status = db.Column(db.String(20), default='pending', index=True)  # pending, running, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True, index=True)
    duration_seconds = db.Column(db.Integer, nullable=True)
    
    # Archive support for database optimization
    archived = db.Column(db.Boolean, default=False, index=True)
    
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
            severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            for alert in zap_results['alerts']:
                risk = alert.get('risk', 'Informational')
                if risk in severity_counts:
                    severity_counts[risk] += 1
            
            self.high_severity_count = severity_counts['High']
            self.medium_severity_count = severity_counts['Medium'] 
            self.low_severity_count = severity_counts['Low']
            self.info_severity_count = severity_counts['Informational']
            self.vulnerabilities_count = sum(severity_counts.values())
    
    def calculate_risk_score(self):
        """Calculate risk score based on vulnerability counts"""
        if self.vulnerabilities_count == 0:
            self.risk_score = 0.0
            return
        
        # Weight scores by severity
        high_weight = 8.0
        medium_weight = 5.0
        low_weight = 2.0
        info_weight = 0.5
        
        total_score = (
            self.high_severity_count * high_weight +
            self.medium_severity_count * medium_weight +
            self.low_severity_count * low_weight +
            self.info_severity_count * info_weight
        )
        
        # Normalize to 0-10 scale
        max_possible = self.vulnerabilities_count * high_weight
        if max_possible > 0:
            self.risk_score = min(10.0, (total_score / max_possible) * 10.0)
        else:
            self.risk_score = 0.0
    
    def to_dict(self):
        """Convert scan to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'vulnerabilities_count': self.vulnerabilities_count,
            'high_severity_count': self.high_severity_count,
            'medium_severity_count': self.medium_severity_count,
            'low_severity_count': self.low_severity_count,
            'info_severity_count': self.info_severity_count,
            'risk_score': self.risk_score,
            'nlp_summary': self.nlp_summary,
            'progress_percentage': self.progress_percentage,
            'archived': self.archived
        }
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.target_url}>'

class Vulnerability(db.Model):
    """Individual vulnerability found in scans"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    
    # Vulnerability details
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False, index=True)  # High, Medium, Low, Info
    confidence = db.Column(db.String(20), nullable=True)  # High, Medium, Low
    
    # Location details
    url = db.Column(db.String(500), nullable=False)
    parameter = db.Column(db.String(200), nullable=True)
    method = db.Column(db.String(10), nullable=True)  # GET, POST, etc.
    
    # Technical details
    attack = db.Column(db.Text, nullable=True)  # Attack vector used
    evidence = db.Column(db.Text, nullable=True)  # Evidence of vulnerability
    solution = db.Column(db.Text, nullable=True)  # Recommended fix
    reference = db.Column(db.Text, nullable=True)  # External references
    
    # OWASP/CWE categorization
    cwe_id = db.Column(db.Integer, nullable=True)
    wasc_id = db.Column(db.Integer, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert vulnerability to dictionary"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'attack': self.attack,
            'evidence': self.evidence,
            'solution': self.solution,
            'reference': self.reference,
            'cwe_id': self.cwe_id,
            'wasc_id': self.wasc_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<Vulnerability {self.name} ({self.severity})>'

class Feedback(db.Model):
    """User feedback and bug reports"""
    __tablename__ = 'feedback'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    
    # Feedback content
    type = db.Column(db.String(20), nullable=False, index=True)  # bug, feature, general
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    
    # Optional metadata
    browser = db.Column(db.String(100), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    url = db.Column(db.String(500), nullable=True)  # Page where feedback was given
    
    # Status tracking
    status = db.Column(db.String(20), default='open', index=True)  # open, in_progress, resolved
    admin_notes = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert feedback to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'type': self.type,
            'subject': self.subject,
            'message': self.message,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<Feedback {self.subject}>'

class ApiKey(db.Model):
    """API keys for programmatic access"""
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Key details
    name = db.Column(db.String(100), nullable=False)  # User-friendly name
    key_hash = db.Column(db.String(255), nullable=False, unique=True, index=True)
    key_prefix = db.Column(db.String(10), nullable=False)  # First few chars for identification
    
    # Permissions and limits
    permissions = db.Column(db.JSON, default=lambda: {'scan': True, 'read': True})
    rate_limit = db.Column(db.Integer, default=100)  # Requests per hour
    
    # Status and tracking
    is_active = db.Column(db.Boolean, default=True, index=True)
    last_used = db.Column(db.DateTime, nullable=True)
    usage_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    user = db.relationship('User', backref='api_keys')
    
    def to_dict(self):
        """Convert API key to dictionary (excluding sensitive data)"""
        return {
            'id': self.id,
            'name': self.name,
            'key_prefix': self.key_prefix,
            'permissions': self.permissions,
            'rate_limit': self.rate_limit,
            'is_active': self.is_active,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }
    
    def __repr__(self):
        return f'<ApiKey {self.name} ({self.key_prefix}...)>'

class Badge(db.Model):
    """User achievement badges"""
    __tablename__ = 'badges'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Badge details
    name = db.Column(db.String(50), nullable=False)  # e.g., "10 Scans", "First Vulnerability"
    description = db.Column(db.String(200), nullable=True)
    icon = db.Column(db.String(50), nullable=True)  # Icon class or emoji
    category = db.Column(db.String(30), nullable=False, index=True)  # scanning, social, achievement
    
    # Achievement tracking
    awarded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='badges')
    
    def to_dict(self):
        """Convert badge to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'category': self.category,
            'awarded_at': self.awarded_at.isoformat() if self.awarded_at else None
        }
    
    def __repr__(self):
        return f'<Badge {self.name}>'

class Referral(db.Model):
    """User referral system"""
    __tablename__ = 'referrals'
    
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    referee_email = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False, index=True)
    redeemed = db.Column(db.Boolean, default=False, index=True)
    redeemed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    redeemed_at = db.Column(db.DateTime, nullable=True)
    
    # Reward tracking
    reward_granted = db.Column(db.Boolean, default=False)
    reward_type = db.Column(db.String(20), default='scan_limit')  # scan_limit, premium_trial
    reward_amount = db.Column(db.Integer, default=5)  # Number of scans or days
    
    def to_dict(self):
        """Convert referral to dictionary"""
        return {
            'id': self.id,
            'referee_email': self.referee_email,
            'code': self.code,
            'redeemed': self.redeemed,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'redeemed_at': self.redeemed_at.isoformat() if self.redeemed_at else None,
            'reward_granted': self.reward_granted,
            'reward_type': self.reward_type,
            'reward_amount': self.reward_amount
        }
    
    def __repr__(self):
        return f'<Referral {self.code}>'

class AuditLog(db.Model):
    """Audit logs for admin actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    details = db.Column(db.JSON, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        """Convert audit log to dictionary"""
        return {
            'id': self.id,
            'admin_id': self.admin_id,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
    
    def __repr__(self):
        return f'<AuditLog {self.action}>'

class Schedule(db.Model):
    """Scheduled scans"""
    __tablename__ = 'schedules'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Schedule details
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False, default='spider')
    frequency = db.Column(db.String(20), nullable=False, index=True)  # daily, weekly, monthly
    
    # Schedule configuration
    is_active = db.Column(db.Boolean, default=True, index=True)
    next_run = db.Column(db.DateTime, nullable=True, index=True)
    last_run = db.Column(db.DateTime, nullable=True)
    run_count = db.Column(db.Integer, default=0)
    
    # Scan configuration
    scan_config = db.Column(db.JSON, default=lambda: {"max_depth": 10, "timeout": 300})
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert schedule to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'scan_type': self.scan_type,
            'frequency': self.frequency,
            'is_active': self.is_active,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'run_count': self.run_count,
            'scan_config': self.scan_config,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<Schedule {self.name}>'

def init_db(app):
    """Initialize database with sample data"""
    db.init_app(app)
    """Initialize database with sample data"""
    with app.app_context():
        db.create_all()
        
        # Check if admin user exists
        admin_user = User.query.filter_by(email='admin@websecpen.com').first()
        if not admin_user:
            admin_user = User(
                email='admin@websecpen.com',
                first_name='Admin',
                last_name='User',
                is_admin=True,
                role='admin',
                scan_limit=9999,
                preferences={"notifications": True, "has_seen_tutorial": True}
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
        
        # Create test user if not exists (legacy domain)
        test_user = User.query.filter_by(email='test@websecpen.com').first()
        if not test_user:
            test_user = User(
                email='test@websecpen.com',
                first_name='Test',
                last_name='User',
                role='premium',
                scan_limit=50,
                preferences={"notifications": True, "has_seen_tutorial": False}
            )
            test_user.set_password('test123')
            db.session.add(test_user)

        # Create example.com test user to match frontend docs
        test_example_user = User.query.filter_by(email='test@example.com').first()
        if not test_example_user:
            test_example_user = User(
                email='test@example.com',
                first_name='Test',
                last_name='User',
                role='premium',
                scan_limit=50,
                preferences={"notifications": True, "has_seen_tutorial": False}
            )
            test_example_user.set_password('test123')
            db.session.add(test_example_user)
        
        db.session.commit()
        print("Database initialized successfully!")

def create_sample_data(app):
    """Create sample data for testing"""
    with app.app_context():
        # Add sample feedback
        if not Feedback.query.first():
            sample_feedback = [
                Feedback(
                    user_id=1,
                    type='feature',
                    subject='Great scanning tool!',
                    message='I love how fast and accurate the vulnerability scanning is. Could you add more scan types?'
                ),
                Feedback(
                    user_id=2,
                    type='bug',
                    subject='Dashboard loading issue',
                    message='The dashboard sometimes takes a long time to load when I have many scans.'
                )
            ]
            for feedback in sample_feedback:
                db.session.add(feedback)
        
        db.session.commit()
        print("Sample data created successfully!")

class Team(db.Model):
    """Team model for collaboration"""
    __tablename__ = 'teams'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    owner = db.relationship('User', backref='owned_teams')
    
    def __repr__(self):
        return f'<Team {self.name}>'


class TeamMember(db.Model):
    """Team member model for team collaboration"""
    __tablename__ = 'team_members'
    
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(20), default='member')  # member, admin
    permissions = db.Column(db.JSON, default=['view'])  # view, scan, edit
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    team = db.relationship('Team', backref='members')
    user = db.relationship('User', backref='team_memberships')
    
    def __repr__(self):
        return f'<TeamMember {self.user_id} in team {self.team_id}>'

