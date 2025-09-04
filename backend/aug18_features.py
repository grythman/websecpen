# aug18_features.py - Advanced Features for WebSecPen (Aug 18, 2025)
# Report Customization, Security, and Integrations

import os
import io
import json
import pyotp
import qrcode
import requests
import secrets
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from flask import Flask, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt, create_access_token
from werkzeug.security import check_password_hash
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from models import db, User, Scan, TeamMember

# Global Redis client (will be initialized)
redis_client = None

def init_redis_client():
    """Initialize Redis client for queue management"""
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
# 1. CUSTOM SCAN REPORT TEMPLATES
# =============================================================================

def create_report_template_model():
    """Model definition for ReportTemplate (to be added to models.py)"""
    return '''
class ReportTemplate(db.Model):
    __tablename__ = 'report_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    template_config = db.Column(db.JSON, nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='report_templates')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'template_config': self.template_config,
            'is_public': self.is_public,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
'''

def init_report_template_routes(app):
    """Initialize custom report template routes"""
    
    @app.route('/api/report/templates', methods=['GET'])
    @jwt_required()
    def get_report_templates():
        """Get user's custom report templates"""
        user_id = get_jwt_identity()
        
        try:
            # For now, simulate templates stored in Redis
            templates = []
            
            if redis_client:
                # Get user's templates
                template_keys = redis_client.keys(f'template:{user_id}:*')
                for key in template_keys:
                    template_data = redis_client.get(key)
                    if template_data:
                        templates.append(json.loads(template_data))
            
            # Add default templates
            default_templates = [
                {
                    'id': 'default_executive',
                    'name': 'Executive Summary',
                    'description': 'High-level overview for executives',
                    'template_config': {
                        'title': 'Security Assessment Executive Summary',
                        'fields': ['severity', 'name', 'solution'],
                        'show_charts': True,
                        'include_summary': True,
                        'group_by_severity': True
                    },
                    'is_default': True
                },
                {
                    'id': 'default_technical',
                    'name': 'Technical Report',
                    'description': 'Detailed technical analysis',
                    'template_config': {
                        'title': 'Detailed Technical Security Report',
                        'fields': ['name', 'desc', 'severity', 'solution', 'reference', 'evidence'],
                        'show_charts': True,
                        'include_summary': True,
                        'include_methodology': True,
                        'group_by_type': True
                    },
                    'is_default': True
                },
                {
                    'id': 'default_compliance',
                    'name': 'Compliance Report',
                    'description': 'Compliance-focused report',
                    'template_config': {
                        'title': 'Security Compliance Assessment',
                        'fields': ['name', 'severity', 'cweid', 'wascid', 'solution'],
                        'show_charts': False,
                        'include_summary': True,
                        'include_compliance': True,
                        'group_by_compliance': True
                    },
                    'is_default': True
                }
            ]
            
            return jsonify({
                'templates': templates + default_templates,
                'total': len(templates) + len(default_templates)
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to fetch templates: {str(e)}'}), 500
    
    @app.route('/api/report/templates', methods=['POST'])
    @jwt_required()
    def create_report_template():
        """Create a new custom report template"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        template_config = data.get('template_config', {})
        
        if not name or len(name) < 3:
            return jsonify({'error': 'Template name must be at least 3 characters'}), 400
        
        if not template_config or not isinstance(template_config, dict):
            return jsonify({'error': 'Invalid template configuration'}), 400
        
        try:
            # Create template data
            template_id = f"template_{user_id}_{datetime.utcnow().timestamp()}"
            template_data = {
                'id': template_id,
                'user_id': user_id,
                'name': name,
                'description': description,
                'template_config': template_config,
                'is_public': data.get('is_public', False),
                'created_at': datetime.utcnow().isoformat()
            }
            
            # Store in Redis
            if redis_client:
                redis_client.setex(
                    f'template:{user_id}:{template_id}',
                    86400 * 30,  # 30 days
                    json.dumps(template_data)
                )
            
            return jsonify({
                'message': 'Template created successfully',
                'template': template_data
            }), 201
            
        except Exception as e:
            return jsonify({'error': f'Failed to create template: {str(e)}'}), 500
    
    @app.route('/api/scan/<int:scan_id>/report/custom/<template_id>', methods=['GET'])
    @jwt_required()
    def generate_custom_report(scan_id, template_id):
        """Generate custom PDF report using specified template"""
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
            # Get template configuration
            template_config = None
            
            # Check for default templates
            if template_id.startswith('default_'):
                default_templates = {
                    'default_executive': {
                        'title': 'Security Assessment Executive Summary',
                        'fields': ['severity', 'name', 'solution'],
                        'show_charts': True,
                        'include_summary': True,
                        'group_by_severity': True
                    },
                    'default_technical': {
                        'title': 'Detailed Technical Security Report',
                        'fields': ['name', 'desc', 'severity', 'solution', 'reference', 'evidence'],
                        'show_charts': True,
                        'include_summary': True,
                        'include_methodology': True,
                        'group_by_type': True
                    },
                    'default_compliance': {
                        'title': 'Security Compliance Assessment',
                        'fields': ['name', 'severity', 'cweid', 'wascid', 'solution'],
                        'show_charts': False,
                        'include_summary': True,
                        'include_compliance': True,
                        'group_by_compliance': True
                    }
                }
                template_config = default_templates.get(template_id)
            else:
                # Get user template from Redis
                if redis_client:
                    template_data = redis_client.get(f'template:{user_id}:{template_id}')
                    if template_data:
                        template_info = json.loads(template_data)
                        template_config = template_info.get('template_config')
            
            if not template_config:
                return jsonify({'error': 'Template not found'}), 404
            
            # Generate PDF
            output = io.BytesIO()
            doc = SimpleDocTemplate(output, pagesize=A4, topMargin=0.5*inch)
            
            # Build PDF content
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                textColor=colors.darkblue,
                alignment=TA_CENTER,
                spaceAfter=20
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.darkblue,
                spaceBefore=15,
                spaceAfter=10
            )
            
            # Title
            story.append(Paragraph(template_config.get('title', 'Security Scan Report'), title_style))
            story.append(Spacer(1, 20))
            
            # Scan information
            scan_info = [
                ['Scan Details', ''],
                ['Target URL:', scan.target_url],
                ['Scan Type:', scan.scan_type or 'Spider'],
                ['Scan Date:', scan.created_at.strftime('%Y-%m-%d %H:%M:%S')],
                ['Status:', scan.status.title()],
            ]
            
            scan_table = Table(scan_info, colWidths=[2*inch, 4*inch])
            scan_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(scan_table)
            story.append(Spacer(1, 20))
            
            # Process scan results
            vulnerabilities = scan.results.get('alerts', []) if scan.results else []
            
            if template_config.get('include_summary', False):
                story.append(Paragraph('Executive Summary', heading_style))
                
                # Severity statistics
                severity_counts = defaultdict(int)
                for vuln in vulnerabilities:
                    severity = vuln.get('risk', 'Low').title()
                    severity_counts[severity] += 1
                
                summary_text = f"This security assessment identified {len(vulnerabilities)} potential vulnerabilities across the target application. "
                if severity_counts:
                    severity_summary = ", ".join([f"{count} {severity}" for severity, count in severity_counts.items()])
                    summary_text += f"The findings include: {severity_summary}."
                
                story.append(Paragraph(summary_text, styles['Normal']))
                story.append(Spacer(1, 15))
            
            # Group vulnerabilities if specified
            if template_config.get('group_by_severity', False):
                # Group by severity
                severity_groups = defaultdict(list)
                for vuln in vulnerabilities:
                    severity = vuln.get('risk', 'Low').title()
                    severity_groups[severity].append(vuln)
                
                for severity in ['High', 'Medium', 'Low', 'Informational']:
                    if severity in severity_groups:
                        story.append(Paragraph(f'{severity} Severity Findings', heading_style))
                        story.extend(_create_vulnerability_table(severity_groups[severity], template_config, styles))
                        story.append(Spacer(1, 15))
            
            elif template_config.get('group_by_type', False):
                # Group by vulnerability type
                type_groups = defaultdict(list)
                for vuln in vulnerabilities:
                    vuln_type = vuln.get('name', 'Unknown').split(' ')[0]
                    type_groups[vuln_type].append(vuln)
                
                for vuln_type, vulns in type_groups.items():
                    story.append(Paragraph(f'{vuln_type} Vulnerabilities', heading_style))
                    story.extend(_create_vulnerability_table(vulns, template_config, styles))
                    story.append(Spacer(1, 15))
            
            else:
                # List all vulnerabilities
                story.append(Paragraph('Identified Vulnerabilities', heading_style))
                story.extend(_create_vulnerability_table(vulnerabilities, template_config, styles))
            
            # Add methodology if specified
            if template_config.get('include_methodology', False):
                story.append(PageBreak())
                story.append(Paragraph('Testing Methodology', heading_style))
                methodology_text = """
                This security assessment was conducted using automated scanning techniques combined with manual verification. 
                The testing methodology included:
                
                • Automated vulnerability scanning using OWASP ZAP
                • Web application crawling and discovery
                • Injection attack testing (SQL, XSS, etc.)
                • Authentication and session management testing
                • Configuration and deployment testing
                """
                story.append(Paragraph(methodology_text, styles['Normal']))
            
            # Build PDF
            doc.build(story)
            output.seek(0)
            
            # Return PDF
            return Response(
                output.getvalue(),
                mimetype='application/pdf',
                headers={
                    'Content-Disposition': f'attachment; filename=scan_{scan_id}_custom_report.pdf'
                }
            )
            
        except Exception as e:
            return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500

def _create_vulnerability_table(vulnerabilities, template_config, styles):
    """Helper function to create vulnerability table for PDF"""
    if not vulnerabilities:
        return [Paragraph('No vulnerabilities found in this category.', styles['Normal'])]
    
    story = []
    fields = template_config.get('fields', ['name', 'severity', 'desc'])
    
    # Create table data
    table_data = []
    
    # Header row
    header_row = [field.title() for field in fields]
    table_data.append(header_row)
    
    # Data rows
    for vuln in vulnerabilities:
        row = []
        for field in fields:
            value = vuln.get(field, 'N/A')
            if isinstance(value, str) and len(value) > 100:
                value = value[:100] + '...'
            row.append(str(value))
        table_data.append(row)
    
    # Create table
    col_widths = [1.5*inch] * len(fields)
    vuln_table = Table(table_data, colWidths=col_widths)
    vuln_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(vuln_table)
    return story

# =============================================================================
# 2. MULTI-FACTOR AUTHENTICATION (MFA)
# =============================================================================

def update_user_model_for_mfa():
    """Model updates for MFA (to be added to models.py)"""
    return '''
# Add to User model:
mfa_secret = db.Column(db.String(32), nullable=True)
mfa_enabled = db.Column(db.Boolean, default=False)
mfa_backup_codes = db.Column(db.JSON, nullable=True)  # List of backup codes
'''

def init_mfa_routes(app):
    """Initialize Multi-Factor Authentication routes"""
    
    @app.route('/api/mfa/setup', methods=['POST'])
    @jwt_required()
    def setup_mfa():
        """Setup MFA for user account"""
        user_id = get_jwt_identity()
        
        try:
            # For now, simulate MFA setup with Redis
            secret = pyotp.random_base32()
            
            # Generate QR code data
            totp = pyotp.TOTP(secret)
            user_email = f"user_{user_id}@websecpen.com"  # Simulated email
            qr_uri = totp.provisioning_uri(
                user_email,
                issuer_name="WebSecPen"
            )
            
            # Generate backup codes
            backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
            
            # Store MFA data in Redis temporarily
            if redis_client:
                mfa_data = {
                    'secret': secret,
                    'backup_codes': backup_codes,
                    'enabled': False,
                    'setup_time': datetime.utcnow().isoformat()
                }
                redis_client.setex(f'mfa:{user_id}', 3600, json.dumps(mfa_data))  # 1 hour expiry
            
            return jsonify({
                'secret': secret,
                'qr_uri': qr_uri,
                'backup_codes': backup_codes,
                'manual_entry_key': secret
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to setup MFA: {str(e)}'}), 500
    
    @app.route('/api/mfa/verify', methods=['POST'])
    @jwt_required()
    def verify_mfa():
        """Verify MFA setup with TOTP code"""
        user_id = get_jwt_identity()
        data = request.get_json()
        
        code = data.get('code', '').strip()
        if not code:
            return jsonify({'error': 'Verification code is required'}), 400
        
        try:
            # Get MFA setup data
            if redis_client:
                mfa_data_json = redis_client.get(f'mfa:{user_id}')
                if not mfa_data_json:
                    return jsonify({'error': 'MFA setup not found or expired'}), 400
                
                mfa_data = json.loads(mfa_data_json)
                secret = mfa_data['secret']
                
                # Verify TOTP code
                totp = pyotp.TOTP(secret)
                if totp.verify(code):
                    # Enable MFA
                    mfa_data['enabled'] = True
                    mfa_data['verified_at'] = datetime.utcnow().isoformat()
                    
                    # Store permanently (extend expiry)
                    redis_client.setex(f'mfa:{user_id}', 86400 * 365, json.dumps(mfa_data))  # 1 year
                    
                    return jsonify({
                        'message': 'MFA enabled successfully',
                        'backup_codes': mfa_data['backup_codes']
                    }), 200
                else:
                    return jsonify({'error': 'Invalid verification code'}), 400
            
            return jsonify({'error': 'MFA setup not found'}), 400
            
        except Exception as e:
            return jsonify({'error': f'Failed to verify MFA: {str(e)}'}), 500
    
    @app.route('/api/mfa/status', methods=['GET'])
    @jwt_required()
    def get_mfa_status():
        """Get MFA status for user"""
        user_id = get_jwt_identity()
        
        try:
            if redis_client:
                mfa_data_json = redis_client.get(f'mfa:{user_id}')
                if mfa_data_json:
                    mfa_data = json.loads(mfa_data_json)
                    return jsonify({
                        'enabled': mfa_data.get('enabled', False),
                        'setup_time': mfa_data.get('setup_time'),
                        'verified_at': mfa_data.get('verified_at')
                    }), 200
            
            return jsonify({'enabled': False}), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get MFA status: {str(e)}'}), 500

def init_enhanced_auth_routes(app):
    """Initialize enhanced authentication with MFA support"""
    
    @app.route('/api/login', methods=['POST'])
    def login_with_mfa():
        """Enhanced login with MFA support"""
        data = request.get_json()
        
        email = data.get('email', '').strip()
        password = data.get('password', '')
        mfa_code = data.get('mfa_code', '').strip()
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        try:
            # Find user (simulated)
            user_id = 1  # Simulated user ID
            
            # Simulate password check (in production, use actual User model)
            if email == 'admin@example.com' and password == 'password':
                # Check if MFA is enabled
                mfa_enabled = False
                mfa_verified = True
                
                if redis_client:
                    mfa_data_json = redis_client.get(f'mfa:{user_id}')
                    if mfa_data_json:
                        mfa_data = json.loads(mfa_data_json)
                        mfa_enabled = mfa_data.get('enabled', False)
                        
                        if mfa_enabled:
                            if not mfa_code:
                                return jsonify({
                                    'error': 'MFA code required',
                                    'mfa_required': True
                                }), 401
                            
                            # Verify MFA code
                            secret = mfa_data['secret']
                            backup_codes = mfa_data.get('backup_codes', [])
                            
                            totp = pyotp.TOTP(secret)
                            if totp.verify(mfa_code):
                                mfa_verified = True
                            elif mfa_code.upper() in backup_codes:
                                # Use backup code (remove it after use)
                                backup_codes.remove(mfa_code.upper())
                                mfa_data['backup_codes'] = backup_codes
                                redis_client.setex(f'mfa:{user_id}', 86400 * 365, json.dumps(mfa_data))
                                mfa_verified = True
                            else:
                                mfa_verified = False
                
                if mfa_enabled and not mfa_verified:
                    return jsonify({'error': 'Invalid MFA code'}), 401
                
                # Create access token
                access_token = create_access_token(
                    identity=user_id,
                    additional_claims={
                        'is_admin': True,
                        'mfa_verified': mfa_verified
                    }
                )
                
                return jsonify({
                    'access_token': access_token,
                    'user_id': user_id,
                    'mfa_enabled': mfa_enabled
                }), 200
            else:
                return jsonify({'error': 'Invalid credentials'}), 401
                
        except Exception as e:
            return jsonify({'error': f'Login failed: {str(e)}'}), 500

# =============================================================================
# 3. PAGERDUTY INTEGRATION
# =============================================================================

def init_pagerduty_routes(app):
    """Initialize PagerDuty integration routes"""
    
    @app.route('/api/scan/<int:scan_id>/pagerduty', methods=['POST'])
    @jwt_required()
    def create_pagerduty_incident(scan_id):
        """Create PagerDuty incidents for high-severity vulnerabilities"""
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
            return jsonify({'error': 'Scan not completed'}), 400
        
        try:
            pagerduty_key = os.environ.get('PAGERDUTY_INTEGRATION_KEY')
            if not pagerduty_key:
                return jsonify({'error': 'PagerDuty not configured'}), 400
            
            incidents_created = 0
            vulnerabilities = scan.results.get('alerts', []) if scan.results else []
            
            for vuln in vulnerabilities:
                severity = vuln.get('risk', 'Low').lower()
                
                # Only create incidents for high and medium severity
                if severity in ['high', 'medium']:
                    incident_data = {
                        'routing_key': pagerduty_key,
                        'event_action': 'trigger',
                        'dedup_key': f'websecpen-{scan_id}-{vuln.get("pluginid", "unknown")}',
                        'payload': {
                            'summary': f'{vuln.get("name", "Security Issue")} detected in {scan.target_url}',
                            'severity': 'critical' if severity == 'high' else 'warning',
                            'source': scan.target_url,
                            'component': 'WebSecPen Security Scanner',
                            'group': 'Security',
                            'class': vuln.get('name', 'Unknown'),
                            'custom_details': {
                                'scan_id': scan_id,
                                'vulnerability_type': vuln.get('name'),
                                'description': vuln.get('desc', 'No description available'),
                                'solution': vuln.get('solution', 'No solution available'),
                                'confidence': vuln.get('confidence', 'Unknown'),
                                'url': vuln.get('url', scan.target_url),
                                'scanner': 'WebSecPen'
                            }
                        }
                    }
                    
                    response = requests.post(
                        'https://events.pagerduty.com/v2/enqueue',
                        json=incident_data,
                        timeout=10
                    )
                    
                    if response.status_code == 202:
                        incidents_created += 1
                    else:
                        print(f'PagerDuty API error: {response.status_code} - {response.text}')
            
            return jsonify({
                'message': f'Created {incidents_created} PagerDuty incidents',
                'incidents_created': incidents_created,
                'total_vulnerabilities': len(vulnerabilities)
            }), 200
            
        except Exception as e:
            return jsonify({'error': f'PagerDuty integration failed: {str(e)}'}), 500
    
    @app.route('/api/pagerduty/config', methods=['GET'])
    @jwt_required()
    def get_pagerduty_config():
        """Get PagerDuty configuration status"""
        pagerduty_key = os.environ.get('PAGERDUTY_INTEGRATION_KEY')
        
        return jsonify({
            'configured': bool(pagerduty_key),
            'integration_url': 'https://events.pagerduty.com/v2/enqueue' if pagerduty_key else None
        }), 200

# =============================================================================
# 4. SCAN PRIORITIZATION DASHBOARD
# =============================================================================

def init_scan_queue_routes(app):
    """Initialize scan queue management routes"""
    
    @app.route('/api/admin/scan-queue', methods=['GET'])
    @jwt_required()
    def get_scan_queue_status():
        """Get scan queue status and priorities"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            queue_data = {
                'total_queued': 0,
                'priority_distribution': {},
                'queue_items': [],
                'processing_stats': {}
            }
            
            if redis_client:
                # Get priority queue data
                queue_items = redis_client.zrevrange('scan_priority_queue', 0, -1, withscores=True)
                
                priority_counts = defaultdict(int)
                queue_details = []
                
                for item_json, score in queue_items:
                    try:
                        item_data = json.loads(item_json)
                        scan_id = item_data.get('scan_id')
                        
                        # Categorize priority
                        if score >= 0.8:
                            priority = 'High'
                        elif score >= 0.5:
                            priority = 'Medium'
                        else:
                            priority = 'Low'
                        
                        priority_counts[priority] += 1
                        
                        queue_details.append({
                            'scan_id': scan_id,
                            'priority_score': round(float(score), 3),
                            'priority_level': priority,
                            'queued_at': item_data.get('queued_at', 'Unknown')
                        })
                        
                    except (json.JSONDecodeError, KeyError):
                        continue
                
                queue_data.update({
                    'total_queued': len(queue_items),
                    'priority_distribution': dict(priority_counts),
                    'queue_items': queue_details[:20],  # Limit to first 20 items
                    'processing_stats': {
                        'avg_priority_score': sum(score for _, score in queue_items) / len(queue_items) if queue_items else 0,
                        'highest_priority': max(score for _, score in queue_items) if queue_items else 0,
                        'lowest_priority': min(score for _, score in queue_items) if queue_items else 0
                    }
                })
            
            return jsonify(queue_data), 200
            
        except Exception as e:
            return jsonify({'error': f'Failed to get queue status: {str(e)}'}), 500
    
    @app.route('/api/admin/scan-queue/simulate', methods=['POST'])
    @jwt_required()
    def simulate_queue_data():
        """Simulate queue data for testing (admin only)"""
        claims = get_jwt()
        if not claims.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            if redis_client:
                # Create some test queue items
                import random
                
                for i in range(10):
                    scan_data = {
                        'scan_id': f'test_scan_{i}',
                        'url': f'https://test{i}.example.com',
                        'queued_at': datetime.utcnow().isoformat()
                    }
                    priority_score = random.uniform(0.1, 1.0)
                    
                    redis_client.zadd(
                        'scan_priority_queue',
                        {json.dumps(scan_data): priority_score}
                    )
                
                return jsonify({'message': 'Queue simulation data created'}), 200
            else:
                return jsonify({'error': 'Redis not available'}), 500
                
        except Exception as e:
            return jsonify({'error': f'Failed to simulate queue: {str(e)}'}), 500

# =============================================================================
# MAIN INITIALIZATION FUNCTION
# =============================================================================

def init_aug18_routes(app):
    """Initialize all August 18th features"""
    
    # Initialize Redis
    redis_available = init_redis_client()
    if not redis_available:
        print("Warning: Redis not available. Some features may not work properly.")
    
    # Initialize all feature routes
    init_report_template_routes(app)
    init_mfa_routes(app)
    init_enhanced_auth_routes(app)
    init_pagerduty_routes(app)
    init_scan_queue_routes(app)
    
    print("✅ August 18th features initialized successfully!")
    print("📋 Features: Custom Reports, MFA, PagerDuty, Queue Dashboard")
    
    return app 