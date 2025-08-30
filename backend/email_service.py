# email_service.py - Email Notification Service for WebSecPen
import os
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, To, From, Subject, PlainTextContent, HtmlContent
import json

# Configure logging
logger = logging.getLogger(__name__)

class EmailService:
    """
    Comprehensive email service for WebSecPen notifications
    Supports scan completion, feedback responses, and system alerts
    """
    
    def __init__(self):
        self.api_key = os.getenv('SENDGRID_API_KEY')
        self.from_email = os.getenv('FROM_EMAIL', 'no-reply@websecpen.com')
        self.from_name = os.getenv('FROM_NAME', 'WebSecPen Security Scanner')
        self.frontend_url = os.getenv('FRONTEND_URL', 'https://websecpen.com')
        
        # Initialize SendGrid client if API key is available
        self.client = None
        if self.api_key:
            try:
                self.client = SendGridAPIClient(self.api_key)
                logger.info("SendGrid email service initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize SendGrid client: {e}")
        else:
            logger.warning("SendGrid API key not configured - email notifications disabled")
    
    def is_enabled(self) -> bool:
        """Check if email service is properly configured"""
        return self.client is not None
    
    def send_email(self, to_email: str, subject: str, html_content: str, 
                   plain_content: str = None, template_data: Dict[str, Any] = None) -> bool:
        """
        Send email with HTML and plain text content
        """
        if not self.is_enabled():
            logger.warning(f"Email service disabled - would send: {subject} to {to_email}")
            return False
        
        try:
            # Create the email message
            from_addr = From(self.from_email, self.from_name)
            to_addr = To(to_email)
            subject_obj = Subject(subject)
            
            # Create plain text content if not provided
            if not plain_content:
                plain_content = self._html_to_plain(html_content)
            
            # Build the email
            mail = Mail(
                from_email=from_addr,
                to_emails=to_addr,
                subject=subject_obj,
                html_content=HtmlContent(html_content),
                plain_text_content=PlainTextContent(plain_content)
            )
            
            # Add custom headers
            mail.header = {
                'X-WebSecPen-Type': 'notification',
                'X-Sent-At': datetime.utcnow().isoformat()
            }
            
            # Send the email
            response = self.client.send(mail)
            
            if response.status_code == 202:
                logger.info(f"Email sent successfully to {to_email}: {subject}")
                return True
            else:
                logger.error(f"Failed to send email to {to_email}: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending email to {to_email}: {str(e)}")
            return False
    
    def send_scan_completion_notification(self, user_email: str, scan_id: int, 
                                         target_url: str, scan_type: str, 
                                         vulnerabilities_count: int, risk_score: float) -> bool:
        """
        Send notification when a security scan completes
        """
        subject = f"🔍 Security Scan Complete - {vulnerabilities_count} Issues Found"
        
        # Determine risk level emoji and color
        risk_emoji = "🔴" if risk_score >= 7 else "🟡" if risk_score >= 4 else "🟢"
        risk_color = "#dc3545" if risk_score >= 7 else "#ffc107" if risk_score >= 4 else "#28a745"
        
        html_content = self._get_scan_completion_template(
            scan_id=scan_id,
            target_url=target_url,
            scan_type=scan_type,
            vulnerabilities_count=vulnerabilities_count,
            risk_score=risk_score,
            risk_emoji=risk_emoji,
            risk_color=risk_color
        )
        
        plain_content = f"""
WebSecPen Security Scan Complete

Scan Details:
- Target: {target_url}
- Type: {scan_type}
- Scan ID: {scan_id}
- Vulnerabilities Found: {vulnerabilities_count}
- Risk Score: {risk_score}/10

View your detailed results at: {self.frontend_url}/dashboard

Thank you for using WebSecPen!
        """.strip()
        
        return self.send_email(user_email, subject, html_content, plain_content)
    
    def send_feedback_response_notification(self, user_email: str, feedback_id: int, 
                                          original_feedback: str, admin_response: str) -> bool:
        """
        Send notification when admin responds to user feedback
        """
        subject = f"💬 Response to Your Feedback #{feedback_id}"
        
        html_content = self._get_feedback_response_template(
            feedback_id=feedback_id,
            original_feedback=original_feedback,
            admin_response=admin_response
        )
        
        plain_content = f"""
WebSecPen Feedback Response

Your Feedback:
{original_feedback}

Our Response:
{admin_response}

Thank you for helping us improve WebSecPen!

View your feedback history at: {self.frontend_url}/dashboard
        """.strip()
        
        return self.send_email(user_email, subject, html_content, plain_content)
    
    def send_welcome_notification(self, user_email: str, user_name: str = None) -> bool:
        """
        Send welcome email to new users
        """
        name = user_name or user_email.split('@')[0]
        subject = f"🎉 Welcome to WebSecPen, {name}!"
        
        html_content = self._get_welcome_template(name)
        
        plain_content = f"""
Welcome to WebSecPen, {name}!

Thank you for joining our AI-powered security scanning platform.

Getting Started:
1. Log in to your dashboard: {self.frontend_url}
2. Start your first security scan
3. Review AI-powered vulnerability analysis
4. Access interactive tutorials and onboarding

Features Available:
- Advanced vulnerability scanning (XSS, SQLi, CSRF, Directory Traversal)
- AI-powered result analysis and prioritization
- Real-time progress monitoring
- Comprehensive reporting and analytics
- Mobile-responsive interface

Need help? Visit our documentation or submit feedback through the platform.

Happy scanning!
The WebSecPen Team
        """.strip()
        
        return self.send_email(user_email, subject, html_content, plain_content)
    
    def send_system_alert(self, admin_emails: list, alert_type: str, 
                         alert_message: str, details: Dict[str, Any] = None) -> bool:
        """
        Send system alerts to administrators
        """
        subject = f"🚨 WebSecPen System Alert: {alert_type}"
        
        html_content = self._get_system_alert_template(
            alert_type=alert_type,
            alert_message=alert_message,
            details=details or {}
        )
        
        plain_content = f"""
WebSecPen System Alert

Alert Type: {alert_type}
Message: {alert_message}

Details:
{json.dumps(details or {}, indent=2)}

Please investigate this alert immediately.

Time: {datetime.utcnow().isoformat()}
        """.strip()
        
        success_count = 0
        for admin_email in admin_emails:
            if self.send_email(admin_email, subject, html_content, plain_content):
                success_count += 1
        
        return success_count > 0
    
    def _get_scan_completion_template(self, **kwargs) -> str:
        """Generate HTML template for scan completion notification"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Complete</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-align: center; padding: 30px; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
        .scan-details {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 5px solid {kwargs['risk_color']}; }}
        .risk-score {{ font-size: 2em; font-weight: bold; color: {kwargs['risk_color']}; text-align: center; margin: 20px 0; }}
        .button {{ display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }}
        .footer {{ text-align: center; color: #666; margin-top: 30px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{kwargs['risk_emoji']} Security Scan Complete</h1>
            <p>Your WebSecPen security assessment is ready</p>
        </div>
        
        <div class="content">
            <div class="scan-details">
                <h3>Scan Summary</h3>
                <p><strong>Target URL:</strong> {kwargs['target_url']}</p>
                <p><strong>Scan Type:</strong> {kwargs['scan_type']}</p>
                <p><strong>Scan ID:</strong> #{kwargs['scan_id']}</p>
                <p><strong>Vulnerabilities Found:</strong> {kwargs['vulnerabilities_count']}</p>
                
                <div class="risk-score">
                    Risk Score: {kwargs['risk_score']}/10
                </div>
                
                <p style="margin-top: 20px;">
                    {'🔴 <strong>High Risk:</strong> Immediate attention required!' if kwargs['risk_score'] >= 7 else 
                     '🟡 <strong>Medium Risk:</strong> Review and address vulnerabilities.' if kwargs['risk_score'] >= 4 else 
                     '🟢 <strong>Low Risk:</strong> Good security posture with minor issues.'}
                </p>
            </div>
            
            <div style="text-align: center;">
                <a href="{self.frontend_url}/dashboard" class="button">
                    View Detailed Results
                </a>
            </div>
            
            <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 8px;">
                <h4>🤖 AI-Powered Analysis</h4>
                <p>Your scan results include intelligent vulnerability prioritization, detailed remediation guidance, and risk assessment powered by advanced AI models.</p>
            </div>
        </div>
        
        <div class="footer">
            <p>Thank you for using WebSecPen - AI-Powered Security Scanner</p>
            <p>Questions? Reply to this email or visit our support center.</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _get_feedback_response_template(self, **kwargs) -> str:
        """Generate HTML template for feedback response notification"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Feedback Response</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-align: center; padding: 30px; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
        .feedback-box {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 5px solid #667eea; }}
        .response-box {{ background: #e7f3ff; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 5px solid #28a745; }}
        .button {{ display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }}
        .footer {{ text-align: center; color: #666; margin-top: 30px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>💬 We've Responded to Your Feedback</h1>
            <p>Thank you for helping us improve WebSecPen</p>
        </div>
        
        <div class="content">
            <div class="feedback-box">
                <h3>Your Feedback (#{kwargs['feedback_id']})</h3>
                <p>{kwargs['original_feedback']}</p>
            </div>
            
            <div class="response-box">
                <h3>Our Response</h3>
                <p>{kwargs['admin_response']}</p>
            </div>
            
            <div style="text-align: center;">
                <a href="{self.frontend_url}/dashboard" class="button">
                    View Your Dashboard
                </a>
            </div>
            
            <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 8px;">
                <h4>📝 Continue the Conversation</h4>
                <p>Have more feedback? We'd love to hear from you! Submit additional feedback through your dashboard or reply to this email.</p>
            </div>
        </div>
        
        <div class="footer">
            <p>Thank you for using WebSecPen - AI-Powered Security Scanner</p>
            <p>Your feedback helps us build a better platform for everyone.</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _get_welcome_template(self, name: str) -> str:
        """Generate HTML template for welcome notification"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to WebSecPen</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-align: center; padding: 40px; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
        .feature-box {{ background: white; padding: 20px; border-radius: 8px; margin: 15px 0; }}
        .button {{ display: inline-block; background: #667eea; color: white; padding: 15px 35px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }}
        .footer {{ text-align: center; color: #666; margin-top: 30px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome to WebSecPen!</h1>
            <h2>Hi {name},</h2>
            <p>Thank you for joining our AI-powered security scanning platform</p>
        </div>
        
        <div class="content">
            <div class="feature-box">
                <h3>🔍 Advanced Security Scanning</h3>
                <p>Detect XSS, SQL injection, CSRF, and directory traversal vulnerabilities with our intelligent scanner.</p>
            </div>
            
            <div class="feature-box">
                <h3>🤖 AI-Powered Analysis</h3>
                <p>Get intelligent vulnerability prioritization and detailed remediation guidance powered by advanced NLP models.</p>
            </div>
            
            <div class="feature-box">
                <h3>📊 Real-time Monitoring</h3>
                <p>Track scan progress in real-time with comprehensive analytics and reporting.</p>
            </div>
            
            <div class="feature-box">
                <h3>📱 Mobile-First Design</h3>
                <p>Access your security dashboard from any device with our responsive, accessible interface.</p>
            </div>
            
            <div style="text-align: center;">
                <a href="{self.frontend_url}/dashboard" class="button">
                    Start Your First Scan
                </a>
            </div>
            
            <div style="margin-top: 30px; padding: 20px; background: #d1ecf1; border-radius: 8px;">
                <h4>🎓 Interactive Onboarding</h4>
                <p>New to security scanning? Our interactive tour will guide you through all the features step by step.</p>
            </div>
        </div>
        
        <div class="footer">
            <p>Need help getting started? Our documentation and tutorials are here to help.</p>
            <p>Happy scanning! - The WebSecPen Team</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _get_system_alert_template(self, **kwargs) -> str:
        """Generate HTML template for system alert notification"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Alert</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #dc3545; color: white; text-align: center; padding: 30px; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
        .alert-box {{ background: #fff5f5; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 5px solid #dc3545; }}
        .details-box {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; font-family: monospace; }}
        .footer {{ text-align: center; color: #666; margin-top: 30px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 System Alert</h1>
            <p>WebSecPen requires immediate attention</p>
        </div>
        
        <div class="content">
            <div class="alert-box">
                <h3>Alert Type: {kwargs['alert_type']}</h3>
                <p><strong>Message:</strong> {kwargs['alert_message']}</p>
                <p><strong>Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
            
            <div class="details-box">
                <h4>Technical Details:</h4>
                <pre>{json.dumps(kwargs['details'], indent=2)}</pre>
            </div>
            
            <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 8px;">
                <h4>⚡ Action Required</h4>
                <p>Please investigate this alert immediately and take appropriate corrective action.</p>
            </div>
        </div>
        
        <div class="footer">
            <p>WebSecPen System Monitoring</p>
            <p>This is an automated alert from your security platform.</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _html_to_plain(self, html_content: str) -> str:
        """Convert HTML content to plain text (basic implementation)"""
        import re
        # Remove HTML tags
        clean = re.compile('<.*?>')
        plain = re.sub(clean, '', html_content)
        # Clean up whitespace
        plain = re.sub(r'\s+', ' ', plain).strip()
        return plain

# Global email service instance
email_service = EmailService() 