# pdf_report.py - PDF Report Generation with ReportLab
import os
import io
from datetime import datetime
from typing import Dict, List, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, 
    PageBreak, Image, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
import logging

logger = logging.getLogger(__name__)

class WebSecPenPDFReport:
    """
    Professional PDF report generator for WebSecPen security scans
    """
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2c3e50'),
            alignment=1  # Center alignment
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=20,
            textColor=colors.HexColor('#34495e'),
        ))
        
        # Executive summary style
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=12,
            leftIndent=20,
            rightIndent=20,
            backColor=colors.HexColor('#ecf0f1'),
            borderColor=colors.HexColor('#bdc3c7'),
            borderWidth=1,
            borderPadding=10
        ))
        
        # Vulnerability item style
        self.styles.add(ParagraphStyle(
            name='VulnerabilityItem',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            leftIndent=10
        ))
        
        # High risk style
        self.styles.add(ParagraphStyle(
            name='HighRisk',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#e74c3c'),
            fontName='Helvetica-Bold'
        ))
        
        # Medium risk style
        self.styles.add(ParagraphStyle(
            name='MediumRisk',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#f39c12'),
            fontName='Helvetica-Bold'
        ))
        
        # Low risk style
        self.styles.add(ParagraphStyle(
            name='LowRisk',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#f1c40f')
        ))
    
    def generate_scan_report(self, scan_data: Dict[str, Any], user_data: Dict[str, Any] = None) -> bytes:
        """
        Generate comprehensive PDF report for a security scan
        
        Args:
            scan_data: Dictionary containing scan results and metadata
            user_data: Optional user information for personalization
            
        Returns:
            bytes: PDF file content
        """
        try:
            # Create PDF buffer
            buffer = io.BytesIO()
            
            # Create document
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            story = []
            
            # Title page
            story.extend(self._create_title_page(scan_data, user_data))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(scan_data))
            story.append(PageBreak())
            
            # Scan overview
            story.extend(self._create_scan_overview(scan_data))
            
            # Vulnerability details
            if scan_data.get('vulnerabilities'):
                story.append(PageBreak())
                story.extend(self._create_vulnerability_details(scan_data))
            
            # Recommendations
            story.append(PageBreak())
            story.extend(self._create_recommendations(scan_data))
            
            # Technical appendix
            story.append(PageBreak())
            story.extend(self._create_technical_appendix(scan_data))
            
            # Build PDF
            doc.build(story)
            
            # Get PDF bytes
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            logger.info(f"Generated PDF report: {len(pdf_bytes)} bytes")
            return pdf_bytes
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            raise
    
    def _create_title_page(self, scan_data: Dict[str, Any], user_data: Dict[str, Any] = None) -> List:
        """Create the title page"""
        elements = []
        
        # Add logo placeholder (you can add actual logo here)
        elements.append(Spacer(1, 1*inch))
        
        # Title
        title = Paragraph("🛡️ WebSecPen Security Assessment Report", self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
        # Scan information table
        scan_info_data = [
            ['Target URL:', scan_data.get('target_url', 'N/A')],
            ['Scan Type:', scan_data.get('scan_type', 'N/A')],
            ['Scanner:', scan_data.get('scanner', 'WebSecPen')],
            ['Scan Date:', scan_data.get('created_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))],
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ]
        
        if user_data:
            scan_info_data.insert(0, ['Client:', user_data.get('email', 'N/A')])
        
        scan_info_table = Table(scan_info_data, colWidths=[2*inch, 4*inch])
        scan_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        elements.append(scan_info_table)
        elements.append(Spacer(1, 1*inch))
        
        # Security level indicator
        severity_counts = {
            'High': scan_data.get('high_severity_count', 0),
            'Medium': scan_data.get('medium_severity_count', 0),
            'Low': scan_data.get('low_severity_count', 0),
            'Info': scan_data.get('info_severity_count', 0)
        }
        
        total_vulns = sum(severity_counts.values())
        
        if total_vulns > 0:
            # Overall risk assessment
            if severity_counts['High'] > 0:
                risk_level = "HIGH RISK"
                risk_color = colors.HexColor('#e74c3c')
            elif severity_counts['Medium'] > 2:
                risk_level = "MEDIUM RISK"
                risk_color = colors.HexColor('#f39c12')
            elif severity_counts['Medium'] > 0 or severity_counts['Low'] > 5:
                risk_level = "LOW RISK"
                risk_color = colors.HexColor('#f1c40f')
            else:
                risk_level = "MINIMAL RISK"
                risk_color = colors.HexColor('#27ae60')
        else:
            risk_level = "NO VULNERABILITIES FOUND"
            risk_color = colors.HexColor('#27ae60')
        
        risk_para = Paragraph(f"<b>OVERALL RISK LEVEL: {risk_level}</b>", 
                             ParagraphStyle('RiskLevel', 
                                          parent=self.styles['Normal'],
                                          fontSize=16,
                                          textColor=risk_color,
                                          alignment=1,
                                          fontName='Helvetica-Bold'))
        
        elements.append(risk_para)
        elements.append(Spacer(1, 0.5*inch))
        
        # Vulnerability summary table
        if total_vulns > 0:
            vuln_summary_data = [
                ['Severity Level', 'Count', 'Percentage'],
                ['High', str(severity_counts['High']), f"{severity_counts['High']/total_vulns*100:.1f}%"],
                ['Medium', str(severity_counts['Medium']), f"{severity_counts['Medium']/total_vulns*100:.1f}%"],
                ['Low', str(severity_counts['Low']), f"{severity_counts['Low']/total_vulns*100:.1f}%"],
                ['Informational', str(severity_counts['Info']), f"{severity_counts['Info']/total_vulns*100:.1f}%"],
                ['TOTAL', str(total_vulns), '100.0%']
            ]
            
            vuln_summary_table = Table(vuln_summary_data, colWidths=[2*inch, 1*inch, 1.5*inch])
            vuln_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#ecf0f1')),
                ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            elements.append(vuln_summary_table)
        
        return elements
    
    def _create_executive_summary(self, scan_data: Dict[str, Any]) -> List:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['CustomTitle']))
        
        # Generate executive summary based on scan results
        total_vulns = scan_data.get('vulnerabilities_count', 0)
        high_count = scan_data.get('high_severity_count', 0)
        medium_count = scan_data.get('medium_severity_count', 0)
        
        if total_vulns == 0:
            summary_text = """
            This security assessment found no significant vulnerabilities in the target application. 
            The application appears to follow security best practices and shows good resistance to 
            common attack vectors. However, this assessment should be part of an ongoing security 
            program, and regular testing is recommended to maintain security posture.
            """
        elif high_count > 0:
            summary_text = f"""
            This security assessment identified {total_vulns} vulnerabilities, including {high_count} 
            high-severity issues that require immediate attention. These vulnerabilities could potentially 
            allow attackers to compromise the application or access sensitive data. Immediate remediation 
            is strongly recommended, followed by a re-scan to verify fixes.
            """
        elif medium_count > 0:
            summary_text = f"""
            This security assessment identified {total_vulns} vulnerabilities, with {medium_count} 
            medium-severity issues that should be addressed in the near term. While not immediately 
            critical, these vulnerabilities could be exploited by attackers and should be prioritized 
            for remediation within the next security maintenance window.
            """
        else:
            summary_text = f"""
            This security assessment identified {total_vulns} low-severity vulnerabilities. While these 
            issues do not pose immediate threats, addressing them will improve the overall security 
            posture of the application and reduce potential attack surface.
            """
        
        # Add NLP summary if available
        if scan_data.get('nlp_summary'):
            summary_text += f"\n\nAI Analysis: {scan_data['nlp_summary']}"
        
        summary_para = Paragraph(summary_text.strip(), self.styles['ExecutiveSummary'])
        elements.append(summary_para)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Key recommendations
        elements.append(Paragraph("Key Recommendations", self.styles['CustomSubtitle']))
        
        recommendations = [
            "1. Address all high-severity vulnerabilities immediately",
            "2. Implement a regular security testing schedule",
            "3. Conduct code review of identified vulnerable areas",
            "4. Update security policies and procedures based on findings",
            "5. Consider implementing additional security controls"
        ]
        
        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles['VulnerabilityItem']))
        
        return elements
    
    def _create_scan_overview(self, scan_data: Dict[str, Any]) -> List:
        """Create scan overview section"""
        elements = []
        
        elements.append(Paragraph("Scan Overview", self.styles['CustomTitle']))
        
        # Scan methodology
        elements.append(Paragraph("Scan Methodology", self.styles['CustomSubtitle']))
        
        methodology_text = f"""
        This security assessment was conducted using {scan_data.get('scanner', 'WebSecPen')} 
        scanner, which performs comprehensive testing for common web application vulnerabilities 
        including SQL injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), 
        and directory traversal attacks.
        """
        
        elements.append(Paragraph(methodology_text.strip(), self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Scan statistics
        elements.append(Paragraph("Scan Statistics", self.styles['CustomSubtitle']))
        
        stats_data = [
            ['Metric', 'Value'],
            ['Target URL', scan_data.get('target_url', 'N/A')],
            ['Scan Type', scan_data.get('scan_type', 'N/A')],
            ['Duration', self._format_duration(scan_data.get('duration'))],
            ['Pages Scanned', str(scan_data.get('pages_scanned', 'N/A'))],
            ['Requests Made', str(scan_data.get('requests_made', 'N/A'))],
            ['Vulnerabilities Found', str(scan_data.get('vulnerabilities_count', 0))],
            ['Risk Score', f"{scan_data.get('risk_score', 0):.1f}/10"]
        ]
        
        stats_table = Table(stats_data, colWidths=[2.5*inch, 2.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(stats_table)
        
        return elements
    
    def _create_vulnerability_details(self, scan_data: Dict[str, Any]) -> List:
        """Create detailed vulnerability listings"""
        elements = []
        
        elements.append(Paragraph("Vulnerability Details", self.styles['CustomTitle']))
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Group vulnerabilities by severity
        severity_groups = {'High': [], 'Medium': [], 'Low': [], 'Informational': []}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Informational')
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(vuln)
        
        # Create sections for each severity level
        for severity in ['High', 'Medium', 'Low', 'Informational']:
            if severity_groups[severity]:
                elements.append(Paragraph(f"{severity} Severity Vulnerabilities", 
                                        self.styles['CustomSubtitle']))
                
                for i, vuln in enumerate(severity_groups[severity], 1):
                    elements.extend(self._create_vulnerability_item(vuln, i, severity))
                    elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_vulnerability_item(self, vuln: Dict[str, Any], index: int, severity: str) -> List:
        """Create individual vulnerability item"""
        elements = []
        
        # Vulnerability title
        title_style = self.styles.get(f'{severity}Risk', self.styles['Normal'])
        title = Paragraph(f"{index}. {vuln.get('type', 'Unknown Vulnerability')}", title_style)
        elements.append(title)
        
        # Vulnerability details table
        vuln_data = [
            ['URL:', vuln.get('url', 'N/A')],
            ['Parameter:', vuln.get('param', 'N/A')],
            ['Severity:', vuln.get('severity', 'N/A')],
            ['Confidence:', vuln.get('confidence', 'N/A')],
        ]
        
        if vuln.get('cwe_id'):
            vuln_data.append(['CWE ID:', vuln.get('cwe_id')])
        
        vuln_table = Table(vuln_data, colWidths=[1.2*inch, 4*inch])
        vuln_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        
        elements.append(vuln_table)
        
        # Description
        if vuln.get('description'):
            elements.append(Paragraph(f"<b>Description:</b> {vuln['description']}", 
                                    self.styles['VulnerabilityItem']))
        
        # Solution
        if vuln.get('solution'):
            elements.append(Paragraph(f"<b>Recommended Fix:</b> {vuln['solution']}", 
                                    self.styles['VulnerabilityItem']))
        
        return elements
    
    def _create_recommendations(self, scan_data: Dict[str, Any]) -> List:
        """Create recommendations section"""
        elements = []
        
        elements.append(Paragraph("Security Recommendations", self.styles['CustomTitle']))
        
        # General recommendations based on findings
        high_count = scan_data.get('high_severity_count', 0)
        medium_count = scan_data.get('medium_severity_count', 0)
        
        if high_count > 0:
            elements.append(Paragraph("Immediate Actions Required", self.styles['CustomSubtitle']))
            immediate_actions = [
                "Take the application offline or restrict access until high-severity vulnerabilities are fixed",
                "Conduct emergency security review of affected components",
                "Implement temporary security controls as needed",
                "Schedule immediate remediation with development team"
            ]
            for action in immediate_actions:
                elements.append(Paragraph(f"• {action}", self.styles['VulnerabilityItem']))
            
            elements.append(Spacer(1, 0.2*inch))
        
        elements.append(Paragraph("Long-term Security Improvements", self.styles['CustomSubtitle']))
        
        long_term_recs = [
            "Implement secure coding practices and security code reviews",
            "Establish regular security testing schedule (monthly/quarterly)",
            "Provide security training for development team",
            "Implement Web Application Firewall (WAF) for additional protection",
            "Set up continuous security monitoring and alerting",
            "Conduct penetration testing by external security professionals",
            "Implement security headers and content security policies",
            "Regular security updates and patch management process"
        ]
        
        for rec in long_term_recs:
            elements.append(Paragraph(f"• {rec}", self.styles['VulnerabilityItem']))
        
        return elements
    
    def _create_technical_appendix(self, scan_data: Dict[str, Any]) -> List:
        """Create technical appendix"""
        elements = []
        
        elements.append(Paragraph("Technical Appendix", self.styles['CustomTitle']))
        
        # Scan configuration
        elements.append(Paragraph("Scan Configuration", self.styles['CustomSubtitle']))
        
        config = scan_data.get('scan_config', {})
        config_text = f"""
        Scanner: {scan_data.get('scanner', 'WebSecPen')}
        Scan Type: {scan_data.get('scan_type', 'N/A')}
        Start Time: {scan_data.get('created_at', 'N/A')}
        Duration: {self._format_duration(scan_data.get('duration'))}
        Configuration: {config if config else 'Default settings'}
        """
        
        elements.append(Paragraph(config_text.strip(), self.styles['Normal']))
        
        # Disclaimer
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph("Disclaimer", self.styles['CustomSubtitle']))
        
        disclaimer_text = """
        This security assessment report is based on automated scanning tools and may not identify 
        all potential security issues. Manual testing and code review are recommended for comprehensive 
        security evaluation. The findings in this report are accurate as of the scan date and may 
        change as the application evolves. WebSecPen is not responsible for any security incidents 
        that may occur after this assessment.
        """
        
        elements.append(Paragraph(disclaimer_text.strip(), self.styles['Normal']))
        
        return elements
    
    def _format_duration(self, duration_seconds) -> str:
        """Format duration in human-readable format"""
        if not duration_seconds:
            return "N/A"
        
        if isinstance(duration_seconds, str):
            try:
                duration_seconds = float(duration_seconds)
            except:
                return "N/A"
        
        if duration_seconds < 60:
            return f"{duration_seconds:.1f} seconds"
        elif duration_seconds < 3600:
            minutes = duration_seconds / 60
            return f"{minutes:.1f} minutes"
        else:
            hours = duration_seconds / 3600
            return f"{hours:.1f} hours"

# Helper functions for Flask integration
def generate_pdf_report(scan_data: Dict[str, Any], user_data: Dict[str, Any] = None) -> bytes:
    """
    Generate PDF report for a scan
    
    Args:
        scan_data: Scan data from database
        user_data: Optional user data
        
    Returns:
        bytes: PDF file content
    """
    report_generator = WebSecPenPDFReport()
    return report_generator.generate_scan_report(scan_data, user_data) 