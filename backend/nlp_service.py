# nlp_service.py - Intelligent Vulnerability Analysis with HuggingFace
import os
import logging
from typing import List, Dict, Any
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    logger.warning("Transformers not available. Install with: pip install transformers torch")
    TRANSFORMERS_AVAILABLE = False

class VulnerabilityNLPAnalyzer:
    """
    Advanced NLP analyzer for security vulnerabilities using HuggingFace models
    """
    
    def __init__(self):
        self.summarizer = None
        self.classifier = None
        self.sentiment_analyzer = None
        self.initialized = False
        
        if TRANSFORMERS_AVAILABLE:
            self._initialize_models()
    
    def _initialize_models(self):
        """Initialize HuggingFace models for various NLP tasks"""
        try:
            logger.info("Initializing HuggingFace NLP models...")
            
            # Summarization model for vulnerability descriptions
            self.summarizer = pipeline(
                'summarization',
                model='facebook/bart-large-cnn',
                tokenizer='facebook/bart-large-cnn'
            )
            
            # Text classification for vulnerability severity and prioritization
            self.classifier = pipeline(
                'text-classification',
                model='distilbert-base-uncased-finetuned-sst-2-english'
            )
            
            # Enhanced classifier for security risk assessment
            self.risk_classifier = pipeline(
                'zero-shot-classification',
                model='facebook/bart-large-mnli'
            )
            
            # Sentiment analysis for risk assessment
            self.sentiment_analyzer = pipeline(
                'sentiment-analysis',
                model='cardiffnlp/twitter-roberta-base-sentiment-latest'
            )
            
            self.initialized = True
            logger.info("✅ NLP models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize NLP models: {str(e)}")
            self.initialized = False
    
    def analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Comprehensive NLP analysis of vulnerability scan results
        """
        if not vulnerabilities:
            return {
                'summary': 'No vulnerabilities detected in the scan.',
                'risk_assessment': 'Low',
                'recommendations': ['Continue regular security monitoring'],
                'technical_analysis': 'Clean scan - no security issues found',
                'executive_summary': 'The application passed security scanning with no vulnerabilities detected.'
            }
        
        # Fallback analysis if transformers not available
        if not TRANSFORMERS_AVAILABLE or not self.initialized:
            return self._fallback_analysis(vulnerabilities)
        
        try:
            return self._advanced_nlp_analysis(vulnerabilities)
        except Exception as e:
            logger.error(f"NLP analysis failed: {str(e)}")
            return self._fallback_analysis(vulnerabilities)
    
    def _advanced_nlp_analysis(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Advanced NLP analysis using HuggingFace models"""
        
        # Prepare vulnerability text for analysis
        vuln_descriptions = []
        risk_indicators = []
        
        for vuln in vulnerabilities:
            desc = f"{vuln.get('name', 'Unknown vulnerability')}: {vuln.get('description', 'No description available')}"
            vuln_descriptions.append(desc)
            
            # Extract risk indicators
            severity = vuln.get('risk_level', 'Low').lower()
            confidence = vuln.get('confidence', 0)
            risk_indicators.append(f"{severity} severity vulnerability with {confidence}% confidence")
        
        # Combine all descriptions for summarization
        full_text = ". ".join(vuln_descriptions)
        
        # Generate summary using BART
        if len(full_text) > 100:  # Only summarize if there's substantial content
            try:
                summary_result = self.summarizer(
                    full_text, 
                    max_length=150, 
                    min_length=50, 
                    do_sample=False
                )
                summary = summary_result[0]['summary_text']
            except Exception as e:
                logger.warning(f"Summarization failed: {e}")
                summary = self._generate_manual_summary(vulnerabilities)
        else:
            summary = full_text
        
        # Risk assessment using sentiment analysis
        risk_text = ". ".join(risk_indicators)
        try:
            sentiment_result = self.sentiment_analyzer(risk_text)
            risk_assessment = self._interpret_risk_sentiment(sentiment_result[0])
        except Exception as e:
            logger.warning(f"Risk assessment failed: {e}")
            risk_assessment = self._calculate_manual_risk(vulnerabilities)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities)
        
        # Technical analysis
        technical_analysis = self._generate_technical_analysis(vulnerabilities)
        
        # Executive summary
        executive_summary = self._generate_executive_summary(vulnerabilities, summary)
        
        return {
            'summary': summary,
            'risk_assessment': risk_assessment,
            'recommendations': recommendations,
            'technical_analysis': technical_analysis,
            'executive_summary': executive_summary,
            'vulnerability_count': len(vulnerabilities),
            'severity_breakdown': self._get_severity_breakdown(vulnerabilities)
        }
    
    def _fallback_analysis(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Fallback analysis when NLP models are not available"""
        
        high_count = len([v for v in vulnerabilities if v.get('risk_level', '').lower() == 'high'])
        medium_count = len([v for v in vulnerabilities if v.get('risk_level', '').lower() == 'medium'])
        low_count = len([v for v in vulnerabilities if v.get('risk_level', '').lower() == 'low'])
        
        # Generate basic summary
        summary = f"Security scan detected {len(vulnerabilities)} vulnerabilities: "
        summary += f"{high_count} high, {medium_count} medium, {low_count} low severity issues."
        
        # Risk assessment
        if high_count > 0:
            risk_assessment = "High"
        elif medium_count > 2:
            risk_assessment = "Medium-High"
        elif medium_count > 0:
            risk_assessment = "Medium"
        else:
            risk_assessment = "Low"
        
        # Basic recommendations
        recommendations = self._generate_recommendations(vulnerabilities)
        
        return {
            'summary': summary,
            'risk_assessment': risk_assessment,
            'recommendations': recommendations,
            'technical_analysis': self._generate_technical_analysis(vulnerabilities),
            'executive_summary': self._generate_executive_summary(vulnerabilities, summary),
            'vulnerability_count': len(vulnerabilities),
            'severity_breakdown': self._get_severity_breakdown(vulnerabilities)
        }
    
    def _generate_manual_summary(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate summary without NLP models"""
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('name', 'Unknown').split()[0]  # Get first word as type
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        if len(vuln_types) == 1:
            vuln_type = list(vuln_types.keys())[0]
            return f"Multiple {vuln_type} vulnerabilities detected requiring immediate attention."
        else:
            types_str = ", ".join([f"{count} {vtype}" for vtype, count in vuln_types.items()])
            return f"Mixed vulnerability types found: {types_str}. Comprehensive remediation needed."
    
    def _interpret_risk_sentiment(self, sentiment_result: Dict[str, Any]) -> str:
        """Interpret sentiment analysis results for risk assessment"""
        label = sentiment_result.get('label', 'NEUTRAL')
        score = sentiment_result.get('score', 0.5)
        
        if label == 'NEGATIVE' and score > 0.8:
            return "Critical"
        elif label == 'NEGATIVE' and score > 0.6:
            return "High"
        elif label == 'NEGATIVE':
            return "Medium"
        else:
            return "Low"
    
    def _calculate_manual_risk(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Manual risk calculation based on vulnerability data"""
        risk_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('risk_level', 'Low').lower()
            confidence = vuln.get('confidence', 50)
            
            if severity == 'high':
                risk_score += 3 * (confidence / 100)
            elif severity == 'medium':
                risk_score += 2 * (confidence / 100)
            elif severity == 'low':
                risk_score += 1 * (confidence / 100)
        
        if risk_score > 3:
            return "Critical"
        elif risk_score > 2:
            return "High"
        elif risk_score > 1:
            return "Medium"
        else:
            return "Low"
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        vuln_types = set()
        
        for vuln in vulnerabilities:
            name = vuln.get('name', '').lower()
            if 'xss' in name or 'cross-site' in name:
                vuln_types.add('xss')
            elif 'sql' in name or 'injection' in name:
                vuln_types.add('sqli')
            elif 'csrf' in name or 'cross-site request' in name:
                vuln_types.add('csrf')
            elif 'directory' in name or 'traversal' in name:
                vuln_types.add('directory')
        
        if 'xss' in vuln_types:
            recommendations.append("Implement proper input validation and output encoding to prevent XSS attacks")
            recommendations.append("Use Content Security Policy (CSP) headers to mitigate XSS risks")
        
        if 'sqli' in vuln_types:
            recommendations.append("Use parameterized queries and prepared statements to prevent SQL injection")
            recommendations.append("Implement input validation and sanitization for all user inputs")
        
        if 'csrf' in vuln_types:
            recommendations.append("Implement CSRF tokens for all state-changing operations")
            recommendations.append("Validate origin and referrer headers for sensitive requests")
        
        if 'directory' in vuln_types:
            recommendations.append("Implement proper file access controls and path validation")
            recommendations.append("Use whitelist-based file access restrictions")
        
        # General recommendations
        recommendations.extend([
            "Conduct regular security code reviews and penetration testing",
            "Keep all frameworks and dependencies updated to latest security patches",
            "Implement comprehensive logging and monitoring for security events"
        ])
        
        return recommendations[:6]  # Return top 6 recommendations
    
    def _generate_technical_analysis(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate technical analysis of vulnerabilities"""
        if not vulnerabilities:
            return "No technical security issues identified in the scan."
        
        analysis_parts = []
        
        # Analyze vulnerability distribution
        severity_counts = self._get_severity_breakdown(vulnerabilities)
        analysis_parts.append(f"Vulnerability distribution: {severity_counts}")
        
        # Analyze common attack vectors
        attack_vectors = {}
        for vuln in vulnerabilities:
            method = vuln.get('method', 'Unknown')
            attack_vectors[method] = attack_vectors.get(method, 0) + 1
        
        if attack_vectors:
            common_vectors = sorted(attack_vectors.items(), key=lambda x: x[1], reverse=True)[:3]
            analysis_parts.append(f"Primary attack vectors: {dict(common_vectors)}")
        
        # Analyze affected parameters
        params = set()
        for vuln in vulnerabilities:
            if vuln.get('parameter'):
                params.add(vuln.get('parameter'))
        
        if params:
            analysis_parts.append(f"Affected parameters: {', '.join(list(params)[:5])}")
        
        return ". ".join(analysis_parts) + "."
    
    def _generate_executive_summary(self, vulnerabilities: List[Dict[str, Any]], technical_summary: str) -> str:
        """Generate executive summary for management"""
        if not vulnerabilities:
            return "The security assessment completed successfully with no vulnerabilities detected. The application demonstrates good security posture."
        
        high_count = len([v for v in vulnerabilities if v.get('risk_level', '').lower() == 'high'])
        total_count = len(vulnerabilities)
        
        if high_count > 0:
            exec_summary = f"URGENT: Security assessment identified {total_count} vulnerabilities, including {high_count} high-severity issues requiring immediate remediation. "
        elif total_count > 5:
            exec_summary = f"Security assessment found {total_count} vulnerabilities requiring attention. "
        else:
            exec_summary = f"Security assessment identified {total_count} minor vulnerabilities. "
        
        exec_summary += "Recommend prioritizing fixes based on severity and implementing comprehensive security controls."
        
        return exec_summary
    
    def _get_severity_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by severity"""
        breakdown = {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('risk_level', 'Low')
            if severity in breakdown:
                breakdown[severity] += 1
            else:
                breakdown['Info'] += 1
        
        return breakdown

# Global NLP analyzer instance
nlp_analyzer = VulnerabilityNLPAnalyzer()

def analyze_scan_results(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Main function to analyze vulnerability scan results with NLP and prioritization
    """
    # Get basic NLP analysis
    analysis = nlp_analyzer.analyze_vulnerabilities(vulnerabilities)
    
    # Add intelligent prioritization
    prioritized_vulns = prioritize_vulnerabilities(vulnerabilities)
    
    # Enhanced analysis with prioritization data
    if prioritized_vulns:
        analysis['prioritized_vulnerabilities'] = prioritized_vulns[:10]  # Top 10 most critical
        analysis['total_critical'] = len([v for v in prioritized_vulns if v.get('threat_level') == 'critical'])
        analysis['total_high'] = len([v for v in prioritized_vulns if v.get('threat_level') == 'high'])
        analysis['avg_priority_score'] = sum(v.get('priority_score', 0) for v in prioritized_vulns) / len(prioritized_vulns)
        analysis['highest_priority'] = prioritized_vulns[0] if prioritized_vulns else None
    
    return analysis

def prioritize_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Intelligently prioritize vulnerabilities using NLP analysis
    """
    return nlp_analyzer.prioritize_vulnerabilities(vulnerabilities) 