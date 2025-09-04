# nlp_service.py - NLP Service
# Temporarily simplified to avoid import errors

import json
from datetime import datetime
from flask import jsonify

def init_nlp_service():
    """Initialize NLP service"""
    try:
        print('✅ NLP service initialized (simplified)')
        return True
    except Exception as e:
        print(f'❌ NLP service initialization error: {e}')
        return False

def analyze_sentiment(text):
    """Analyze sentiment of text"""
    try:
        # Simple sentiment analysis (placeholder)
        if any(word in text.lower() for word in ['good', 'great', 'excellent', 'amazing']):
            return {'label': 'POSITIVE', 'score': 0.8}
        elif any(word in text.lower() for word in ['bad', 'terrible', 'awful', 'horrible']):
            return {'label': 'NEGATIVE', 'score': 0.8}
        else:
            return {'label': 'NEUTRAL', 'score': 0.5}
    except Exception as e:
        return {'label': 'NEUTRAL', 'score': 0.5, 'error': str(e)}

def generate_recommendations(vulnerability_data):
    """Generate recommendations for vulnerabilities"""
    try:
        recommendations = []
        for vuln in vulnerability_data:
            if vuln.get('type') == 'XSS':
                recommendations.append({
                    'type': 'XSS',
                    'recommendation': 'Implement proper input validation and output encoding'
                })
            elif vuln.get('type') == 'SQL Injection':
                recommendations.append({
                    'type': 'SQL Injection',
                    'recommendation': 'Use parameterized queries and prepared statements'
                })
            else:
                recommendations.append({
                    'type': vuln.get('type', 'Unknown'),
                    'recommendation': 'Review and fix the identified security issue'
                })
        return recommendations
    except Exception as e:
        return [{'type': 'Error', 'recommendation': f'Error generating recommendations: {e}'}]


def analyze_scan_results(scan_results):
    """Analyze scan results and provide insights"""
    try:
        if not scan_results:
            return {'insights': [], 'recommendations': []}
        
        insights = []
        recommendations = []
        
        for result in scan_results:
            if result.get('severity') == 'HIGH':
                insights.append('High severity vulnerability detected')
                recommendations.append('Immediate action required')
            elif result.get('severity') == 'MEDIUM':
                insights.append('Medium severity vulnerability detected')
                recommendations.append('Schedule remediation')
            else:
                insights.append('Low severity vulnerability detected')
                recommendations.append('Monitor and plan remediation')
        
        return {
            'insights': insights,
            'recommendations': recommendations,
            'status': 'success'
        }
    except Exception as e:
        return {
            'insights': [],
            'recommendations': [],
            'error': str(e),
            'status': 'error'
        }
