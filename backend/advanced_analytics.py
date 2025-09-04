# advanced_analytics.py - Advanced Analytics Service
# Temporarily simplified to avoid import errors

import json
from datetime import datetime, timedelta
from flask import jsonify
from models import db, User, Scan, Vulnerability

def get_analytics_data():
    """Get basic analytics data"""
    try:
        # Basic stats
        total_users = User.query.count()
        total_scans = Scan.query.count()
        total_vulnerabilities = Vulnerability.query.count()
        
        return {
            'total_users': total_users,
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'status': 'success'
        }
    except Exception as e:
        return {
            'error': str(e),
            'status': 'error'
        }

def get_scan_trends():
    """Get scan trends over time"""
    try:
        # Get scans from last 30 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        scans = Scan.query.filter(
            Scan.created_at >= start_date
        ).all()
        
        trends = []
        for scan in scans:
            trends.append({
                'date': scan.created_at.strftime('%Y-%m-%d'),
                'scan_id': scan.id,
                'url': scan.url
            })
        
        return {
            'trends': trends,
            'status': 'success'
        }
    except Exception as e:
        return {
            'error': str(e),
            'status': 'error'
        }


def init_advanced_analytics():
    """Initialize advanced analytics service"""
    try:
        print('✅ Advanced analytics service initialized')
        return True
    except Exception as e:
        print(f'❌ Advanced analytics initialization error: {e}')
        return False


def init_advanced_routes(app):
    """Initialize advanced analytics routes"""
    try:
        @app.route('/api/analytics/basic', methods=['GET'])
        def get_basic_analytics():
            return jsonify(get_analytics_data())
        
        @app.route('/api/analytics/trends', methods=['GET'])
        def get_scan_trends_route():
            return jsonify(get_scan_trends())
        
        print('✅ Advanced analytics routes initialized')
        return True
    except Exception as e:
        print(f'❌ Advanced analytics routes initialization error: {e}')
        return False
