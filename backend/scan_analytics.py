from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from models import Scan

def init_scan_analytics_routes(app, limiter):
    """Initialize scan analytics routes"""
    
    @app.route('/scan/trends', methods=['GET'])
    @jwt_required()
    @limiter.limit("10 per minute")
    def scan_trends_api():
        """Get vulnerability trends over time"""
        try:
            user_id = get_jwt_identity()
            days = int(request.args.get('days', 30))
            
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Get scans in date range
            scans = Scan.query.filter_by(user_id=user_id)\
                             .filter(Scan.created_at >= start_date)\
                             .filter(Scan.created_at <= end_date)\
                             .order_by(Scan.created_at.asc())\
                             .all()
            
            # Group scans by date and calculate trends
            trends_data = {}
            for scan in scans:
                date_key = scan.created_at.strftime('%Y-%m-%d')
                if date_key not in trends_data:
                    trends_data[date_key] = {
                        'date': date_key,
                        'scans': 0,
                        'vulnerabilities': 0,
                        'high_severity': 0,
                        'medium_severity': 0,
                        'low_severity': 0
                    }
                
                trends_data[date_key]['scans'] += 1
                trends_data[date_key]['vulnerabilities'] += scan.vulnerabilities_count or 0
                trends_data[date_key]['high_severity'] += scan.high_severity_count or 0
                trends_data[date_key]['medium_severity'] += scan.medium_severity_count or 0
                trends_data[date_key]['low_severity'] += scan.low_severity_count or 0
            
            # Convert to list and sort by date
            trends_list = list(trends_data.values())
            trends_list.sort(key=lambda x: x['date'])
            
            return jsonify({
                'trends': trends_list,
                'period': f'{days} days',
                'total_scans': len(scans),
                'total_vulnerabilities': sum(scan.vulnerabilities_count or 0 for scan in scans)
            }), 200
            
        except Exception as e:
            print(f"Trends error: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/scan/severity', methods=['GET'])
    @jwt_required()
    @limiter.limit("10 per minute")
    def scan_severity_api():
        """Get vulnerability severity breakdown"""
        try:
            user_id = get_jwt_identity()
            
            # Get all completed scans for user
            scans = Scan.query.filter_by(user_id=user_id, status='completed').all()
            
            # Calculate totals
            total_scans = len(scans)
            total_high = sum(scan.high_severity_count or 0 for scan in scans)
            total_medium = sum(scan.medium_severity_count or 0 for scan in scans)
            total_low = sum(scan.low_severity_count or 0 for scan in scans)
            total_vulnerabilities = total_high + total_medium + total_low
            
            # Calculate percentages
            high_percentage = (total_high / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0
            medium_percentage = (total_medium / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0
            low_percentage = (total_low / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0
            
            return jsonify({
                'severity_breakdown': {
                    'high': {
                        'count': total_high,
                        'percentage': round(high_percentage, 1)
                    },
                    'medium': {
                        'count': total_medium,
                        'percentage': round(medium_percentage, 1)
                    },
                    'low': {
                        'count': total_low,
                        'percentage': round(low_percentage, 1)
                    }
                },
                'totals': {
                    'scans': total_scans,
                    'vulnerabilities': total_vulnerabilities
                },
                'risk_distribution': [
                    {'severity': 'High', 'count': total_high, 'color': '#ef4444'},
                    {'severity': 'Medium', 'count': total_medium, 'color': '#f59e0b'},
                    {'severity': 'Low', 'count': total_low, 'color': '#3b82f6'}
                ]
            }), 200
            
        except Exception as e:
            print(f"Severity breakdown error: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500 