# premium_features.py - Payment integration, trends, badges, and CI/CD features
import os
import stripe
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, Scan, Badge

# Initialize Stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

def init_premium_routes(app):
    """Initialize premium feature routes"""
    
    # FEATURE 1: PAYMENT INTEGRATION FOR PREMIUM TIERS
    @app.route('/api/subscription/create-checkout', methods=['POST'])
    @jwt_required()
    def create_checkout_session():
        """Create Stripe checkout session for premium subscription"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        try:
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': os.environ.get('STRIPE_PRICE_ID', 'price_test_123'),  # Replace with actual Price ID
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=f"{os.environ.get('FRONTEND_URL', 'http://localhost:3000')}/success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{os.environ.get('FRONTEND_URL', 'http://localhost:3000')}/cancel",
                client_reference_id=str(user_id),
                customer_email=user.email
            )
            return jsonify({'checkout_url': session.url}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/subscription/status', methods=['GET'])
    @jwt_required()
    def check_subscription():
        """Check user subscription status"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'status': 'active' if user.role == 'premium' else 'inactive',
            'role': user.role,
            'scan_limit': user.scan_limit
        }), 200

    @app.route('/api/webhook/stripe', methods=['POST'])
    def stripe_webhook():
        """Handle Stripe webhook events"""
        payload = request.get_data(as_text=True)
        sig_header = request.headers.get('Stripe-Signature')
        endpoint_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
        except ValueError:
            return jsonify({'error': 'Invalid payload'}), 400
        except stripe.error.SignatureVerificationError:
            return jsonify({'error': 'Invalid signature'}), 400

        # Handle successful subscription
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            user_id = session['client_reference_id']
            
            # Update user to premium
            user = User.query.get(user_id)
            if user:
                user.role = 'premium'
                user.scan_limit = 100  # Premium scan limit
                db.session.commit()
                
                # Award premium badge
                badge = Badge(
                    user_id=user_id,
                    name='Premium User',
                    description='Upgraded to premium subscription'
                )
                db.session.add(badge)
                db.session.commit()

        return jsonify({'status': 'success'}), 200

    # FEATURE 2: VULNERABILITY TREND ANALYSIS
    @app.route('/api/scan/trends', methods=['GET'])
    @jwt_required()
    def get_trends():
        """Get vulnerability trends over time"""
        user_id = get_jwt_identity()
        days = request.args.get('days', 30, type=int)
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        scans = Scan.query.filter(
            Scan.user_id == user_id,
            Scan.created_at >= start_date,
            Scan.status == 'completed'
        ).all()
        
        trends = defaultdict(list)
        daily_counts = defaultdict(lambda: defaultdict(int))
        
        for scan in scans:
            date = scan.created_at.strftime('%Y-%m-%d')
            if scan.results:
                for vuln in scan.results:
                    vuln_type = vuln.get('type', 'Unknown')
                    daily_counts[date][vuln_type] += 1
        
        # Generate date range
        current_date = start_date
        all_dates = []
        while current_date <= end_date:
            all_dates.append(current_date.strftime('%Y-%m-%d'))
            current_date += timedelta(days=1)
        
        # Get all vulnerability types
        all_vuln_types = set()
        for scan in scans:
            if scan.results:
                for vuln in scan.results:
                    all_vuln_types.add(vuln.get('type', 'Unknown'))
        
        # Format data for frontend
        result = {}
        for vuln_type in all_vuln_types:
            result[vuln_type] = []
            for date in all_dates:
                count = daily_counts[date][vuln_type]
                result[vuln_type].append({'date': date, 'count': count})
        
        return jsonify(result), 200

    # FEATURE 4: GAMIFICATION - BADGES
    @app.route('/api/badges', methods=['GET'])
    @jwt_required()
    def get_badges():
        """Get user badges"""
        user_id = get_jwt_identity()
        badges = Badge.query.filter_by(user_id=user_id).order_by(Badge.awarded_at.desc()).all()
        
        return jsonify([badge.to_dict() for badge in badges]), 200

    @app.route('/api/badges/available', methods=['GET'])
    @jwt_required()
    def get_available_badges():
        """Get list of all available badges"""
        available_badges = [
            {'name': 'First Scan', 'description': 'Complete your first security scan'},
            {'name': '10 Scans', 'description': 'Complete 10 security scans'},
            {'name': '50 Scans', 'description': 'Complete 50 security scans'},
            {'name': '100 Scans', 'description': 'Complete 100 security scans'},
            {'name': 'Premium User', 'description': 'Upgrade to premium subscription'},
            {'name': 'Vulnerability Hunter', 'description': 'Find 50+ vulnerabilities'},
            {'name': 'Security Expert', 'description': 'Find critical vulnerabilities'},
        ]
        
        return jsonify(available_badges), 200

    def award_badge_if_eligible(user_id, scan_count):
        """Award badges based on scan milestones"""
        milestone_badges = {
            1: ('First Scan', 'Complete your first security scan'),
            10: ('10 Scans', 'Complete 10 security scans'),
            50: ('50 Scans', 'Complete 50 security scans'),
            100: ('100 Scans', 'Complete 100 security scans')
        }
        
        if scan_count in milestone_badges:
            name, description = milestone_badges[scan_count]
            
            # Check if badge already exists
            existing_badge = Badge.query.filter_by(user_id=user_id, name=name).first()
            if not existing_badge:
                badge = Badge(
                    user_id=user_id,
                    name=name,
                    description=description
                )
                db.session.add(badge)
                db.session.commit()
                return badge.to_dict()
        
        return None

    # Update existing scan start endpoint to include badge logic
    def enhance_scan_start(original_func):
        """Decorator to enhance scan start with badge logic"""
        def wrapper(*args, **kwargs):
            result = original_func(*args, **kwargs)
            
            # Award badges after successful scan creation
            if isinstance(result, tuple) and len(result) == 2 and result[1] == 201:
                user_id = get_jwt_identity()
                scan_count = Scan.query.filter_by(user_id=user_id).count()
                new_badge = award_badge_if_eligible(user_id, scan_count)
                
                # Add badge info to response if awarded
                if new_badge and isinstance(result[0].get_json(), dict):
                    response_data = result[0].get_json()
                    response_data['badge_awarded'] = new_badge
                    return jsonify(response_data), result[1]
            
            return result
        return wrapper

    return {
        'award_badge_if_eligible': award_badge_if_eligible,
        'enhance_scan_start': enhance_scan_start
    }
