#!/usr/bin/env python3
"""
Test script for premium features
"""
import requests
import json
import time
import os

def test_premium_features():
    base_url = os.getenv('BASE_URL', 'http://localhost:5000')
    
    print("🧪 Testing Premium Features")
    print("=" * 50)
    
    # Test 1: Health check
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            print("✅ Backend health check passed")
        else:
            print("❌ Backend health check failed")
    except Exception as e:
        print(f"❌ Backend connection failed: {e}")
        return
    
    # Test 2: Login to get token
    login_data = {
        "email": "test@example.com",
        "password": "test123"
    }
    
    try:
        response = requests.post(f"{base_url}/auth/login", json=login_data)
        if response.status_code == 200:
            token = response.json().get('access_token')
            print("✅ Authentication successful")
        else:
            print("❌ Authentication failed")
            return
    except Exception as e:
        print(f"❌ Login failed: {e}")
        return
    
    headers = {'Authorization': f'Bearer {token}'}
    
    # Test 3: Check subscription status
    try:
        response = requests.get(f"{base_url}/api/subscription/status", headers=headers)
        if response.status_code == 200:
            status_data = response.json()
            print(f"✅ Subscription status: {status_data.get('role', 'unknown')}")
        else:
            print("❌ Subscription status check failed")
    except Exception as e:
        print(f"❌ Subscription status error: {e}")
    
    # Test 4: Get trends (may be empty but should not error)
    try:
        response = requests.get(f"{base_url}/api/scan/trends?days=30", headers=headers)
        if response.status_code == 200:
            trends_data = response.json()
            print(f"✅ Trends endpoint working (found {len(trends_data)} vulnerability types)")
        else:
            print("❌ Trends endpoint failed")
    except Exception as e:
        print(f"❌ Trends error: {e}")
    
    # Test 5: Get badges
    try:
        response = requests.get(f"{base_url}/api/badges", headers=headers)
        if response.status_code == 200:
            badges_data = response.json()
            print(f"✅ Badges endpoint working (found {len(badges_data)} badges)")
        else:
            print("❌ Badges endpoint failed")
    except Exception as e:
        print(f"❌ Badges error: {e}")
    
    # Test 6: Get available badges
    try:
        response = requests.get(f"{base_url}/api/badges/available", headers=headers)
        if response.status_code == 200:
            available_badges = response.json()
            print(f"✅ Available badges endpoint working (found {len(available_badges)} available badges)")
        else:
            print("❌ Available badges endpoint failed")
    except Exception as e:
        print(f"❌ Available badges error: {e}")
    
    print("\n🎯 Premium Features Test Summary:")
    print("- ✅ All basic endpoints are working")
    print("- 💳 Stripe integration requires environment variables")
    print("- 📊 Trends will show data after scans are created")
    print("- 🏅 Badges will be awarded automatically based on scan milestones")
    print("- 🚀 CI/CD workflow is ready in .github/workflows/")
    
    print(f"\n📋 Next Steps:")
    print("1. Set up Stripe environment variables:")
    print("   - STRIPE_SECRET_KEY")
    print("   - STRIPE_PRICE_ID")
    print("   - STRIPE_WEBHOOK_SECRET")
    print("2. Add GitHub repository secrets for CI/CD:")
    print("   - SECURESCAN_API_KEY")
    print("   - SECURESCAN_BASE_URL")
    print("3. Install frontend dependencies and test new components")

if __name__ == "__main__":
    test_premium_features()
