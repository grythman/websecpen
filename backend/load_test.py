#!/usr/bin/env python3
# load_test.py - Load Testing Script for WebSecPen Backend
import os
import sys
import time
import json
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
import requests
from datetime import datetime

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class WebSecPenLoadTester:
    """
    Comprehensive load testing for WebSecPen backend
    Tests authentication, scan endpoints, and analytics under load
    """
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url.rstrip('/')
        self.test_users = []
        self.results = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'response_times': [],
            'errors': [],
            'test_start': None,
            'test_end': None
        }
    
    def setup_test_users(self, count: int = 5):
        """Create test users for load testing"""
        print(f"🔧 Setting up {count} test users...")
        
        for i in range(count):
            user_data = {
                'email': f'loadtest_{i}@example.com',
                'password': f'test123_{i}',
                'name': f'LoadTest User {i}'
            }
            
            try:
                # Register test user
                response = requests.post(
                    f"{self.base_url}/auth/register",
                    json=user_data,
                    timeout=10
                )
                
                if response.status_code in [200, 201]:
                    # Login to get token
                    login_response = requests.post(
                        f"{self.base_url}/auth/login",
                        json={'email': user_data['email'], 'password': user_data['password']},
                        timeout=10
                    )
                    
                    if login_response.status_code == 200:
                        token = login_response.json().get('access_token')
                        user_data['token'] = token
                        self.test_users.append(user_data)
                        print(f"✅ Created user {i+1}: {user_data['email']}")
                    else:
                        print(f"❌ Failed to login user {i+1}: {login_response.status_code}")
                else:
                    print(f"❌ Failed to register user {i+1}: {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Error creating user {i+1}: {e}")
        
        print(f"✅ Successfully created {len(self.test_users)} test users")
        return len(self.test_users)
    
    def make_request(self, method: str, endpoint: str, user_data: Dict, 
                    payload: Dict = None, description: str = "") -> Dict[str, Any]:
        """Make a single API request and track metrics"""
        start_time = time.time()
        
        headers = {
            'Authorization': f"Bearer {user_data['token']}",
            'Content-Type': 'application/json'
        }
        
        try:
            if method.upper() == 'GET':
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    timeout=30
                )
            elif method.upper() == 'POST':
                response = requests.post(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    json=payload,
                    timeout=30
                )
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            self.results['total_requests'] += 1
            self.results['response_times'].append(response_time)
            
            if response.status_code < 400:
                self.results['successful_requests'] += 1
                return {
                    'success': True,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'description': description,
                    'user': user_data['email']
                }
            else:
                self.results['failed_requests'] += 1
                error_info = {
                    'success': False,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'error': response.text[:200],
                    'description': description,
                    'user': user_data['email']
                }
                self.results['errors'].append(error_info)
                return error_info
                
        except Exception as e:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            self.results['total_requests'] += 1
            self.results['failed_requests'] += 1
            
            error_info = {
                'success': False,
                'status_code': 0,
                'response_time': response_time,
                'error': str(e),
                'description': description,
                'user': user_data['email']
            }
            self.results['errors'].append(error_info)
            return error_info
    
    def test_authentication_load(self, concurrent_users: int = 10, requests_per_user: int = 5):
        """Test authentication endpoints under load"""
        print(f"\n🔐 Testing authentication load: {concurrent_users} users, {requests_per_user} requests each")
        
        def auth_test_worker(user_index: int):
            results = []
            user = self.test_users[user_index % len(self.test_users)]
            
            for i in range(requests_per_user):
                # Test profile endpoint
                result = self.make_request(
                    'GET', 
                    '/auth/profile', 
                    user,
                    description=f"Profile check {i+1}"
                )
                results.append(result)
                
                # Small delay between requests
                time.sleep(0.1)
            
            return results
        
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(auth_test_worker, i) for i in range(concurrent_users)]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"❌ Auth test worker failed: {e}")
    
    def test_scan_endpoints_load(self, concurrent_users: int = 10, scans_per_user: int = 3):
        """Test scan endpoints under load"""
        print(f"\n🔍 Testing scan endpoints load: {concurrent_users} users, {scans_per_user} scans each")
        
        scan_targets = [
            {'url': 'http://localhost:8080', 'scan_type': 'XSS'},
            {'url': 'http://localhost:8080/xss', 'scan_type': 'XSS'},
            {'url': 'http://localhost:8080/sqli', 'scan_type': 'SQLi'},
            {'url': 'http://example.com', 'scan_type': 'comprehensive'},
            {'url': 'http://httpbin.org', 'scan_type': 'CSRF'}
        ]
        
        def scan_test_worker(user_index: int):
            results = []
            user = self.test_users[user_index % len(self.test_users)]
            
            for i in range(scans_per_user):
                scan_data = scan_targets[i % len(scan_targets)]
                
                # Start scan
                result = self.make_request(
                    'POST',
                    '/scan/start',
                    user,
                    payload=scan_data,
                    description=f"Start scan {i+1} ({scan_data['scan_type']})"
                )
                results.append(result)
                
                # Test scan list endpoint
                list_result = self.make_request(
                    'GET',
                    '/scans',
                    user,
                    description=f"List scans {i+1}"
                )
                results.append(list_result)
                
                # Small delay between requests
                time.sleep(0.2)
            
            return results
        
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(scan_test_worker, i) for i in range(concurrent_users)]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"❌ Scan test worker failed: {e}")
    
    def test_analytics_load(self, concurrent_users: int = 5, requests_per_user: int = 10):
        """Test analytics endpoints under load"""
        print(f"\n📊 Testing analytics load: {concurrent_users} users, {requests_per_user} requests each")
        
        def analytics_test_worker(user_index: int):
            results = []
            user = self.test_users[0]  # Use first user (assuming admin)
            
            for i in range(requests_per_user):
                # Test analytics endpoint
                result = self.make_request(
                    'GET',
                    '/admin/analytics',
                    user,
                    description=f"Analytics request {i+1}"
                )
                results.append(result)
                
                # Test dashboard endpoint
                dashboard_result = self.make_request(
                    'GET',
                    '/admin/dashboard',
                    user,
                    description=f"Dashboard request {i+1}"
                )
                results.append(dashboard_result)
                
                # Small delay between requests
                time.sleep(0.1)
            
            return results
        
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(analytics_test_worker, i) for i in range(concurrent_users)]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"❌ Analytics test worker failed: {e}")
    
    def test_feedback_load(self, concurrent_users: int = 8, feedback_per_user: int = 2):
        """Test feedback endpoints under load"""
        print(f"\n💬 Testing feedback load: {concurrent_users} users, {feedback_per_user} feedback each")
        
        feedback_templates = [
            {'feedback': 'Great platform! Love the AI analysis.', 'type': 'general'},
            {'feedback': 'Found a bug in the scan progress display.', 'type': 'bug'},
            {'feedback': 'Would love to see more scan types.', 'type': 'feature'},
            {'feedback': 'The dashboard is very responsive.', 'type': 'general'},
            {'feedback': 'Scanning could be faster.', 'type': 'performance'}
        ]
        
        def feedback_test_worker(user_index: int):
            results = []
            user = self.test_users[user_index % len(self.test_users)]
            
            for i in range(feedback_per_user):
                feedback_data = feedback_templates[i % len(feedback_templates)]
                
                # Submit feedback
                result = self.make_request(
                    'POST',
                    '/feedback',
                    user,
                    payload=feedback_data,
                    description=f"Submit feedback {i+1}"
                )
                results.append(result)
                
                # Small delay between requests
                time.sleep(0.1)
            
            return results
        
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(feedback_test_worker, i) for i in range(concurrent_users)]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"❌ Feedback test worker failed: {e}")
    
    def run_comprehensive_load_test(self):
        """Run a comprehensive load test covering all endpoints"""
        print("🚀 WEBSECPEN COMPREHENSIVE LOAD TEST")
        print("=" * 60)
        
        self.results['test_start'] = datetime.now()
        
        # Setup test environment
        if not self.test_users:
            user_count = self.setup_test_users(5)
            if user_count == 0:
                print("❌ No test users available. Cannot proceed with load test.")
                return
        
        print(f"\n🎯 Starting load test with {len(self.test_users)} users")
        print(f"📍 Target: {self.base_url}")
        
        # Run load tests
        try:
            self.test_authentication_load(concurrent_users=10, requests_per_user=5)
            time.sleep(2)
            
            self.test_scan_endpoints_load(concurrent_users=8, scans_per_user=2)
            time.sleep(2)
            
            self.test_feedback_load(concurrent_users=6, feedback_per_user=2)
            time.sleep(1)
            
            # Test analytics if first user has admin privileges
            self.test_analytics_load(concurrent_users=3, requests_per_user=5)
            
        except KeyboardInterrupt:
            print("\n⚠️ Load test interrupted by user")
        except Exception as e:
            print(f"\n❌ Load test failed: {e}")
        
        self.results['test_end'] = datetime.now()
        
        # Generate comprehensive report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive load test report"""
        print("\n" + "=" * 60)
        print("📊 LOAD TEST RESULTS")
        print("=" * 60)
        
        # Basic statistics
        total_requests = self.results['total_requests']
        successful_requests = self.results['successful_requests']
        failed_requests = self.results['failed_requests']
        success_rate = (successful_requests / total_requests * 100) if total_requests > 0 else 0
        
        print(f"📈 REQUEST STATISTICS:")
        print(f"   Total Requests: {total_requests}")
        print(f"   Successful: {successful_requests}")
        print(f"   Failed: {failed_requests}")
        print(f"   Success Rate: {success_rate:.2f}%")
        
        # Response time statistics
        if self.results['response_times']:
            response_times = self.results['response_times']
            print(f"\n⏱️ RESPONSE TIME STATISTICS:")
            print(f"   Average: {statistics.mean(response_times):.2f}ms")
            print(f"   Median: {statistics.median(response_times):.2f}ms")
            print(f"   Min: {min(response_times):.2f}ms")
            print(f"   Max: {max(response_times):.2f}ms")
            print(f"   95th Percentile: {sorted(response_times)[int(len(response_times) * 0.95)]:.2f}ms")
        
        # Test duration
        if self.results['test_start'] and self.results['test_end']:
            duration = self.results['test_end'] - self.results['test_start']
            print(f"\n🕐 TEST DURATION: {duration}")
            
            # Calculate requests per second
            rps = total_requests / duration.total_seconds()
            print(f"   Requests per Second: {rps:.2f}")
        
        # Error analysis
        if self.results['errors']:
            print(f"\n❌ ERROR ANALYSIS:")
            error_codes = {}
            for error in self.results['errors']:
                code = error.get('status_code', 'Unknown')
                error_codes[code] = error_codes.get(code, 0) + 1
            
            for code, count in error_codes.items():
                print(f"   Status {code}: {count} errors")
            
            # Show sample errors
            print(f"\n📝 SAMPLE ERRORS:")
            for error in self.results['errors'][:5]:
                print(f"   {error['description']}: {error['error'][:100]}")
        
        # Performance assessment
        print(f"\n🎯 PERFORMANCE ASSESSMENT:")
        if success_rate >= 95:
            print("   ✅ EXCELLENT - System handled load very well")
        elif success_rate >= 90:
            print("   🟡 GOOD - System performed well with minor issues")
        elif success_rate >= 80:
            print("   🟠 FAIR - System needs optimization")
        else:
            print("   🔴 POOR - System requires significant improvements")
        
        avg_response_time = statistics.mean(self.results['response_times']) if self.results['response_times'] else 0
        if avg_response_time < 500:
            print("   ⚡ Response times are excellent (< 500ms)")
        elif avg_response_time < 1000:
            print("   🟡 Response times are acceptable (< 1000ms)")
        elif avg_response_time < 2000:
            print("   🟠 Response times need improvement (< 2000ms)")
        else:
            print("   🔴 Response times are too slow (> 2000ms)")
        
        print("\n" + "=" * 60)
        print("🎉 LOAD TEST COMPLETE")
        print("=" * 60)

def main():
    """Main function for running load tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description='WebSecPen Load Testing')
    parser.add_argument('--url', default='http://localhost:5000', help='Backend URL')
    parser.add_argument('--users', type=int, default=5, help='Number of test users')
    parser.add_argument('--quick', action='store_true', help='Run quick test')
    
    args = parser.parse_args()
    
    tester = WebSecPenLoadTester(args.url)
    
    if args.quick:
        print("🚀 Running quick load test...")
        tester.setup_test_users(2)
        tester.test_authentication_load(concurrent_users=3, requests_per_user=2)
        tester.generate_report()
    else:
        tester.run_comprehensive_load_test()

if __name__ == '__main__':
    main() 