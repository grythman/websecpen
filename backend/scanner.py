# scanner.py - Security Scanner Module
import requests
import re
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import sqlite3
from datetime import datetime
import threading

class SecurityScanner:
    """
    Python-based security scanner that can detect real vulnerabilities.
    This will be easily replaceable with OWASP ZAP integration later.
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebSecPen Security Scanner 1.0'
        })
        self.vulnerabilities = []
        
    def scan_target(self, target_url, scan_type, config=None, callback=None):
        """
        Main scanning function that coordinates different scan types with advanced configuration
        """
        config = config or {}
        max_depth = config.get('max_depth', 3)
        include_sql = config.get('include_sql', True)
        include_xss = config.get('include_xss', True)
        include_csrf = config.get('include_csrf', True)
        include_directory = config.get('include_directory', True)
        custom_headers = config.get('custom_headers', {})
        scan_delay = config.get('scan_delay', 1)  # Delay between requests in seconds
        aggressive_mode = config.get('aggressive_mode', False)
        
        print(f"Starting {scan_type} scan for {target_url} with config: {config}")
        
        # Apply custom headers if provided
        if custom_headers:
            self.session.headers.update(custom_headers)
        
        try:
            # Initialize scan results
            results = {
                'target_url': target_url,
                'scan_type': scan_type,
                'scan_config': config,
                'start_time': datetime.utcnow(),
                'status': 'running',
                'vulnerabilities': [],
                'pages_scanned': 0,
                'requests_made': 0,
                'max_depth': max_depth,
                'current_depth': 0
            }
            
            if callback:
                callback(results)
            
            # Perform different types of scans based on scan_type
            if scan_type == 'XSS':
                self._scan_xss(target_url, results, callback)
            elif scan_type == 'SQLi':
                self._scan_sqli(target_url, results, callback)
            elif scan_type == 'CSRF':
                self._scan_csrf(target_url, results, callback)
            elif scan_type == 'Directory':
                self._scan_directory_traversal(target_url, results, callback)
            else:
                # Full scan - run all tests
                self._scan_xss(target_url, results, callback)
                self._scan_sqli(target_url, results, callback)
                self._scan_csrf(target_url, results, callback)
                self._scan_directory_traversal(target_url, results, callback)
            
            # Finalize results
            results['end_time'] = datetime.utcnow()
            results['status'] = 'completed'
            results['duration'] = (results['end_time'] - results['start_time']).total_seconds()
            
            if callback:
                callback(results)
                
            return results
            
        except Exception as e:
            print(f"Scan error: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
            if callback:
                callback(results)
            return results
    
    def _scan_xss(self, base_url, results, callback=None):
        """Scan for XSS vulnerabilities"""
        print("Scanning for XSS vulnerabilities...")
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>'
        ]
        
        # Test common XSS entry points
        test_endpoints = [
            '/xss',
            '/xss?input=test',
            '/search',
            '/search?q=test',
            '/vulnerable',
            '/vulnerable?input=test'
        ]
        
        for endpoint in test_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            # Test GET parameters
            for payload in xss_payloads:
                try:
                    # Test various parameter names
                    for param in ['input', 'q', 'search', 'query', 'data']:
                        test_params = {param: payload}
                        response = self.session.get(test_url, params=test_params, timeout=10)
                        results['requests_made'] += 1
                        
                        # Check if payload is reflected in response
                        if payload in response.text and response.status_code == 200:
                            vulnerability = {
                                'type': 'XSS',
                                'severity': 'High',
                                'title': f'Reflected XSS in {param} parameter',
                                'description': f'User input in {param} parameter is reflected without proper encoding',
                                'url': response.url,
                                'parameter': param,
                                'payload': payload,
                                'confidence': 95,
                                'evidence': payload[:100],
                                'solution': 'Implement proper input validation and output encoding'
                            }
                            results['vulnerabilities'].append(vulnerability)
                            print(f"Found XSS: {test_url}?{param}={payload[:20]}...")
                        
                        time.sleep(0.1)  # Rate limiting
                        
                except Exception as e:
                    print(f"Error testing {test_url}: {str(e)}")
                    continue
        
        results['pages_scanned'] += len(test_endpoints)
        if callback:
            callback(results)
    
    def _scan_sqli(self, base_url, results, callback=None):
        """Scan for SQL Injection vulnerabilities"""
        print("Scanning for SQL Injection vulnerabilities...")
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT null--",
            "admin'--",
            "' OR 'a'='a",
            "1' OR '1'='1' --",
            "' OR 1=1#",
            "') OR ('1'='1"
        ]
        
        test_endpoints = [
            '/sqli',
            '/sqli?username=test',
            '/login',
            '/search'
        ]
        
        for endpoint in test_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            for payload in sqli_payloads:
                try:
                    # Test various parameter names
                    for param in ['username', 'user', 'id', 'search', 'query']:
                        test_params = {param: payload}
                        response = self.session.get(test_url, params=test_params, timeout=10)
                        results['requests_made'] += 1
                        
                        # Check for SQL error patterns
                        sql_errors = [
                            'sqlite3.OperationalError',
                            'MySQL syntax error',
                            'PostgreSQL',
                            'ORA-',
                            'Microsoft OLE DB',
                            'syntax error',
                            'unexpected token',
                            'sqlite_',
                            'WHERE username',
                            'SELECT * FROM'
                        ]
                        
                        response_text = response.text.lower()
                        for error_pattern in sql_errors:
                            if error_pattern.lower() in response_text:
                                vulnerability = {
                                    'type': 'SQLi',
                                    'severity': 'High',
                                    'title': f'SQL Injection in {param} parameter',
                                    'description': f'SQL injection vulnerability detected through error-based testing',
                                    'url': response.url,
                                    'parameter': param,
                                    'payload': payload,
                                    'confidence': 90,
                                    'evidence': error_pattern,
                                    'solution': 'Use parameterized queries and input validation'
                                }
                                results['vulnerabilities'].append(vulnerability)
                                print(f"Found SQLi: {test_url}?{param}={payload[:20]}...")
                                break
                        
                        time.sleep(0.1)
                        
                except Exception as e:
                    print(f"Error testing {test_url}: {str(e)}")
                    continue
        
        results['pages_scanned'] += len(test_endpoints)
        if callback:
            callback(results)
    
    def _scan_csrf(self, base_url, results, callback=None):
        """Scan for CSRF vulnerabilities"""
        print("Scanning for CSRF vulnerabilities...")
        
        test_endpoints = [
            '/csrf',
            '/profile',
            '/settings',
            '/admin'
        ]
        
        for endpoint in test_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                response = self.session.get(test_url, timeout=10)
                results['requests_made'] += 1
                
                if response.status_code == 200:
                    # Check for forms without CSRF tokens
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        method = form.get('method', 'GET').upper()
                        if method in ['POST', 'PUT', 'DELETE']:
                            # Check for CSRF token fields
                            csrf_fields = form.find_all('input', {'name': re.compile(r'csrf|token|_token', re.I)})
                            
                            if not csrf_fields:
                                vulnerability = {
                                    'type': 'CSRF',
                                    'severity': 'Medium',
                                    'title': f'Missing CSRF Protection',
                                    'description': f'Form at {endpoint} lacks CSRF protection',
                                    'url': test_url,
                                    'method': method,
                                    'confidence': 85,
                                    'evidence': f'Form method: {method}, No CSRF token found',
                                    'solution': 'Implement CSRF tokens for all state-changing operations'
                                }
                                results['vulnerabilities'].append(vulnerability)
                                print(f"Found CSRF: {test_url}")
                
                time.sleep(0.1)
                
            except Exception as e:
                print(f"Error testing {test_url}: {str(e)}")
                continue
        
        results['pages_scanned'] += len(test_endpoints)
        if callback:
            callback(results)
    
    def _scan_directory_traversal(self, base_url, results, callback=None):
        """Scan for Directory Traversal vulnerabilities"""
        print("Scanning for Directory Traversal vulnerabilities...")
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '../../../etc/hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%2f..%2f..%2fetc%2fpasswd'
        ]
        
        test_endpoints = [
            '/directory',
            '/file',
            '/download',
            '/view'
        ]
        
        for endpoint in test_endpoints:
            test_url = urljoin(base_url, endpoint)
            
            for payload in traversal_payloads:
                try:
                    # Test various parameter names
                    for param in ['file', 'path', 'filename', 'document']:
                        test_params = {param: payload}
                        response = self.session.get(test_url, params=test_params, timeout=10)
                        results['requests_made'] += 1
                        
                        # Check for sensitive file contents
                        sensitive_patterns = [
                            'root:x:0:0:',  # /etc/passwd
                            'localhost',    # hosts file
                            '# Host Database',
                            '[autorun]'     # Windows autorun
                        ]
                        
                        for pattern in sensitive_patterns:
                            if pattern in response.text and response.status_code == 200:
                                vulnerability = {
                                    'type': 'Directory Traversal',
                                    'severity': 'High',
                                    'title': f'Directory Traversal in {param} parameter',
                                    'description': f'Able to access system files through path traversal',
                                    'url': response.url,
                                    'parameter': param,
                                    'payload': payload,
                                    'confidence': 95,
                                    'evidence': pattern,
                                    'solution': 'Implement proper input validation and file access controls'
                                }
                                results['vulnerabilities'].append(vulnerability)
                                print(f"Found Directory Traversal: {test_url}?{param}={payload}")
                                break
                        
                        time.sleep(0.1)
                        
                except Exception as e:
                    print(f"Error testing {test_url}: {str(e)}")
                    continue
        
        results['pages_scanned'] += len(test_endpoints)
        if callback:
            callback(results)

# Async scan manager for handling multiple concurrent scans
class ScanManager:
    """Manages multiple concurrent scans and progress tracking"""
    
    def __init__(self):
        self.active_scans = {}
        
    def start_scan(self, scan_id, target_url, scan_type, scan_config=None, progress_callback=None):
        """Start a new scan in a separate thread with configurable options"""
        
        def run_scan():
            scanner = SecurityScanner()
            
            def update_progress(results):
                # Update database with progress
                if progress_callback:
                    progress_callback(scan_id, results)
            
            # Run the scan with configuration
            final_results = scanner.scan_target(target_url, scan_type, scan_config, update_progress)
            
            # Final callback
            if progress_callback:
                progress_callback(scan_id, final_results)
            
            # Clean up
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
        
        # Start scan in background thread
        thread = threading.Thread(target=run_scan)
        self.active_scans[scan_id] = {
            'thread': thread,
            'start_time': datetime.utcnow(),
            'status': 'starting'
        }
        thread.start()
        
        return True
    
    def get_scan_status(self, scan_id):
        """Get current status of a scan"""
        if scan_id in self.active_scans:
            scan_info = self.active_scans[scan_id]
            return {
                'status': 'running',
                'start_time': scan_info['start_time'],
                'thread_alive': scan_info['thread'].is_alive()
            }
        else:
            return {'status': 'not_found'}
    
    def stop_scan(self, scan_id):
        """Stop a running scan"""
        if scan_id in self.active_scans:
            # Note: Python threads cannot be forcefully stopped safely
            # In a real implementation, we'd use a cancellation token
            return True
        return False

# Global scan manager instance
scan_manager = ScanManager() 