# scanner.py - Security Scanner Module with OWASP ZAP Integration
import requests
import re
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import sqlite3
from datetime import datetime
import threading
import logging

# Import ZAP integration
try:
    from zap_integration import ZAPScanner, get_zap_scanner, convert_zap_to_websecpen_format
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
    logging.warning("ZAP integration not available, using Python scanner")

logger = logging.getLogger(__name__)

class SecurityScanner:
    """
    Hybrid security scanner that uses OWASP ZAP when available,
    falls back to Python-based scanning when ZAP is not accessible
    """
    
    def __init__(self, use_zap: bool = True):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebSecPen Security Scanner 2.0'
        })
        self.vulnerabilities = []
        self.use_zap = use_zap and ZAP_AVAILABLE
        self.zap_scanner = None
        
        # Initialize ZAP if requested and available
        if self.use_zap:
            try:
                self.zap_scanner = get_zap_scanner()
                if not self.zap_scanner.is_available():
                    logger.warning("ZAP not available, falling back to Python scanner")
                    self.use_zap = False
                else:
                    logger.info("Using OWASP ZAP for security scanning")
            except Exception as e:
                logger.warning(f"ZAP initialization failed: {e}, using Python scanner")
                self.use_zap = False
        
        if not self.use_zap:
            logger.info("Using Python-based security scanner")
        
    def scan_target(self, target_url, scan_type, config=None, callback=None):
        """
        Main scanning function that coordinates different scan types
        Uses ZAP when available, falls back to Python scanner
        """
        config = config or {}
        
        print(f"Starting {scan_type} scan for {target_url}")
        print(f"Scanner mode: {'OWASP ZAP' if self.use_zap else 'Python Scanner'}")
        
        try:
            if self.use_zap and self.zap_scanner:
                return self._scan_with_zap(target_url, scan_type, config, callback)
            else:
                return self._scan_with_python(target_url, scan_type, config, callback)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            # If ZAP fails, try Python scanner as fallback
            if self.use_zap:
                logger.info("ZAP scan failed, trying Python scanner as fallback")
                self.use_zap = False
                return self._scan_with_python(target_url, scan_type, config, callback)
            else:
                raise
    
    def _scan_with_zap(self, target_url, scan_type, config, callback=None):
        """Use OWASP ZAP for scanning"""
        try:
            # Start ZAP session
            session_name = f"WebSecPen_{int(time.time())}"
            self.zap_scanner.start_session(session_name)
            
            # Initialize results
            results = {
                'target_url': target_url,
                'scan_type': scan_type,
                'scanner': 'OWASP ZAP',
                'scan_config': config,
                'start_time': datetime.utcnow(),
                'status': 'running',
                'vulnerabilities': [],
                'pages_scanned': 0,
                'requests_made': 0,
                'progress': 0
            }
            
            if callback:
                callback(results)
            
            # Perform ZAP scan based on scan type
            if scan_type in ['XSS', 'SQLi', 'CSRF', 'Directory', 'Full']:
                # For all types, do a comprehensive ZAP scan
                zap_results = self.zap_scanner.full_scan(target_url, 
                    callback=lambda r: self._update_zap_progress(r, results, callback))
                
                # Convert ZAP results to WebSecPen format
                if zap_results.get('alerts'):
                    converted_vulns = convert_zap_to_websecpen_format(zap_results['alerts'])
                    
                    # Filter by scan type if specific type requested
                    if scan_type != 'Full':
                        converted_vulns = self._filter_vulnerabilities_by_type(converted_vulns, scan_type)
                    
                    results['vulnerabilities'] = converted_vulns
                    results['vulnerabilities_count'] = len(converted_vulns)
                    results['high_severity_count'] = zap_results.get('high_severity_count', 0)
                    results['medium_severity_count'] = zap_results.get('medium_severity_count', 0)
                    results['low_severity_count'] = zap_results.get('low_severity_count', 0)
                    results['info_severity_count'] = zap_results.get('info_severity_count', 0)
                
                results['status'] = zap_results.get('status', 'completed')
                results['zap_session'] = session_name
                
            # Finalize results
            results['end_time'] = datetime.utcnow()
            results['duration'] = (results['end_time'] - results['start_time']).total_seconds()
            results['progress'] = 100
            
            if callback:
                callback(results)
            
            # Cleanup
            self.zap_scanner.cleanup_session()
            
            return results
            
        except Exception as e:
            logger.error(f"ZAP scan error: {e}")
            results['status'] = 'failed'
            results['error'] = str(e)
            if callback:
                callback(results)
            return results
    
    def _update_zap_progress(self, zap_results, websecpen_results, callback):
        """Update WebSecPen results with ZAP progress"""
        if 'progress' in zap_results:
            websecpen_results['progress'] = zap_results['progress']
            websecpen_results['status'] = zap_results.get('status', 'running')
            
            if callback:
                callback(websecpen_results)
    
    def _filter_vulnerabilities_by_type(self, vulnerabilities, scan_type):
        """Filter vulnerabilities by requested scan type"""
        if scan_type == 'XSS':
            return [v for v in vulnerabilities if 'xss' in v.get('type', '').lower() or 'cross site scripting' in v.get('type', '').lower()]
        elif scan_type == 'SQLi':
            return [v for v in vulnerabilities if 'sql' in v.get('type', '').lower() or 'injection' in v.get('type', '').lower()]
        elif scan_type == 'CSRF':
            return [v for v in vulnerabilities if 'csrf' in v.get('type', '').lower() or 'cross-site request forgery' in v.get('type', '').lower()]
        elif scan_type == 'Directory':
            return [v for v in vulnerabilities if 'directory' in v.get('type', '').lower() or 'path' in v.get('type', '').lower()]
        else:
            return vulnerabilities
    
    def _scan_with_python(self, target_url, scan_type, config, callback=None):
        """Fallback Python-based scanning (original implementation)"""
        config = config or {}
        max_depth = config.get('max_depth', 3)
        include_sql = config.get('include_sql', True)
        include_xss = config.get('include_xss', True)
        include_csrf = config.get('include_csrf', True)
        include_directory = config.get('include_directory', True)
        custom_headers = config.get('custom_headers', {})
        scan_delay = config.get('scan_delay', 1)
        aggressive_mode = config.get('aggressive_mode', False)
        
        # Apply custom headers if provided
        if custom_headers:
            self.session.headers.update(custom_headers)
        
        try:
            # Initialize scan results
            results = {
                'target_url': target_url,
                'scan_type': scan_type,
                'scanner': 'Python Scanner',
                'scan_config': config,
                'start_time': datetime.utcnow(),
                'status': 'running',
                'vulnerabilities': [],
                'pages_scanned': 0,
                'requests_made': 0,
                'max_depth': max_depth,
                'current_depth': 0,
                'progress': 0
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
            results['progress'] = 100
            
            if callback:
                callback(results)
                
            return results
            
        except Exception as e:
            print(f"Python scan error: {str(e)}")
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