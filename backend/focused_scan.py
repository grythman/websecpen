# focused_scan.py - Focused Vulnerability Scanning for Retesting
# Specialized ZAP integration for targeted vulnerability verification

import os
import time
import json
from zapv2 import ZAPv2
from datetime import datetime
from models import db, Scan

def start_focused_retest(target_url, vulnerability_data, scan_record_id):
    """
    Start a focused retest for a specific vulnerability
    
    Args:
        target_url (str): The URL to scan
        vulnerability_data (dict): Original vulnerability information
        scan_record_id (int): Database ID of the scan record
    
    Returns:
        str: ZAP scan ID
    """
    try:
        # Initialize ZAP
        zap_api_key = os.environ.get('ZAP_API_KEY')
        zap_proxy = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
        
        zap = ZAPv2(api_key=zap_api_key, proxies=zap_proxy)
        
        # Get vulnerability details
        vuln_name = vulnerability_data.get('name', '')
        vuln_url = vulnerability_data.get('url', target_url)
        vuln_param = vulnerability_data.get('param', '')
        vuln_attack = vulnerability_data.get('attack', '')
        vuln_method = vulnerability_data.get('method', 'GET')
        
        print(f"Starting focused retest for: {vuln_name} at {vuln_url}")
        
        # 1. Access the target URL
        zap.core.access_url(vuln_url)
        time.sleep(2)
        
        # 2. Create a focused scan context
        context_name = f"retest_{scan_record_id}_{int(time.time())}"
        zap.context.new_context(context_name)
        context_id = zap.context.context(context_name)['id']
        
        # Include only the specific URL and related paths
        zap.context.include_in_context(context_name, f"{vuln_url}.*")
        
        # 3. Configure scan based on vulnerability type
        scan_config = get_focused_scan_config(vuln_name, vulnerability_data)
        
        # 4. Run targeted active scan
        if scan_config['use_active_scan']:
            # Enable only relevant scan rules
            for policy_id in scan_config['scan_policies']:
                zap.ascan.enable_scanners(policy_id, scanpolicyname='Default Policy')
            
            # Start active scan
            scan_id = zap.ascan.scan(
                url=vuln_url,
                recurse=False,  # Don't recurse for focused testing
                inscopeonly=True,
                scanpolicyname='Default Policy',
                method=vuln_method,
                postdata=vuln_param if vuln_method.upper() == 'POST' else None
            )
        else:
            # Use passive scan only
            scan_id = f"passive_{scan_record_id}_{int(time.time())}"
            
            # Trigger passive scan by accessing the URL multiple times
            for _ in range(3):
                zap.core.access_url(vuln_url)
                time.sleep(1)
        
        # 5. Update scan record with ZAP scan ID
        scan_record = Scan.query.get(scan_record_id)
        if scan_record:
            scan_record.scan_id = scan_id
            db.session.commit()
        
        # 6. Start monitoring scan progress
        monitor_focused_scan(scan_id, scan_record_id, zap, scan_config)
        
        return scan_id
        
    except Exception as e:
        print(f"Error starting focused retest: {e}")
        # Update scan record with error
        scan_record = Scan.query.get(scan_record_id)
        if scan_record:
            scan_record.status = 'failed'
            scan_record.results = {'error': str(e)}
            db.session.commit()
        raise

def get_focused_scan_config(vuln_name, vulnerability_data):
    """
    Get scan configuration based on vulnerability type
    
    Args:
        vuln_name (str): Name of the vulnerability
        vulnerability_data (dict): Vulnerability details
    
    Returns:
        dict: Scan configuration
    """
    vuln_name_lower = vuln_name.lower()
    
    # XSS vulnerabilities
    if 'xss' in vuln_name_lower or 'cross site scripting' in vuln_name_lower:
        return {
            'use_active_scan': True,
            'scan_policies': ['40012', '40014', '40016', '40017'],  # XSS scan rules
            'max_duration': 300,  # 5 minutes
            'payload_tests': [
                '<script>alert("xss")</script>',
                '"><script>alert("xss")</script>',
                "javascript:alert('xss')"
            ]
        }
    
    # SQL Injection vulnerabilities
    elif 'sql' in vuln_name_lower or 'injection' in vuln_name_lower:
        return {
            'use_active_scan': True,
            'scan_policies': ['40018', '40019', '40020', '40021'],  # SQL injection scan rules
            'max_duration': 600,  # 10 minutes
            'payload_tests': [
                "' OR '1'='1",
                "1' OR '1'='1' --",
                "'; DROP TABLE users; --"
            ]
        }
    
    # Path Traversal vulnerabilities
    elif 'path' in vuln_name_lower or 'traversal' in vuln_name_lower or 'directory' in vuln_name_lower:
        return {
            'use_active_scan': True,
            'scan_policies': ['6'],  # Path traversal scan rule
            'max_duration': 180,  # 3 minutes
            'payload_tests': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
            ]
        }
    
    # CSRF vulnerabilities
    elif 'csrf' in vuln_name_lower or 'cross-site request forgery' in vuln_name_lower:
        return {
            'use_active_scan': False,  # CSRF is better tested passively
            'scan_policies': [],
            'max_duration': 120,  # 2 minutes
            'payload_tests': []
        }
    
    # Default configuration for unknown vulnerability types
    else:
        return {
            'use_active_scan': True,
            'scan_policies': ['1', '2', '3'],  # Basic scan rules
            'max_duration': 300,  # 5 minutes
            'payload_tests': []
        }

def monitor_focused_scan(scan_id, scan_record_id, zap, scan_config):
    """
    Monitor the progress of a focused scan and update results
    
    Args:
        scan_id (str): ZAP scan ID
        scan_record_id (int): Database scan record ID
        zap (ZAPv2): ZAP API instance
        scan_config (dict): Scan configuration
    """
    import threading
    
    def monitor_thread():
        try:
            max_duration = scan_config.get('max_duration', 300)
            start_time = time.time()
            
            if scan_config['use_active_scan']:
                # Monitor active scan
                while True:
                    # Check if scan is complete
                    status = zap.ascan.status(scan_id)
                    progress = int(status)
                    
                    print(f"Retest scan {scan_id} progress: {progress}%")
                    
                    # Update scan record
                    scan_record = Scan.query.get(scan_record_id)
                    if scan_record:
                        scan_record.metadata = scan_record.metadata or {}
                        scan_record.metadata['progress'] = progress
                        db.session.commit()
                    
                    if progress >= 100:
                        break
                    
                    # Check timeout
                    if time.time() - start_time > max_duration:
                        print(f"Retest scan {scan_id} timed out")
                        zap.ascan.stop(scan_id)
                        break
                    
                    time.sleep(10)
            else:
                # For passive scans, wait for the configured duration
                time.sleep(max_duration)
            
            # Collect results
            collect_retest_results(scan_id, scan_record_id, zap, scan_config)
            
        except Exception as e:
            print(f"Error monitoring retest scan: {e}")
            # Update scan record with error
            scan_record = Scan.query.get(scan_record_id)
            if scan_record:
                scan_record.status = 'failed'
                scan_record.results = {'error': str(e)}
                scan_record.completed_at = datetime.utcnow()
                db.session.commit()
    
    # Start monitoring in background thread
    monitor_thread = threading.Thread(target=monitor_thread)
    monitor_thread.daemon = True
    monitor_thread.start()

def collect_retest_results(scan_id, scan_record_id, zap, scan_config):
    """
    Collect and process retest results
    
    Args:
        scan_id (str): ZAP scan ID
        scan_record_id (int): Database scan record ID
        zap (ZAPv2): ZAP API instance
        scan_config (dict): Scan configuration
    """
    try:
        # Get alerts from ZAP
        alerts = zap.core.alerts()
        
        # Filter alerts to only include new ones from this scan
        # (ZAP doesn't provide scan-specific alerts easily, so we filter by timestamp)
        current_time = time.time()
        recent_alerts = []
        
        for alert in alerts:
            try:
                # Filter alerts that are recent (within the last scan duration)
                alert_time = alert.get('timestamp', current_time)
                if isinstance(alert_time, str):
                    # Convert string timestamp if needed
                    alert_time = current_time  # Fallback
                
                if current_time - float(alert_time) < scan_config.get('max_duration', 300):
                    recent_alerts.append(alert)
            except:
                # Include alert if timestamp parsing fails
                recent_alerts.append(alert)
        
        # Create comprehensive results
        results = {
            'scan_type': 'focused_retest',
            'scan_config': scan_config,
            'alerts': recent_alerts,
            'scan_summary': {
                'total_alerts': len(recent_alerts),
                'high_risk': len([a for a in recent_alerts if a.get('risk') == 'High']),
                'medium_risk': len([a for a in recent_alerts if a.get('risk') == 'Medium']),
                'low_risk': len([a for a in recent_alerts if a.get('risk') == 'Low']),
                'info_risk': len([a for a in recent_alerts if a.get('risk') == 'Informational'])
            },
            'scan_metadata': {
                'scan_duration': scan_config.get('max_duration', 300),
                'scan_type': 'active' if scan_config['use_active_scan'] else 'passive',
                'completed_at': datetime.utcnow().isoformat()
            }
        }
        
        # Update scan record
        scan_record = Scan.query.get(scan_record_id)
        if scan_record:
            scan_record.status = 'completed'
            scan_record.results = results
            scan_record.completed_at = datetime.utcnow()
            db.session.commit()
            
            print(f"Retest scan {scan_id} completed with {len(recent_alerts)} alerts")
            
            # Emit completion notification if possible
            try:
                from app import socketio
                socketio.emit('retest_completed', {
                    'retest_scan_id': scan_record_id,
                    'status': 'completed',
                    'total_alerts': len(recent_alerts),
                    'summary': results['scan_summary']
                }, room=f'user_{scan_record.user_id}')
            except:
                pass  # SocketIO not available
        
    except Exception as e:
        print(f"Error collecting retest results: {e}")
        # Update scan record with error
        scan_record = Scan.query.get(scan_record_id)
        if scan_record:
            scan_record.status = 'failed'
            scan_record.results = {'error': str(e)}
            scan_record.completed_at = datetime.utcnow()
            db.session.commit()

def cleanup_focused_scan_context(context_name, zap):
    """
    Clean up ZAP context after focused scan
    
    Args:
        context_name (str): Name of the context to remove
        zap (ZAPv2): ZAP API instance
    """
    try:
        zap.context.remove_context(context_name)
        print(f"Cleaned up ZAP context: {context_name}")
    except Exception as e:
        print(f"Error cleaning up context {context_name}: {e}")

# Utility functions for advanced retest scenarios

def test_specific_payload(target_url, payload, method='GET', param_name=None):
    """
    Test a specific payload against a URL
    
    Args:
        target_url (str): Target URL
        payload (str): Payload to test
        method (str): HTTP method
        param_name (str): Parameter name for the payload
    
    Returns:
        dict: Test results
    """
    try:
        zap_api_key = os.environ.get('ZAP_API_KEY')
        zap = ZAPv2(api_key=zap_api_key, proxies={'http': 'http://localhost:8080'})
        
        if method.upper() == 'GET':
            test_url = f"{target_url}?{param_name}={payload}" if param_name else f"{target_url}/{payload}"
            zap.core.access_url(test_url)
        else:
            # POST request
            post_data = f"{param_name}={payload}" if param_name else payload
            zap.core.send_request(target_url, method=method, postdata=post_data)
        
        # Check for immediate alerts
        time.sleep(2)
        alerts = zap.core.alerts()
        
        # Filter alerts related to our payload
        relevant_alerts = []
        for alert in alerts:
            if payload in alert.get('attack', '') or payload in alert.get('evidence', ''):
                relevant_alerts.append(alert)
        
        return {
            'payload': payload,
            'method': method,
            'alerts_triggered': len(relevant_alerts),
            'alerts': relevant_alerts,
            'test_successful': len(relevant_alerts) > 0
        }
        
    except Exception as e:
        return {
            'payload': payload,
            'method': method,
            'error': str(e),
            'test_successful': False
        } 