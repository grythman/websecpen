# zap_integration.py - OWASP ZAP API Integration
import requests
import time
import json
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class ZAPScanner:
    """
    OWASP ZAP API integration for comprehensive security scanning
    """
    
    def __init__(self, zap_url: str = "http://localhost:8080", api_key: Optional[str] = None):
        self.zap_url = zap_url
        self.api_key = api_key
        self.base_url = f"{zap_url}/JSON"
        self.session = requests.Session()
        
        # Set API key if provided
        if api_key:
            self.session.params.update({'apikey': api_key})
    
    def is_available(self) -> bool:
        """Check if ZAP is running and accessible"""
        try:
            response = self.session.get(f"{self.base_url}/core/view/version/", timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"ZAP not available: {e}")
            return False
    
    def start_session(self, session_name: str = "WebSecPen") -> str:
        """Start a new ZAP session"""
        try:
            response = self.session.get(
                f"{self.base_url}/core/action/newSession/",
                params={'name': session_name, 'overwrite': 'true'}
            )
            return session_name
        except Exception as e:
            logger.error(f"Failed to start ZAP session: {e}")
            raise
    
    def spider_scan(self, target_url: str, max_children: int = 10) -> str:
        """Start spider scan to discover URLs"""
        try:
            # Start spider
            response = self.session.get(
                f"{self.base_url}/spider/action/scan/",
                params={
                    'url': target_url,
                    'maxChildren': max_children,
                    'recurse': 'true'
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Spider scan failed: {response.text}")
            
            scan_id = response.json().get('scan')
            logger.info(f"Started spider scan with ID: {scan_id}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Spider scan failed: {e}")
            raise
    
    def wait_for_spider(self, scan_id: str, timeout: int = 300) -> bool:
        """Wait for spider scan to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = self.session.get(
                    f"{self.base_url}/spider/view/status/",
                    params={'scanId': scan_id}
                )
                
                status = int(response.json().get('status', 0))
                logger.info(f"Spider progress: {status}%")
                
                if status >= 100:
                    return True
                    
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error checking spider status: {e}")
                time.sleep(5)
        
        logger.warning("Spider scan timeout")
        return False
    
    def active_scan(self, target_url: str, policy_id: Optional[str] = None) -> str:
        """Start active security scan"""
        try:
            params = {'url': target_url, 'recurse': 'true'}
            if policy_id:
                params['scanPolicyName'] = policy_id
            
            response = self.session.get(
                f"{self.base_url}/ascan/action/scan/",
                params=params
            )
            
            if response.status_code != 200:
                raise Exception(f"Active scan failed: {response.text}")
            
            scan_id = response.json().get('scan')
            logger.info(f"Started active scan with ID: {scan_id}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
            raise
    
    def wait_for_active_scan(self, scan_id: str, timeout: int = 600) -> bool:
        """Wait for active scan to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = self.session.get(
                    f"{self.base_url}/ascan/view/status/",
                    params={'scanId': scan_id}
                )
                
                status = int(response.json().get('status', 0))
                logger.info(f"Active scan progress: {status}%")
                
                if status >= 100:
                    return True
                    
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error checking active scan status: {e}")
                time.sleep(10)
        
        logger.warning("Active scan timeout")
        return False
    
    def get_alerts(self, base_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all security alerts/vulnerabilities found"""
        try:
            params = {}
            if base_url:
                params['baseurl'] = base_url
            
            response = self.session.get(
                f"{self.base_url}/core/view/alerts/",
                params=params
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get alerts: {response.text}")
            
            alerts = response.json().get('alerts', [])
            logger.info(f"Retrieved {len(alerts)} alerts")
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []
    
    def get_scan_progress(self, scan_id: str, scan_type: str = 'ascan') -> Dict[str, Any]:
        """Get scan progress information"""
        try:
            if scan_type == 'spider':
                response = self.session.get(
                    f"{self.base_url}/spider/view/status/",
                    params={'scanId': scan_id}
                )
            else:  # active scan
                response = self.session.get(
                    f"{self.base_url}/ascan/view/status/",
                    params={'scanId': scan_id}
                )
            
            if response.status_code != 200:
                return {'status': 0, 'error': 'Failed to get progress'}
            
            data = response.json()
            return {
                'status': int(data.get('status', 0)),
                'scan_id': scan_id,
                'scan_type': scan_type
            }
            
        except Exception as e:
            logger.error(f"Failed to get scan progress: {e}")
            return {'status': 0, 'error': str(e)}
    
    def full_scan(self, target_url: str, callback=None) -> Dict[str, Any]:
        """Perform complete ZAP scan (spider + active scan)"""
        try:
            results = {
                'target_url': target_url,
                'start_time': time.time(),
                'status': 'running',
                'spider_id': None,
                'active_scan_id': None,
                'alerts': [],
                'progress': 0
            }
            
            if callback:
                callback(results)
            
            # Step 1: Spider scan to discover URLs
            logger.info(f"Starting spider scan for {target_url}")
            spider_id = self.spider_scan(target_url)
            results['spider_id'] = spider_id
            results['progress'] = 10
            
            if callback:
                callback(results)
            
            # Wait for spider to complete
            if not self.wait_for_spider(spider_id):
                results['status'] = 'failed'
                results['error'] = 'Spider scan timeout'
                return results
            
            results['progress'] = 30
            if callback:
                callback(results)
            
            # Step 2: Active scan for vulnerabilities
            logger.info(f"Starting active scan for {target_url}")
            active_scan_id = self.active_scan(target_url)
            results['active_scan_id'] = active_scan_id
            results['progress'] = 40
            
            if callback:
                callback(results)
            
            # Wait for active scan to complete
            if not self.wait_for_active_scan(active_scan_id):
                results['status'] = 'failed'
                results['error'] = 'Active scan timeout'
                return results
            
            results['progress'] = 80
            if callback:
                callback(results)
            
            # Step 3: Get results
            alerts = self.get_alerts(target_url)
            results['alerts'] = alerts
            results['vulnerabilities_count'] = len(alerts)
            
            # Count by severity
            severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            for alert in alerts:
                risk = alert.get('risk', 'Informational')
                severity_counts[risk] = severity_counts.get(risk, 0) + 1
            
            results['severity_counts'] = severity_counts
            results['high_severity_count'] = severity_counts['High']
            results['medium_severity_count'] = severity_counts['Medium']
            results['low_severity_count'] = severity_counts['Low']
            results['info_severity_count'] = severity_counts['Informational']
            
            results['status'] = 'completed'
            results['progress'] = 100
            results['end_time'] = time.time()
            results['duration'] = results['end_time'] - results['start_time']
            
            if callback:
                callback(results)
            
            logger.info(f"ZAP scan completed for {target_url}: {len(alerts)} vulnerabilities found")
            return results
            
        except Exception as e:
            logger.error(f"ZAP full scan failed: {e}")
            results['status'] = 'failed'
            results['error'] = str(e)
            return results
    
    def generate_report(self, report_type: str = 'html') -> Optional[str]:
        """Generate scan report"""
        try:
            if report_type.lower() == 'html':
                response = self.session.get(f"{self.base_url}/core/other/htmlreport/")
            elif report_type.lower() == 'xml':
                response = self.session.get(f"{self.base_url}/core/other/xmlreport/")
            elif report_type.lower() == 'json':
                response = self.session.get(f"{self.base_url}/core/view/alerts/")
                return response.text
            else:
                raise ValueError(f"Unsupported report type: {report_type}")
            
            if response.status_code == 200:
                return response.text
            else:
                logger.error(f"Failed to generate {report_type} report")
                return None
                
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return None
    
    def cleanup_session(self):
        """Clean up ZAP session"""
        try:
            # Stop all scans
            self.session.get(f"{self.base_url}/ascan/action/stopAllScans/")
            self.session.get(f"{self.base_url}/spider/action/stopAllScans/")
            
            # Clear session data
            self.session.get(f"{self.base_url}/core/action/clearExcludedFromProxy/")
            
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")

# Utility functions for integration
def get_zap_scanner(config: Dict[str, Any] = None) -> ZAPScanner:
    """Get configured ZAP scanner instance"""
    config = config or {}
    
    zap_url = config.get('zap_url', 'http://localhost:8080')
    api_key = config.get('zap_api_key')
    
    return ZAPScanner(zap_url=zap_url, api_key=api_key)

def convert_zap_to_websecpen_format(zap_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert ZAP alert format to WebSecPen format"""
    converted = []
    
    for alert in zap_alerts:
        converted.append({
            'type': alert.get('name', 'Unknown'),
            'severity': alert.get('risk', 'Informational'),
            'confidence': alert.get('confidence', 'Medium'),
            'description': alert.get('description', ''),
            'solution': alert.get('solution', ''),
            'reference': alert.get('reference', ''),
            'url': alert.get('url', ''),
            'param': alert.get('param', ''),
            'evidence': alert.get('evidence', ''),
            'attack': alert.get('attack', ''),
            'cwe_id': alert.get('cweid', ''),
            'wasc_id': alert.get('wascid', ''),
            'source_id': alert.get('sourceid', ''),
            'other_info': alert.get('otherinfo', ''),
            'plugin_id': alert.get('pluginId', ''),
            'alert_id': alert.get('id', ''),
            'message_id': alert.get('messageId', ''),
            'alert_ref': alert.get('alertRef', '')
        })
    
    return converted 