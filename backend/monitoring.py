# monitoring.py - Performance Monitoring System for WebSecPen
import os
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional
from flask import request, g
from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
import psutil
import threading

# Configure logging
logger = logging.getLogger(__name__)

# Prometheus Metrics
REQUEST_COUNT = Counter(
    'websecpen_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_DURATION = Histogram(
    'websecpen_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

SCAN_COUNT = Counter(
    'websecpen_scans_total',
    'Total number of security scans',
    ['scan_type', 'status']
)

SCAN_DURATION = Histogram(
    'websecpen_scan_duration_seconds',
    'Security scan duration in seconds',
    ['scan_type']
)

ACTIVE_USERS = Gauge(
    'websecpen_active_users',
    'Number of currently active users'
)

DATABASE_CONNECTIONS = Gauge(
    'websecpen_database_connections',
    'Number of active database connections'
)

MEMORY_USAGE = Gauge(
    'websecpen_memory_usage_bytes',
    'Memory usage in bytes'
)

CPU_USAGE = Gauge(
    'websecpen_cpu_usage_percent',
    'CPU usage percentage'
)

EMAIL_SENT = Counter(
    'websecpen_emails_sent_total',
    'Total emails sent',
    ['email_type', 'status']
)

NLP_PROCESSING_TIME = Histogram(
    'websecpen_nlp_processing_seconds',
    'NLP processing time in seconds',
    ['operation']
)

VULNERABILITY_COUNT = Gauge(
    'websecpen_vulnerabilities_found',
    'Number of vulnerabilities found',
    ['severity']
)

class PerformanceMonitor:
    """
    Comprehensive performance monitoring for WebSecPen
    """
    
    def __init__(self):
        self.start_time = datetime.utcnow()
        self.request_times: List[float] = []
        self.error_count = 0
        self.active_scans = 0
        self.system_stats_thread = None
        self.monitoring_enabled = True
        
        # Start system monitoring thread
        self._start_system_monitoring()
    
    def _start_system_monitoring(self):
        """Start background thread for system monitoring"""
        def monitor_system():
            while self.monitoring_enabled:
                try:
                    # Update system metrics
                    MEMORY_USAGE.set(psutil.virtual_memory().used)
                    CPU_USAGE.set(psutil.cpu_percent())
                    
                    # Sleep for 30 seconds
                    time.sleep(30)
                    
                except Exception as e:
                    logger.error(f"Error in system monitoring: {e}")
                    time.sleep(60)  # Wait longer on error
        
        self.system_stats_thread = threading.Thread(target=monitor_system, daemon=True)
        self.system_stats_thread.start()
        logger.info("System monitoring thread started")
    
    def track_request(self, endpoint_name: str):
        """Decorator to track HTTP request metrics"""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                status_code = 200
                
                try:
                    # Store start time in Flask g object
                    g.request_start_time = start_time
                    
                    # Execute the function
                    result = f(*args, **kwargs)
                    
                    # Extract status code from response
                    if hasattr(result, 'status_code'):
                        status_code = result.status_code
                    elif isinstance(result, tuple) and len(result) > 1:
                        status_code = result[1]
                    
                    return result
                    
                except Exception as e:
                    status_code = 500
                    self.error_count += 1
                    logger.error(f"Request error in {endpoint_name}: {e}")
                    raise
                    
                finally:
                    # Calculate duration
                    duration = time.time() - start_time
                    self.request_times.append(duration)
                    
                    # Update Prometheus metrics
                    REQUEST_COUNT.labels(
                        method=request.method,
                        endpoint=endpoint_name,
                        status_code=str(status_code)
                    ).inc()
                    
                    REQUEST_DURATION.labels(
                        method=request.method,
                        endpoint=endpoint_name
                    ).observe(duration)
                    
                    # Log slow requests
                    if duration > 2.0:  # Requests taking more than 2 seconds
                        logger.warning(f"Slow request: {endpoint_name} took {duration:.2f}s")
                    
                    # Keep only last 1000 request times
                    if len(self.request_times) > 1000:
                        self.request_times = self.request_times[-1000:]
            
            return wrapper
        return decorator
    
    def track_scan(self, scan_type: str):
        """Decorator to track scan metrics"""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                status = 'completed'
                
                try:
                    self.active_scans += 1
                    result = f(*args, **kwargs)
                    return result
                    
                except Exception as e:
                    status = 'failed'
                    logger.error(f"Scan error ({scan_type}): {e}")
                    raise
                    
                finally:
                    self.active_scans -= 1
                    duration = time.time() - start_time
                    
                    # Update metrics
                    SCAN_COUNT.labels(scan_type=scan_type, status=status).inc()
                    SCAN_DURATION.labels(scan_type=scan_type).observe(duration)
            
            return wrapper
        return decorator
    
    def track_email(self, email_type: str, success: bool):
        """Track email sending metrics"""
        status = 'success' if success else 'failed'
        EMAIL_SENT.labels(email_type=email_type, status=status).inc()
    
    def track_nlp_processing(self, operation: str, duration: float):
        """Track NLP processing metrics"""
        NLP_PROCESSING_TIME.labels(operation=operation).observe(duration)
    
    def update_vulnerability_count(self, severity: str, count: int):
        """Update vulnerability count metrics"""
        VULNERABILITY_COUNT.labels(severity=severity).set(count)
    
    def update_active_users(self, count: int):
        """Update active users metric"""
        ACTIVE_USERS.set(count)
    
    def update_database_connections(self, count: int):
        """Update database connections metric"""
        DATABASE_CONNECTIONS.set(count)
    
    def get_performance_summary(self) -> Dict:
        """Get comprehensive performance summary"""
        uptime = datetime.utcnow() - self.start_time
        
        # Calculate request statistics
        avg_response_time = sum(self.request_times) / len(self.request_times) if self.request_times else 0
        
        # Get recent request times (last 100)
        recent_times = self.request_times[-100:] if len(self.request_times) >= 100 else self.request_times
        recent_avg = sum(recent_times) / len(recent_times) if recent_times else 0
        
        # System resources
        memory_info = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent()
        
        return {
            'uptime_seconds': uptime.total_seconds(),
            'uptime_human': str(uptime),
            'performance': {
                'avg_response_time_ms': avg_response_time * 1000,
                'recent_avg_response_time_ms': recent_avg * 1000,
                'total_requests': len(self.request_times),
                'error_count': self.error_count,
                'active_scans': self.active_scans,
                'requests_per_minute': len([t for t in self.request_times if time.time() - t < 60])
            },
            'system': {
                'cpu_percent': cpu_percent,
                'memory_used_mb': memory_info.used / (1024 * 1024),
                'memory_available_mb': memory_info.available / (1024 * 1024),
                'memory_percent': memory_info.percent,
                'disk_usage_percent': psutil.disk_usage('/').percent
            },
            'application': {
                'active_users': ACTIVE_USERS._value._value,
                'database_connections': DATABASE_CONNECTIONS._value._value,
                'total_scans': sum([metric.samples[0].value for metric in REGISTRY.collect() 
                                  if metric.name == 'websecpen_scans_total']),
                'total_emails': sum([metric.samples[0].value for metric in REGISTRY.collect() 
                                   if metric.name == 'websecpen_emails_sent_total'])
            }
        }
    
    def get_health_status(self) -> Dict:
        """Get application health status"""
        health = {
            'status': 'healthy',
            'checks': {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Check response time
        avg_response_time = sum(self.request_times[-10:]) / 10 if len(self.request_times) >= 10 else 0
        health['checks']['response_time'] = {
            'status': 'healthy' if avg_response_time < 1.0 else 'warning' if avg_response_time < 2.0 else 'unhealthy',
            'value': f"{avg_response_time * 1000:.0f}ms",
            'threshold': '< 1000ms'
        }
        
        # Check memory usage
        memory_percent = psutil.virtual_memory().percent
        health['checks']['memory'] = {
            'status': 'healthy' if memory_percent < 80 else 'warning' if memory_percent < 90 else 'unhealthy',
            'value': f"{memory_percent:.1f}%",
            'threshold': '< 80%'
        }
        
        # Check CPU usage
        cpu_percent = psutil.cpu_percent()
        health['checks']['cpu'] = {
            'status': 'healthy' if cpu_percent < 70 else 'warning' if cpu_percent < 85 else 'unhealthy',
            'value': f"{cpu_percent:.1f}%",
            'threshold': '< 70%'
        }
        
        # Check error rate
        total_requests = len(self.request_times)
        error_rate = (self.error_count / total_requests * 100) if total_requests > 0 else 0
        health['checks']['error_rate'] = {
            'status': 'healthy' if error_rate < 1 else 'warning' if error_rate < 5 else 'unhealthy',
            'value': f"{error_rate:.2f}%",
            'threshold': '< 1%'
        }
        
        # Overall status
        check_statuses = [check['status'] for check in health['checks'].values()]
        if 'unhealthy' in check_statuses:
            health['status'] = 'unhealthy'
        elif 'warning' in check_statuses:
            health['status'] = 'warning'
        
        return health
    
    def get_prometheus_metrics(self) -> str:
        """Get Prometheus-formatted metrics"""
        return generate_latest(REGISTRY)
    
    def cleanup(self):
        """Cleanup monitoring resources"""
        self.monitoring_enabled = False
        if self.system_stats_thread and self.system_stats_thread.is_alive():
            self.system_stats_thread.join(timeout=5)

class AlertManager:
    """
    Alert manager for critical system events
    """
    
    def __init__(self):
        self.alert_thresholds = {
            'high_response_time': 2.0,  # seconds
            'high_error_rate': 5.0,     # percentage
            'high_memory_usage': 90.0,  # percentage
            'high_cpu_usage': 85.0,     # percentage
            'failed_scans': 10          # count in last hour
        }
        self.recent_alerts = []
    
    def check_alerts(self, monitor: PerformanceMonitor):
        """Check for alert conditions"""
        alerts = []
        
        # Check response time
        recent_times = monitor.request_times[-10:] if len(monitor.request_times) >= 10 else monitor.request_times
        if recent_times:
            avg_time = sum(recent_times) / len(recent_times)
            if avg_time > self.alert_thresholds['high_response_time']:
                alerts.append({
                    'type': 'high_response_time',
                    'severity': 'warning',
                    'message': f'Average response time is {avg_time:.2f}s (threshold: {self.alert_thresholds["high_response_time"]}s)',
                    'value': avg_time,
                    'timestamp': datetime.utcnow()
                })
        
        # Check error rate
        total_requests = len(monitor.request_times)
        if total_requests > 0:
            error_rate = (monitor.error_count / total_requests) * 100
            if error_rate > self.alert_thresholds['high_error_rate']:
                alerts.append({
                    'type': 'high_error_rate',
                    'severity': 'critical',
                    'message': f'Error rate is {error_rate:.2f}% (threshold: {self.alert_thresholds["high_error_rate"]}%)',
                    'value': error_rate,
                    'timestamp': datetime.utcnow()
                })
        
        # Check system resources
        memory_percent = psutil.virtual_memory().percent
        if memory_percent > self.alert_thresholds['high_memory_usage']:
            alerts.append({
                'type': 'high_memory_usage',
                'severity': 'critical',
                'message': f'Memory usage is {memory_percent:.1f}% (threshold: {self.alert_thresholds["high_memory_usage"]}%)',
                'value': memory_percent,
                'timestamp': datetime.utcnow()
            })
        
        cpu_percent = psutil.cpu_percent()
        if cpu_percent > self.alert_thresholds['high_cpu_usage']:
            alerts.append({
                'type': 'high_cpu_usage',
                'severity': 'warning',
                'message': f'CPU usage is {cpu_percent:.1f}% (threshold: {self.alert_thresholds["high_cpu_usage"]}%)',
                'value': cpu_percent,
                'timestamp': datetime.utcnow()
            })
        
        # Store and return alerts
        self.recent_alerts.extend(alerts)
        
        # Keep only last 100 alerts
        if len(self.recent_alerts) > 100:
            self.recent_alerts = self.recent_alerts[-100:]
        
        return alerts
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent alerts within specified hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [
            alert for alert in self.recent_alerts
            if alert['timestamp'] > cutoff_time
        ]

# Global monitoring instances
performance_monitor = PerformanceMonitor()
alert_manager = AlertManager() 