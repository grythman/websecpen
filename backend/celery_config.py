# celery_config.py - Celery configuration for WebSecPen scheduled scans
import os
from datetime import datetime, timedelta
from celery import Celery
from flask import current_app
from models import db, User, Scan, Schedule
from scanner import scan_manager

# Initialize Celery
def make_celery(app):
    """Create and configure Celery instance"""
    celery = Celery(
        app.import_name,
        backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
        broker=app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    )
    
    # Update configuration
    celery.conf.update(
        task_track_started=True,
        timezone='UTC',
        beat_schedule={
            'run-scheduled-scans': {
                'task': 'celery_config.run_scheduled_scans',
                'schedule': 300.0,  # Check every 5 minutes
            },
            'archive-old-scans': {
                'task': 'celery_config.archive_old_scans',
                'schedule': 3600.0,  # Run every hour
            },
        },
        beat_scheduler='celery.beat:PersistentScheduler',
        worker_concurrency=2,  # Limit concurrent workers
        task_soft_time_limit=600,  # 10 minutes
        task_time_limit=900,  # 15 minutes hard limit
    )
    
    # Ensure tasks run within Flask app context
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery

# Initialize with Flask app (to be called from main app)
celery = None

def init_celery(app):
    """Initialize Celery with Flask app"""
    global celery
    celery = make_celery(app)
    return celery

# Celery Tasks
@celery.task(bind=True)
def run_scheduled_scan(self, user_id, schedule_id):
    """Run a scheduled scan"""
    try:
        schedule = Schedule.query.get(schedule_id)
        if not schedule or not schedule.is_active:
            return {'error': 'Schedule not found or inactive'}
        
        user = User.query.get(user_id)
        if not user or not user.is_active:
            return {'error': 'User not found or inactive'}
        
        # Check user's scan limit
        current_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_scans = Scan.query.filter(
            Scan.user_id == user_id,
            Scan.created_at >= current_month
        ).count()
        
        if monthly_scans >= user.scan_limit:
            return {'error': 'Monthly scan limit reached'}
        
        # Create new scan
        scan = Scan(
            user_id=user_id,
            target_url=schedule.url,
            scan_type=schedule.scan_type,
            status='pending',
            scan_config=schedule.scan_config
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Start the actual scan
        try:
            scan_result = scan_manager.start_scan(
                target_url=schedule.url,
                scan_type=schedule.scan_type,
                user_id=user_id,
                scan_id=scan.id
            )
            
            scan.status = 'running'
            scan.started_at = datetime.utcnow()
            
        except Exception as e:
            scan.status = 'failed'
            scan.error_message = str(e)
        
        # Update schedule
        schedule.last_run = datetime.utcnow()
        schedule.run_count = (schedule.run_count or 0) + 1
        
        # Calculate next run
        if schedule.frequency == 'daily':
            schedule.next_run = schedule.last_run + timedelta(days=1)
        elif schedule.frequency == 'weekly':
            schedule.next_run = schedule.last_run + timedelta(weeks=1)
        elif schedule.frequency == 'monthly':
            schedule.next_run = schedule.last_run + timedelta(days=30)
        
        db.session.commit()
        
        return {
            'scan_id': scan.id,
            'status': scan.status,
            'schedule_id': schedule.id,
            'next_run': schedule.next_run.isoformat() if schedule.next_run else None
        }
        
    except Exception as e:
        self.retry(countdown=60, max_retries=3)
        return {'error': f'Scan failed: {str(e)}'}

@celery.task
def run_scheduled_scans():
    """Check and run due scheduled scans"""
    try:
        now = datetime.utcnow()
        
        # Find all active schedules that are due
        due_schedules = Schedule.query.filter(
            Schedule.is_active == True,
            Schedule.next_run <= now
        ).all()
        
        results = []
        for schedule in due_schedules:
            # Queue the scan task
            task = run_scheduled_scan.delay(schedule.user_id, schedule.id)
            results.append({
                'schedule_id': schedule.id,
                'task_id': task.id,
                'user_id': schedule.user_id,
                'url': schedule.url
            })
        
        return {
            'processed': len(results),
            'schedules': results,
            'timestamp': now.isoformat()
        }
        
    except Exception as e:
        return {'error': f'Failed to process scheduled scans: {str(e)}'}

@celery.task
def archive_old_scans():
    """Archive scans older than 90 days"""
    try:
        threshold = datetime.utcnow() - timedelta(days=90)
        
        # Update old scans to archived
        updated = Scan.query.filter(
            Scan.created_at < threshold,
            Scan.archived == False
        ).update({'archived': True})
        
        db.session.commit()
        
        return {
            'archived_scans': updated,
            'threshold': threshold.isoformat(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        return {'error': f'Failed to archive scans: {str(e)}'}

@celery.task
def cleanup_expired_tokens():
    """Clean up expired FCM tokens and other maintenance tasks"""
    try:
        # This could include cleaning up expired tokens, 
        # removing inactive users, etc.
        
        # For now, just a placeholder
        return {
            'message': 'Cleanup completed',
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        return {'error': f'Cleanup failed: {str(e)}'}

# Helper function to get Celery instance
def get_celery():
    """Get the current Celery instance"""
    return celery 