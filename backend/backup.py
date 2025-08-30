# backup.py - Automated Database Backup System
import os
import subprocess
import datetime
import json
import shutil
import logging
from pathlib import Path

# Optional AWS S3 integration
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    boto3 = None
    ClientError = Exception
    AWS_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('backup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class BackupManager:
    """
    Comprehensive backup manager for WebSecPen
    Supports local and cloud backups (AWS S3)
    """
    
    def __init__(self):
        # Database configuration
        self.db_host = os.getenv('DATABASE_HOST', 'localhost')
        self.db_port = os.getenv('DATABASE_PORT', '5432')
        self.db_name = os.getenv('DATABASE_NAME', 'websecpen')
        self.db_user = os.getenv('DATABASE_USER', 'postgres')
        self.db_password = os.getenv('DATABASE_PASSWORD', '')
        
        # Backup configuration
        self.backup_dir = Path(os.getenv('BACKUP_DIR', './backups'))
        self.backup_dir.mkdir(exist_ok=True)
        
        # AWS S3 configuration (optional)
        self.aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        self.aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.s3_bucket = os.getenv('S3_BACKUP_BUCKET')
        self.s3_region = os.getenv('AWS_REGION', 'us-east-1')
        
        # Initialize S3 client if credentials and boto3 are available
        self.s3_client = None
        if AWS_AVAILABLE and self.aws_access_key and self.aws_secret_key:
            try:
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_secret_key,
                    region_name=self.s3_region
                )
                logger.info("AWS S3 client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize S3 client: {e}")
        elif not AWS_AVAILABLE:
            logger.info("AWS S3 integration not available (boto3 not installed)")
        
        # Retention settings
        self.local_retention_days = int(os.getenv('LOCAL_RETENTION_DAYS', '7'))
        self.s3_retention_days = int(os.getenv('S3_RETENTION_DAYS', '30'))
    
    def create_database_backup(self):
        """Create PostgreSQL database backup using pg_dump"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"websecpen_db_backup_{timestamp}.sql"
        backup_path = self.backup_dir / backup_filename
        
        try:
            # Prepare pg_dump command
            cmd = [
                'pg_dump',
                '-h', self.db_host,
                '-p', self.db_port,
                '-U', self.db_user,
                '-d', self.db_name,
                '--no-password',
                '--verbose',
                '--clean',
                '--if-exists',
                '--create',
                '-f', str(backup_path)
            ]
            
            # Set password via environment variable
            env = os.environ.copy()
            env['PGPASSWORD'] = self.db_password
            
            logger.info(f"Starting database backup to {backup_path}")
            
            # Execute pg_dump
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                check=True
            )
            
            if backup_path.exists() and backup_path.stat().st_size > 0:
                logger.info(f"Database backup completed successfully: {backup_path}")
                
                # Compress the backup
                compressed_path = self.compress_backup(backup_path)
                if compressed_path:
                    backup_path.unlink()  # Remove uncompressed file
                    return compressed_path
                return backup_path
            else:
                raise Exception("Backup file is empty or doesn't exist")
                
        except subprocess.CalledProcessError as e:
            logger.error(f"pg_dump failed: {e.stderr}")
            if backup_path.exists():
                backup_path.unlink()
            raise
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            if backup_path.exists():
                backup_path.unlink()
            raise
    
    def create_application_backup(self):
        """Create backup of application files and configuration"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"websecpen_app_backup_{timestamp}.tar.gz"
        backup_path = self.backup_dir / backup_filename
        
        try:
            # Files and directories to backup
            backup_items = [
                'models.py',
                'app.py',
                'scanner.py',
                'nlp_service.py',
                'requirements.txt',
                '.env',
                'instance/',  # SQLite database if used
                'logs/',      # Application logs
                'uploads/'    # Any uploaded files
            ]
            
            # Create tar.gz archive
            cmd = ['tar', '-czf', str(backup_path)]
            
            # Add existing files to the archive
            for item in backup_items:
                if os.path.exists(item):
                    cmd.append(item)
            
            if len(cmd) > 3:  # If we have files to backup
                logger.info(f"Starting application backup to {backup_path}")
                
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                
                if backup_path.exists() and backup_path.stat().st_size > 0:
                    logger.info(f"Application backup completed successfully: {backup_path}")
                    return backup_path
                else:
                    raise Exception("Application backup file is empty or doesn't exist")
            else:
                logger.warning("No application files found to backup")
                return None
                
        except subprocess.CalledProcessError as e:
            logger.error(f"tar command failed: {e.stderr}")
            if backup_path.exists():
                backup_path.unlink()
            raise
        except Exception as e:
            logger.error(f"Application backup failed: {e}")
            if backup_path.exists():
                backup_path.unlink()
            raise
    
    def compress_backup(self, file_path):
        """Compress backup file using gzip"""
        try:
            compressed_path = Path(str(file_path) + '.gz')
            
            with open(file_path, 'rb') as f_in:
                with open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    
            # Use gzip for better compression
            cmd = ['gzip', '-9', str(file_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if compressed_path.exists():
                logger.info(f"Backup compressed successfully: {compressed_path}")
                return compressed_path
            else:
                return file_path
                
        except Exception as e:
            logger.error(f"Compression failed: {e}")
            return file_path
    
    def upload_to_s3(self, file_path, s3_key=None):
        """Upload backup file to AWS S3"""
        if not self.s3_client or not self.s3_bucket:
            logger.warning("S3 not configured, skipping cloud backup")
            return False
        
        if not s3_key:
            s3_key = f"backups/{file_path.name}"
        
        try:
            logger.info(f"Uploading {file_path} to S3 bucket {self.s3_bucket}")
            
            # Upload file with metadata
            self.s3_client.upload_file(
                str(file_path),
                self.s3_bucket,
                s3_key,
                ExtraArgs={
                    'Metadata': {
                        'created_at': datetime.datetime.now().isoformat(),
                        'source': 'websecpen-backup',
                        'type': 'database' if 'db_backup' in file_path.name else 'application'
                    },
                    'StorageClass': 'STANDARD_IA'  # Cheaper storage for backups
                }
            )
            
            logger.info(f"Upload completed successfully: s3://{self.s3_bucket}/{s3_key}")
            return True
            
        except ClientError as e:
            logger.error(f"S3 upload failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during S3 upload: {e}")
            return False
    
    def cleanup_old_backups(self):
        """Remove old backup files based on retention policy"""
        try:
            # Cleanup local backups
            now = datetime.datetime.now()
            cutoff_date = now - datetime.timedelta(days=self.local_retention_days)
            
            removed_count = 0
            for backup_file in self.backup_dir.glob('websecpen_*_backup_*.sql*'):
                if backup_file.stat().st_mtime < cutoff_date.timestamp():
                    backup_file.unlink()
                    removed_count += 1
                    logger.info(f"Removed old local backup: {backup_file}")
            
            logger.info(f"Cleaned up {removed_count} old local backups")
            
            # Cleanup S3 backups if configured
            if self.s3_client and self.s3_bucket:
                self.cleanup_s3_backups()
                
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
    
    def cleanup_s3_backups(self):
        """Remove old S3 backup files"""
        try:
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=self.s3_retention_days)
            
            response = self.s3_client.list_objects_v2(
                Bucket=self.s3_bucket,
                Prefix='backups/'
            )
            
            removed_count = 0
            if 'Contents' in response:
                for obj in response['Contents']:
                    if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                        self.s3_client.delete_object(
                            Bucket=self.s3_bucket,
                            Key=obj['Key']
                        )
                        removed_count += 1
                        logger.info(f"Removed old S3 backup: {obj['Key']}")
            
            logger.info(f"Cleaned up {removed_count} old S3 backups")
            
        except Exception as e:
            logger.error(f"S3 cleanup failed: {e}")
    
    def create_backup_metadata(self, db_backup_path=None, app_backup_path=None):
        """Create metadata file for the backup"""
        metadata = {
            'timestamp': datetime.datetime.now().isoformat(),
            'version': '1.0',
            'database_backup': str(db_backup_path) if db_backup_path else None,
            'application_backup': str(app_backup_path) if app_backup_path else None,
            'environment': os.getenv('FLASK_ENV', 'production'),
            'database_host': self.db_host,
            'database_name': self.db_name
        }
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        metadata_path = self.backup_dir / f"backup_metadata_{timestamp}.json"
        
        try:
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Backup metadata created: {metadata_path}")
            return metadata_path
            
        except Exception as e:
            logger.error(f"Failed to create backup metadata: {e}")
            return None
    
    def full_backup(self):
        """Perform complete backup (database + application + upload to cloud)"""
        logger.info("Starting full backup process")
        backup_results = {
            'success': False,
            'database_backup': None,
            'application_backup': None,
            'metadata_file': None,
            's3_upload_success': False,
            'cleanup_success': False,
            'errors': []
        }
        
        try:
            # Create database backup
            try:
                db_backup_path = self.create_database_backup()
                backup_results['database_backup'] = str(db_backup_path)
                logger.info("Database backup completed")
            except Exception as e:
                backup_results['errors'].append(f"Database backup failed: {e}")
                logger.error(f"Database backup failed: {e}")
            
            # Create application backup
            try:
                app_backup_path = self.create_application_backup()
                if app_backup_path:
                    backup_results['application_backup'] = str(app_backup_path)
                    logger.info("Application backup completed")
            except Exception as e:
                backup_results['errors'].append(f"Application backup failed: {e}")
                logger.error(f"Application backup failed: {e}")
            
            # Create metadata
            try:
                metadata_path = self.create_backup_metadata(
                    backup_results.get('database_backup'),
                    backup_results.get('application_backup')
                )
                backup_results['metadata_file'] = str(metadata_path) if metadata_path else None
            except Exception as e:
                backup_results['errors'].append(f"Metadata creation failed: {e}")
                logger.error(f"Metadata creation failed: {e}")
            
            # Upload to S3 if configured
            upload_success = True
            if self.s3_client and self.s3_bucket:
                for backup_file in [backup_results.get('database_backup'), 
                                   backup_results.get('application_backup'),
                                   backup_results.get('metadata_file')]:
                    if backup_file and Path(backup_file).exists():
                        if not self.upload_to_s3(Path(backup_file)):
                            upload_success = False
            
            backup_results['s3_upload_success'] = upload_success
            
            # Cleanup old backups
            try:
                self.cleanup_old_backups()
                backup_results['cleanup_success'] = True
            except Exception as e:
                backup_results['errors'].append(f"Cleanup failed: {e}")
                logger.error(f"Cleanup failed: {e}")
            
            # Determine overall success
            backup_results['success'] = (
                bool(backup_results['database_backup']) and 
                len(backup_results['errors']) == 0
            )
            
            if backup_results['success']:
                logger.info("Full backup completed successfully")
            else:
                logger.warning(f"Backup completed with errors: {backup_results['errors']}")
            
            return backup_results
            
        except Exception as e:
            backup_results['errors'].append(f"Unexpected error: {e}")
            logger.error(f"Full backup failed: {e}")
            return backup_results

def main():
    """Main function for running backups via cron job"""
    backup_manager = BackupManager()
    results = backup_manager.full_backup()
    
    # Print results for logging
    print(json.dumps(results, indent=2))
    
    # Exit with appropriate code
    exit(0 if results['success'] else 1)

if __name__ == '__main__':
    main() 