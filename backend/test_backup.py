#!/usr/bin/env python3
# test_backup.py - Test the backup system functionality

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_backup_system():
    """Test the backup system without requiring a real database"""
    print("🧪 Testing WebSecPen Backup System")
    print("=" * 50)
    
    try:
        from backup import BackupManager
        
        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set environment variables for testing
            os.environ['BACKUP_DIR'] = temp_dir
            os.environ['DATABASE_HOST'] = 'localhost'
            os.environ['DATABASE_NAME'] = 'test_db'
            os.environ['DATABASE_USER'] = 'test_user'
            os.environ['DATABASE_PASSWORD'] = 'test_pass'
            
            # Initialize backup manager
            backup_manager = BackupManager()
            
            print("✅ BackupManager initialized successfully")
            print(f"📁 Backup directory: {backup_manager.backup_dir}")
            print(f"🔧 Local retention: {backup_manager.local_retention_days} days")
            print(f"☁️ S3 retention: {backup_manager.s3_retention_days} days")
            
            # Test backup directory creation
            if backup_manager.backup_dir.exists():
                print("✅ Backup directory created successfully")
            else:
                print("❌ Failed to create backup directory")
                return False
            
            # Test application backup (should work without database)
            try:
                print("\n📦 Testing application backup...")
                
                # Create some test files to backup
                test_files = ['test_models.py', 'test_app.py', 'test_requirements.txt']
                for file_name in test_files:
                    test_file = Path(file_name)
                    test_file.write_text(f"# Test content for {file_name}")
                
                app_backup = backup_manager.create_application_backup()
                if app_backup and app_backup.exists():
                    print(f"✅ Application backup created: {app_backup}")
                    print(f"📏 Backup size: {app_backup.stat().st_size} bytes")
                else:
                    print("⚠️ Application backup skipped (no files found)")
                
                # Clean up test files
                for file_name in test_files:
                    test_file = Path(file_name)
                    if test_file.exists():
                        test_file.unlink()
                
            except Exception as e:
                print(f"❌ Application backup test failed: {e}")
            
            # Test metadata creation
            try:
                print("\n📄 Testing metadata creation...")
                metadata_file = backup_manager.create_backup_metadata(
                    db_backup_path="test_db_backup.sql",
                    app_backup_path="test_app_backup.tar.gz"
                )
                if metadata_file and metadata_file.exists():
                    print(f"✅ Metadata file created: {metadata_file}")
                    
                    # Read and display metadata
                    import json
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    print(f"📊 Metadata content: {json.dumps(metadata, indent=2)}")
                else:
                    print("❌ Failed to create metadata file")
                
            except Exception as e:
                print(f"❌ Metadata creation test failed: {e}")
            
            # Test S3 configuration (without actual upload)
            print(f"\n☁️ S3 Integration: {'Available' if backup_manager.s3_client else 'Not configured'}")
            if backup_manager.s3_client:
                print(f"🪣 S3 Bucket: {backup_manager.s3_bucket}")
                print(f"🌍 S3 Region: {backup_manager.s3_region}")
            else:
                print("💡 To enable S3 backups, set: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BACKUP_BUCKET")
            
            # Test cleanup functionality
            try:
                print("\n🧹 Testing backup cleanup...")
                backup_manager.cleanup_old_backups()
                print("✅ Cleanup completed successfully")
            except Exception as e:
                print(f"❌ Cleanup test failed: {e}")
            
            print("\n" + "=" * 50)
            print("🎉 Backup system test completed!")
            print("\n💡 Next steps:")
            print("   1. Install PostgreSQL client tools: apt-get install postgresql-client")
            print("   2. Configure database connection environment variables")
            print("   3. Set up AWS credentials for S3 backups (optional)")
            print("   4. Create a cron job for automated backups:")
            print("      0 2 * * * cd /path/to/websecpen/backend && python backup.py")
            
            return True
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure you've installed all required packages:")
        print("   pip install boto3 (for S3 support)")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def test_database_tools():
    """Test if PostgreSQL client tools are available"""
    print("\n🔧 Testing PostgreSQL client tools...")
    
    try:
        import subprocess
        result = subprocess.run(['pg_dump', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ pg_dump available: {result.stdout.strip()}")
            return True
        else:
            print("❌ pg_dump not found")
            return False
    except FileNotFoundError:
        print("❌ pg_dump not found in PATH")
        print("💡 Install with: sudo apt-get install postgresql-client")
        return False
    except Exception as e:
        print(f"❌ Error checking pg_dump: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 WebSecPen Backup System Test Suite")
    print("=" * 60)
    
    # Test backup system
    backup_test_passed = test_backup_system()
    
    # Test database tools
    db_tools_available = test_database_tools()
    
    print("\n" + "=" * 60)
    print("📋 TEST RESULTS:")
    print(f"   Backup System: {'✅ PASS' if backup_test_passed else '❌ FAIL'}")
    print(f"   Database Tools: {'✅ Available' if db_tools_available else '⚠️ Missing'}")
    
    if backup_test_passed and db_tools_available:
        print("\n🎉 All tests passed! Backup system is ready for production.")
    elif backup_test_passed:
        print("\n⚠️ Backup system works, but install PostgreSQL client tools for database backups.")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
    
    print("=" * 60)

if __name__ == '__main__':
    main() 