#!/usr/bin/env python3
"""
Database creation script to ensure all tables are created with correct schema
"""
from flask import Flask
from models import db, User, Scan, Vulnerability, Feedback, ApiKey, Badge
import os

def create_database():
    # Create a minimal Flask app
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///websecpen.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    db.init_app(app)
    
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Create default admin user
        admin_user = User(
            email='admin@websecpen.com',
            first_name='Admin',
            last_name='User',
            is_admin=True,
            role='admin',
            scan_limit=999999
        )
        admin_user.set_password('admin123')
        db.session.add(admin_user)
        
        # Create a test user
        test_user = User(
            email='test@websecpen.com',
            first_name='Test',
            last_name='User',
            is_admin=False,
            role='free',
            scan_limit=10
        )
        test_user.set_password('test123')
        db.session.add(test_user)
        
        # Commit changes
        db.session.commit()
        
        print("✅ Database created successfully!")
        print("Admin user: admin@websecpen.com / admin123")
        print("Test user: test@websecpen.com / test123")

if __name__ == '__main__':
    create_database() 