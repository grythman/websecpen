# dummy_target.py - Vulnerable Flask app for testing security scans
from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_123'

# Initialize vulnerable database
def init_db():
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Create users table (vulnerable to SQLi)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    
    # Insert test data
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123', 'admin@test.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user123', 'user@test.com')")
    
    conn.commit()
    conn.close()

# Vulnerable XSS endpoint
@app.route('/')
def home():
    return '''
    <h1>Vulnerable Test Application</h1>
    <p>This app contains intentional vulnerabilities for testing:</p>
    <ul>
        <li><a href="/xss">XSS Vulnerability Test</a></li>
        <li><a href="/sqli">SQL Injection Test</a></li>
        <li><a href="/csrf">CSRF Test</a></li>
        <li><a href="/directory">Directory Traversal Test</a></li>
    </ul>
    '''

# XSS Vulnerability (Reflected)
@app.route('/xss')
def xss_test():
    user_input = request.args.get('input', 'Enter input in URL: ?input=<script>alert("XSS")</script>')
    # Intentionally vulnerable - no escaping
    return f'''
    <h2>XSS Test Page</h2>
    <p>User input: {user_input}</p>
    <form method="GET">
        <input type="text" name="input" placeholder="Enter text here" value="{user_input}">
        <button type="submit">Submit</button>
    </form>
    '''

# SQL Injection Vulnerability
@app.route('/sqli')
def sqli_test():
    username = request.args.get('username', '')
    if username:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Intentionally vulnerable SQL query
        query = f"SELECT * FROM users WHERE username = '{username}'"
        try:
            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()
            
            if results:
                return f'''
                <h2>SQL Injection Test</h2>
                <p>Query: {query}</p>
                <p>Results: {results}</p>
                <a href="/sqli">Try again</a>
                '''
            else:
                return f'''
                <h2>SQL Injection Test</h2>
                <p>No user found for: {username}</p>
                <p>Try: admin' OR '1'='1</p>
                <a href="/sqli">Try again</a>
                '''
        except Exception as e:
            conn.close()
            return f'''
            <h2>SQL Injection Test</h2>
            <p>SQL Error: {str(e)}</p>
            <a href="/sqli">Try again</a>
            '''
    
    return '''
    <h2>SQL Injection Test</h2>
    <form method="GET">
        <input type="text" name="username" placeholder="Enter username">
        <button type="submit">Login</button>
    </form>
    <p>Try: admin' OR '1'='1</p>
    '''

# CSRF Vulnerability
@app.route('/csrf', methods=['GET', 'POST'])
def csrf_test():
    if request.method == 'POST':
        email = request.form.get('email', '')
        # No CSRF token validation - vulnerable
        return f'''
        <h2>CSRF Test Result</h2>
        <p>Email changed to: {email}</p>
        <p>This would be vulnerable to CSRF attacks!</p>
        <a href="/csrf">Back</a>
        '''
    
    return '''
    <h2>CSRF Test Page</h2>
    <form method="POST">
        <label>Change Email:</label>
        <input type="email" name="email" required>
        <button type="submit">Update</button>
    </form>
    <p>This form has no CSRF protection!</p>
    '''

# Directory Traversal Vulnerability
@app.route('/directory')
def directory_test():
    filename = request.args.get('file', 'test.txt')
    try:
        # Intentionally vulnerable - no path validation
        with open(filename, 'r') as f:
            content = f.read()
        return f'''
        <h2>Directory Traversal Test</h2>
        <p>File: {filename}</p>
        <pre>{content}</pre>
        <form method="GET">
            <input type="text" name="file" value="{filename}">
            <button type="submit">Read File</button>
        </form>
        <p>Try: ../../../etc/passwd (on Linux) or ..\..\..\windows\system32\drivers\etc\hosts</p>
        '''
    except Exception as e:
        return f'''
        <h2>Directory Traversal Test</h2>
        <p>Error reading {filename}: {str(e)}</p>
        <form method="GET">
            <input type="text" name="file" value="{filename}">
            <button type="submit">Read File</button>
        </form>
        '''

# Create a test file for directory traversal
@app.route('/create-test-file')
def create_test_file():
    with open('test.txt', 'w') as f:
        f.write('This is a test file for directory traversal testing.\nContains harmless content.')
    return 'Test file created! <a href="/directory">Test directory traversal</a>'

if __name__ == '__main__':
    init_db()
    print("Starting vulnerable test application...")
    print("Available endpoints:")
    print("- http://localhost:8080/ - Home page")
    print("- http://localhost:8080/xss - XSS testing")
    print("- http://localhost:8080/sqli - SQL injection testing")
    print("- http://localhost:8080/csrf - CSRF testing")
    print("- http://localhost:8080/directory - Directory traversal testing")
    app.run(debug=True, host='0.0.0.0', port=8080) 