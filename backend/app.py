from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return {"message": "Flask backend running"}

# Your existing /login route remains here...

@app.route('/scan/start', methods=['POST'])
def start_scan():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        url = data.get('url')
        scan_type = data.get('scan_type')

        # Validation
        if not url or not scan_type:
            return jsonify({'error': 'Missing url or scan_type'}), 400
            
        # URL validation
        import re
        url_pattern = r'^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&=]*)$'
        if not re.match(url_pattern, url):
            return jsonify({'error': 'Invalid URL format'}), 400
            
        # Scan type validation
        valid_scan_types = ['XSS', 'SQLi', 'CSRF', 'Directory']
        if scan_type not in valid_scan_types:
            return jsonify({'error': f'Invalid scan type. Supported types: {", ".join(valid_scan_types)}'}), 400

        # Mock OWASP ZAP integration (to be replaced in task 16)
        import random
        scan_id = random.randint(1, 10000)  # Generate random scan ID
        
        print(f"Starting {scan_type} scan for {url} with ID {scan_id}")
        
        return jsonify({
            'scan_id': scan_id, 
            'status': 'started',
            'message': f'{scan_type} scan initiated for {url}',
            'estimated_duration': '2-5 minutes'
        }), 200
        
    except Exception as e:
        print(f"Error starting scan: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/result/<scan_id>', methods=['GET'])
def get_scan_result(scan_id):
    # Mock data (to be replaced with actual ZAP results)
    try:
        scan_id_int = int(scan_id)
        
        # Mock detailed result data
        mock_result = {
            'scan_id': scan_id_int,
            'target_url': 'https://example.com',
            'scan_type': 'XSS',
            'scan_date': '2025-07-26',
            'status': 'Completed',
            'duration': '3m 45s',
            'vulnerabilities': [
                {
                    'id': 1,
                    'type': 'XSS',
                    'severity': 'High',
                    'title': 'Stored Cross-Site Scripting in Contact Form',
                    'description': 'User input is not properly sanitized before being stored and displayed.',
                    'location': '/contact.php',
                    'confidence': 95
                },
                {
                    'id': 2,
                    'type': 'XSS',
                    'severity': 'Medium',
                    'title': 'Reflected XSS in Search Parameter',
                    'description': 'Search query parameter is reflected without proper encoding.',
                    'location': '/search?q=<script>alert(1)</script>',
                    'confidence': 88
                }
            ],
            'summary': {
                'total_pages_scanned': 45,
                'total_requests': 128,
                'high_severity': 1,
                'medium_severity': 1,
                'low_severity': 0,
                'info_severity': 2
            }
        }
        
        return jsonify(mock_result), 200
        
    except ValueError:
        return jsonify({'error': 'Invalid scan ID format'}), 400
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get the current status of a scan"""
    try:
        scan_id_int = int(scan_id)
        
        # Mock status data
        import random
        statuses = ['Running', 'Completed', 'Failed']
        status = random.choice(statuses)
        
        result = {
            'scan_id': scan_id_int,
            'status': status,
            'progress': random.randint(0, 100) if status == 'Running' else 100,
            'pages_scanned': random.randint(10, 50),
            'issues_found': random.randint(0, 5) if status == 'Completed' else 0
        }
        
        return jsonify(result), 200
        
    except ValueError:
        return jsonify({'error': 'Invalid scan ID format'}), 400
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scans', methods=['GET'])
def get_all_scans():
    """Get all scans for the user"""
    try:
        # Mock scan history data
        mock_scans = [
            { 
                'id': 1, 
                'url': 'https://example.com', 
                'date': '2025-07-26', 
                'status': 'Completed', 
                'scanType': 'XSS',
                'vulnerabilities': 3,
                'severity': 'High'
            },
            { 
                'id': 2, 
                'url': 'https://test.com', 
                'date': '2025-07-25', 
                'status': 'Failed', 
                'scanType': 'SQLi',
                'vulnerabilities': 0,
                'severity': 'N/A'
            },
            { 
                'id': 3, 
                'url': 'https://demo.com', 
                'date': '2025-07-24', 
                'status': 'Completed', 
                'scanType': 'CSRF',
                'vulnerabilities': 1,
                'severity': 'Medium'
            }
        ]
        
        return jsonify({'scans': mock_scans, 'total': len(mock_scans)}), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'WebSecPen API',
        'version': '1.0.0',
        'timestamp': '2025-07-26T12:00:00Z'
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
