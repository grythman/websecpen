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
    data = request.get_json()
    url = data.get('url')
    scan_type = data.get('scan_type')

    if not url or not scan_type:
        return jsonify({'error': 'Missing url or scan_type'}), 400
    if scan_type not in ['XSS', 'SQLi']:
        return jsonify({'error': 'Invalid scan type'}), 400

    # Mock OWASP ZAP integration (to be replaced in task 16)
    scan_id = 1  # Replace with actual logic
    return jsonify({'scan_id': scan_id, 'status': 'started'}), 200

@app.route('/scan/result/&lt;scan_id&gt;', methods=['GET'])
def get_scan_result(scan_id):
    # Mock data (to be replaced with actual ZAP results)
    if scan_id != '1':
        return jsonify({'error': 'Invalid scan ID'}), 404
    return jsonify({
        'scan_id': scan_id,
        'vulnerabilities': ['XSS', 'SQLi'],
        'details': 'Mock details'
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
