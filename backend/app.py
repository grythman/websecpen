from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return {"message": "Flask backend running"}

# Your existing /login route remains here...

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
