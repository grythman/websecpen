import requests

ZAP_API_URL = "http://localhost:8080/JSON/core/view/version"
API_KEY = "your-zap-api-key"  # Replace with actual API key

response = requests.get(ZAP_API_URL, params={"apikey": API_KEY})
print(response.json())  # Should return ZAP version 