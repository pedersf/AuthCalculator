import os
import hmac
import hashlib
import base64
import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# Retrieve secure API key from environment variables
SECURE_API_KEY = os.getenv("SECURE_API_KEY", "")

def generate_auth_headers(api_key_id, api_secret, api_path):
    # 🔹 Generate UTC Timestamp
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

    # 🔹 Ensure the API path is correct (strip domain & trailing slash)
    if api_path.startswith("http"):
        api_path = api_path.split("/", 3)[-1]  # Keep only the path
    api_path = "/" + api_path.strip("/")  # Ensure leading slash

    # 🔹 Construct the string to sign
    string_to_sign = f"{api_key_id}:{timestamp}:{api_path}"

    # 🔹 Generate HMAC-SHA-384 Signature
    signature = hmac.new(api_secret.encode(), string_to_sign.encode(), hashlib.sha384).digest()

    # 🔹 Base64 Encode the Signature
    signature_base64 = base64.b64encode(signature).decode()

    # 🔹 Construct Authentication Headers
    auth_headers = {
        "X-AUTH-QUERYTIME": timestamp,
        "X-AUTH-KEY": f"{api_key_id}:{signature_base64}"
    }

    return auth_headers

@app.route("/")
def home():
    return "Flask API is running securely! Use /calculate-auth with API_KEY."

@app.route("/calculate-auth", methods=["GET"])
def calculate_auth():
    api_key = request.args.get("api_key")
    api_key_id = request.args.get("api_key_id")
    api_secret = request.args.get("api_secret")
    api_path = request.args.get("api_path")

    # Debugging: Log received API key and expected API key
    print(f"🔹 Received API Key: {api_key}")
    print(f"🔹 Expected API Key: {SECURE_API_KEY}")

    # Validate API key
    if api_key != SECURE_API_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    # Validate required parameters
    if not all([api_key_id, api_secret, api_path]):
        return jsonify({"error": "Missing required parameters"}), 400

    # Generate and return authentication headers
    auth_headers = generate_auth_headers(api_key_id, api_secret, api_path)
    return jsonify(auth_headers)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)