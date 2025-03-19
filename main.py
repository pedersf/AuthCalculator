from flask import Flask, request, jsonify, send_from_directory
import hmac
import hashlib
import base64
import datetime
import os
import uuid
import threading
import time

app = Flask(__name__)

# Retrieve Secure API Key from Fly.io Environment
SECURE_API_KEY = os.getenv("SECURE_API_KEY", "default_secure_key")

# File Upload Directory
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)  # Ensure directory exists

# File retention time (in seconds)
DELETE_AFTER_DAYS = 10
DELETE_AFTER_SECONDS = DELETE_AFTER_DAYS * 24 * 60 * 60  # Convert days to seconds

def generate_auth_headers(api_key_id, api_secret, api_key_public_value, api_path):
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    
    if api_path.startswith("http"):
        api_path = api_path.split("/", 3)[-1]  # Keep only the path
    api_path = "/" + api_path.strip("/")  # Ensure leading slash
    
    string_to_sign = f"{api_key_id}:{timestamp}:{api_path}"
    signature = hmac.new(api_secret.encode(), string_to_sign.encode(), hashlib.sha384).digest()
    signature_base64 = base64.b64encode(signature).decode()
    
    auth_headers = {
        "X-AUTH-QUERYTIME": timestamp,
        "X-AUTH-KEY": f"{api_key_public_value}:{signature_base64}"
    }
    return auth_headers

@app.route("/")
def home():
    return "Flask API is running securely! Use /calculate-auth and /upload."

@app.route("/calculate-auth", methods=["GET"])
def calculate_auth():
    api_key = request.args.get("api_key")
    api_key_id = request.args.get("api_key_id")
    api_secret = request.args.get("api_secret")
    api_key_public_value = request.args.get("api_key_public_value")
    api_path = request.args.get("api_path")
    
    if not all([api_key, api_key_id, api_secret, api_key_public_value, api_path]):
        return jsonify({"error": "Missing required parameters"}), 400
    
    if api_key != SECURE_API_KEY:
        return jsonify({"error": "Unauthorized"}), 403
    
    auth_headers = generate_auth_headers(api_key_id, api_secret, api_key_public_value, api_path)
    return jsonify(auth_headers)

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    # Generate a unique filename
    unique_filename = f"{uuid.uuid4()}-{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)

    # Save the file
    try:
        file.save(file_path)
    except Exception as e:
        return jsonify({"error": f"Failed to save file: {str(e)}"}), 500

    # Force HTTPS in the download URL
    secure_host_url = request.host_url.replace("http://", "https://")

    return jsonify({
        "download_url": f"{secure_host_url}download/{unique_filename}",
        "original_filename": file.filename
    })

@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found or already deleted"}), 404

    # Schedule deletion after a successful download
    def delete_file():
        if os.path.exists(file_path):
            os.remove(file_path)

    threading.Timer(10, delete_file).start()  # Auto-delete after 10 seconds
    
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)

# Background task to delete files older than 10 days
def delete_old_files():
    while True:
        now = time.time()
        for filename in os.listdir(UPLOAD_DIR):
            file_path = os.path.join(UPLOAD_DIR, filename)
            if os.path.isfile(file_path):
                file_age = now - os.path.getctime(file_path)
                if file_age > DELETE_AFTER_SECONDS:
                    os.remove(file_path)
        time.sleep(3600)  # Run cleanup every hour

# Start cleanup thread
cleanup_thread = threading.Thread(target=delete_old_files, daemon=True)
cleanup_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)