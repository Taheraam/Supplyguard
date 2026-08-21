"""Vulnerable Demo Application for SupplyGuard Testing and Demonstration."""

import hashlib
import random
import sqlite3
import subprocess

import jwt
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# 1. Hardcoded Secret (CWE-798) - clearly fake
STRIPE_API_KEY = "FAKE_KEY_FOR_TESTING_DO_NOT_USE"


@app.route("/")
def home():
    return jsonify({"status": "running", "service": "vulnerable-demo-app"})


# 2. SQL Injection via string formatting (CWE-89)
@app.route("/users/<user_id>")
def get_user(user_id):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    row = cursor.fetchone()
    return jsonify({"user": row})


# 3. Unprotected Admin Deletion Route (CWE-862)
@app.route("/admin/users/<user_id>/delete", methods=["DELETE"])
def delete_user(user_id):
    return jsonify({"deleted": user_id})


# 4. Insecure subprocess with shell=True (CWE-78)
@app.route("/diagnostics/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    cmd = f"ping -c 1 {host}"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({"output": res.stdout})


# 5. Outbound request with verify=False (CWE-295)
@app.route("/fetch-external")
def fetch_external():
    resp = requests.get("https://insecure.example.com", verify=False)
    return jsonify({"status": resp.status_code})


# 6. Weak password hash MD5 (CWE-916)
@app.route("/auth/hash-password", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "")
    hashed = hashlib.md5(pwd.encode()).hexdigest()
    return jsonify({"hash": hashed})


# 7. Unverified JWT Decode (CWE-347)
@app.route("/auth/verify-token", methods=["POST"])
def verify_token():
    token = request.json.get("token", "")
    payload = jwt.decode(token, verify=False)
    return jsonify({"payload": payload})


# 8. Insecure Pseudo-Random for Auth Token (CWE-330)
@app.route("/auth/generate-session")
def generate_session():
    auth_token = f"sess_{random.randint(100000, 999999)}"
    return jsonify({"session_token": auth_token})


# 9. Dynamic code execution with eval (CWE-94)
@app.route("/calculate")
def calculate():
    expr = request.args.get("expr", "1+1")
    res = eval(expr)
    return jsonify({"result": res})


# 10. CORS Wildcard with Credentials (CWE-942)
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


if __name__ == "__main__":
    # 11. Debug mode enabled in entrypoint (CWE-489)
    app.run(host="0.0.0.0", port=8000, debug=True)
