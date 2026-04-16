"""
Security vulnerability test file — Python
30 intentional vulnerabilities for rule coverage testing.
DO NOT USE IN PRODUCTION.

NOTE: All vulnerabilities are INTENTIONAL for security scanner validation.
"""

import os
import hashlib
import pickle  # nosec — intentional for testing
import subprocess  # nosec — intentional for testing
import sqlite3
import random
import yaml
import xml.etree.ElementTree as ET
import requests as http_requests
from flask import Flask, request, redirect, render_template_string, jsonify

app = Flask(__name__)

# =================================================================
# 1. SQL Injection — string concat + f-string
# =================================================================
def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()

def delete_user(user_id):
    conn = sqlite3.connect("app.db")
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()

def search(keyword):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM posts WHERE body LIKE '%{keyword}%'")
    return cursor.fetchall()

# =================================================================
# 2. XSS — template injection
# =================================================================
@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string(f"<h1>Hello {name}</h1>")

@app.route("/preview")
def preview():
    html = request.args.get("html", "")
    return render_template_string(html)

# =================================================================
# 3. Command injection — os.system + subprocess shell=True
# All intentional for scanner testing (nosec)
# =================================================================
def ping(host):
    os.system("ping -c 4 " + host)  # nosec

def grep_logs(pattern):
    output = subprocess.check_output(  # nosec
        "grep " + pattern + " /var/log/app.log", shell=True
    )
    return output

def tail_file(filename):
    result = subprocess.Popen(  # nosec
        f"tail -100 {filename}",
        shell=True,
        stdout=subprocess.PIPE,
    )
    return result.stdout.read()

def run_script(name):
    subprocess.run("bash /scripts/" + name, shell=True)  # nosec

def call_tool(cmd):
    subprocess.call(cmd, shell=True)  # nosec

# =================================================================
# 4. Hardcoded secrets
# =================================================================
SECRET_KEY = "flask-secret-key-do-not-share"
DATABASE_URL = "postgresql://admin:p@ssw0rd@prod-db:5432/app"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "stripe_secret_EXAMPLE_DO_NOT_USE"
SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxx"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."

app.config["SECRET_KEY"] = "hardcoded-123"

# =================================================================
# 5. Insecure deserialization (all intentional — nosec)
# =================================================================
def load_session(cookie_data):
    import base64
    return pickle.loads(base64.b64decode(cookie_data))  # nosec

def parse_yaml(raw):
    return yaml.load(raw, Loader=yaml.Loader)  # nosec

def parse_unsafe_yaml(raw):
    return yaml.unsafe_load(raw)  # nosec

# =================================================================
# 6. Path traversal
# =================================================================
@app.route("/download")
def download():
    filename = request.args.get("file")
    with open("/uploads/" + filename, "rb") as f:
        return f.read()

@app.route("/avatar/<username>")
def avatar(username):
    return open(f"/data/avatars/{username}.png", "rb").read()

# =================================================================
# 7. SSRF
# =================================================================
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    resp = http_requests.get(url)
    return resp.text

@app.route("/webhook")
def send_webhook():
    target = request.json["callback"]
    http_requests.post(target, json={"ok": True})
    return "sent"

@app.route("/proxy")
def proxy():
    dest = request.args.get("dest")
    http_requests.put(dest, data=request.get_data())
    return "ok"

# =================================================================
# 8. Weak cryptography
# =================================================================
def hash_pw(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()

def weak_token(user_id):
    return hashlib.md5(f"{user_id}-token".encode()).hexdigest()

# =================================================================
# 9. Insecure random
# =================================================================
def otp():
    return random.randint(100000, 999999)

def session_id():
    chars = "abcdef0123456789"
    return "".join(random.choice(chars) for _ in range(32))

def coin_flip():
    return random.random() > 0.5

# =================================================================
# 10. Open redirect
# =================================================================
@app.route("/login-redirect")
def login_redirect():
    next_url = request.args.get("next", "/")
    return redirect(next_url)

@app.route("/oauth/callback")
def oauth_callback():
    return_to = request.args.get("return_to")
    return redirect(return_to)

# =================================================================
# 11. Sensitive data exposure — print/log
# =================================================================
def authenticate(username, password):
    print(f"Auth: user={username}, pass={password}")
    return True

def process_payment(card, cvv):
    print(f"Payment: card={card}, cvv={cvv}")

# =================================================================
# 12. Debug / environment exposure
# =================================================================
@app.route("/debug")
def debug():
    return jsonify({
        "env": dict(os.environ),
        "config": str(app.config),
    })

# =================================================================
# 13. Mass assignment
# =================================================================
def update_profile(user_id, data):
    conn = sqlite3.connect("app.db")
    for key, val in data.items():
        conn.execute(f"UPDATE users SET {key} = '{val}' WHERE id = {user_id}")
    conn.commit()

# =================================================================
# 14. XXE
# =================================================================
def parse_xml(raw):
    return ET.fromstring(raw)

# =================================================================
# 15. Timing attack
# =================================================================
def check_token(provided, stored):
    return provided == stored  # not timing-safe

# =================================================================
# 16. CORS wildcard
# =================================================================
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response
