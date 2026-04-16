# spectrum_vulns.py — Python Vulnerability Spectrum (40 vulnerabilities)
# PURPOSE: Test fixture for scanner validation — ALL code is INTENTIONALLY vulnerable
# TIER 1: 01-10 (Easy/Textbook), TIER 2: 11-20 (Medium), TIER 3: 21-30 (Hard), TIER 4: 31-40 (Expert)
# Total: 40 vulnerabilities across SQL Injection, XSS, Command Injection, Path Traversal,
# SSRF, Hardcoded Secrets, Weak Crypto, Insecure Deserialization, Open Redirect,
# Sensitive Data Exposure, XXE, ReDoS, Race Conditions, SSTI, Zip Slip, etc.

import os
import re
import ssl
import json
import yaml
import pickle
import hashlib
import sqlite3
import zipfile
import logging
import subprocess
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect, render_template_string, make_response, jsonify, send_file
from jinja2 import Template
import requests
import hmac

app = Flask(__name__)

DATABASE = "/var/app/data.db"
UPLOAD_DIR = "/var/uploads"

# ============================================================================
# TIER 1 — EASY (01-10): Textbook patterns
# ============================================================================

# VULN-01 [TIER-1]: SQL Injection - Direct string concatenation
@app.route("/api/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # nosec
    return jsonify(cursor.fetchall())

# VULN-02 [TIER-1]: Command Injection - Direct os.system with user input
@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    result = os.system("ping -c 4 " + host)  # nosec
    return str(result)

# VULN-03 [TIER-1]: XSS / SSTI - Direct render_template_string with user input
@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "!</h1>")  # nosec

# VULN-04 [TIER-1]: Path Traversal - Direct user input in open()
@app.route("/read-file")
def read_file():
    filename = request.args.get("file")
    with open("/var/data/" + filename, "r") as f:  # nosec
        return f.read()

# VULN-05 [TIER-1]: Hardcoded Secrets - Credentials in source
SECRET_KEY = "super_secret_flask_key_12345"  # nosec
DB_PASSWORD = "ProductionDB_P@ss!"  # nosec
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # nosec
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # nosec

# VULN-06 [TIER-1]: Weak Crypto - MD5 for password hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # nosec

# VULN-07 [TIER-1]: Insecure Deserialization - pickle.loads on user data
@app.route("/api/restore", methods=["POST"])
def restore_session():
    data = request.get_data()
    session_obj = pickle.loads(data)  # nosec
    return jsonify(session_obj)

# VULN-08 [TIER-1]: Eval - Direct eval of user input (INTENTIONAL TEST FIXTURE)
@app.route("/calc")
def calculator():
    expression = request.args.get("expr")
    result = eval(expression)  # nosec — intentional vulnerability for scanner testing
    return str(result)

# VULN-09 [TIER-1]: Open Redirect - Unvalidated redirect
@app.route("/redirect")
def open_redirect():
    target = request.args.get("url")
    return redirect(target)  # nosec

# VULN-10 [TIER-1]: Insecure Cookie - Session cookie without secure flags
@app.route("/login", methods=["POST"])
def login():
    resp = make_response("logged in")
    resp.set_cookie("session_id", "abc123", httponly=False, secure=False)  # nosec
    return resp

# ============================================================================
# TIER 2 — MEDIUM (11-20): One level of indirection
# ============================================================================

# VULN-11 [TIER-2]: SQL Injection - Variable then format string
@app.route("/api/search")
def search_products():
    search_term = request.args.get("q")
    conn = sqlite3.connect(DATABASE)
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % search_term  # nosec
    cursor = conn.cursor()
    cursor.execute(query)
    return jsonify(cursor.fetchall())

# VULN-12 [TIER-2]: Command Injection - subprocess with shell=True and user input
@app.route("/api/convert", methods=["POST"])
def convert_file():
    filename = request.form.get("filename")
    output_format = request.form.get("format")
    cmd = f"convert {filename} output.{output_format}"
    subprocess.run(cmd, shell=True, capture_output=True)  # nosec
    return "converted"

# VULN-13 [TIER-2]: Hardcoded Secret - Config dictionary
config = {  # nosec
    "database": {
        "host": "db-master.internal.prod",
        "username": "app_svc",
        "password": "Kj8#mN2$xP9!qR4@",  # nosec
    },
    "api": {
        "secret_key": "stripe_secret_EXAMPLE_DO_NOT_USE",  # nosec
    },
}

# VULN-14 [TIER-2]: XSS - Template string with user variable
@app.route("/profile")
def user_profile():
    username = request.args.get("user")
    bio = request.args.get("bio")
    html = f"<html><body><h1>{username}</h1><p>{bio}</p></body></html>"  # nosec
    return html

# VULN-15 [TIER-2]: Path Traversal - Variable assignment then use
@app.route("/download")
def download_file():
    requested = request.args.get("file")
    filepath = os.path.join("/uploads", requested)
    return send_file(filepath)  # nosec

# VULN-16 [TIER-2]: SSRF - URL from user passed to requests.get
@app.route("/api/fetch")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)  # nosec
    return response.text

# VULN-17 [TIER-2]: Sensitive Data Exposure - Logging passwords
@app.route("/api/register", methods=["POST"])
def register_user():
    username = request.form.get("username")
    password = request.form.get("password")
    logging.info(f"New registration: {username} with password {password}")  # nosec
    return "registered"

# VULN-18 [TIER-2]: SQL Injection - f-string in query
@app.route("/api/orders")
def get_orders():
    table = request.args.get("table")
    status = request.args.get("status")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table} WHERE status = '{status}'")  # nosec
    return jsonify(cursor.fetchall())

# VULN-19 [TIER-2]: YAML Deserialization - yaml.load without SafeLoader
@app.route("/api/import", methods=["POST"])
def import_config():
    yaml_data = request.get_data(as_text=True)
    parsed = yaml.load(yaml_data)  # nosec — missing Loader=SafeLoader
    return jsonify(parsed)

# VULN-20 [TIER-2]: Weak Crypto - SHA1 for tokens
def generate_api_token(user_id):
    return hashlib.sha1(f"{user_id}-secret".encode()).hexdigest()  # nosec

# ============================================================================
# TIER 3 — HARD (21-30): Framework patterns & indirect flow
# ============================================================================

# VULN-21 [TIER-3]: SQL Injection - 3+ hops through helper functions
def get_filter_param(req, name):
    return req.args.get(name)

def build_where(column, value):
    return f"{column} = '{value}'"

@app.route("/api/products")
def list_products():
    category = get_filter_param(request, "category")
    sort_col = get_filter_param(request, "sort")
    where = build_where("category", category)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE " + where + " ORDER BY " + sort_col)  # nosec
    return jsonify(cursor.fetchall())

# VULN-22 [TIER-3]: SSTI - Jinja2 template injection through variable
@app.route("/api/preview", methods=["POST"])
def preview_template():
    template_content = request.form.get("template")
    user_data = request.form.get("data")
    tmpl = Template(template_content)  # nosec — user controls template
    return tmpl.render(data=user_data)

# VULN-23 [TIER-3]: Command Injection - Through Flask before_request decorator
@app.before_request
def log_request():
    user_agent = request.headers.get("User-Agent", "unknown")
    # Stores in request context
    request.environ["cleaned_ua"] = user_agent

@app.route("/api/analytics")
def analytics():
    ua = request.environ.get("cleaned_ua", "")
    cmd = f"echo '{ua}' >> /var/log/user_agents.log"
    os.popen(cmd)  # nosec
    return "logged"

# VULN-24 [TIER-3]: SSRF - User controls host in constructed internal URL
@app.route("/api/service-status")
def service_status():
    service = request.args.get("service")
    port = request.args.get("port", "8080")
    url = f"http://{service}.internal.cluster:{port}/health"
    response = requests.get(url, timeout=5)  # nosec
    return jsonify({"status": response.status_code})

# VULN-25 [TIER-3]: XXE - XML parsing with external entity support
@app.route("/api/parse-xml", methods=["POST"])
def parse_xml():
    xml_data = request.get_data(as_text=True)
    # Default ET.fromstring doesn't disable external entities in all configurations
    root = ET.fromstring(xml_data)  # nosec
    return jsonify({"root_tag": root.tag, "text": root.text})

# VULN-26 [TIER-3]: Path Traversal - Second-order via database
@app.route("/api/avatar/<int:user_id>")
def get_avatar(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT avatar_filename FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    avatar_name = row[0]  # attacker stored "../../../../etc/passwd"
    return send_file(os.path.join(UPLOAD_DIR, avatar_name))  # nosec — second-order

# VULN-27 [TIER-3]: Timing Attack - Non-constant-time comparison
@app.route("/api/webhook", methods=["POST"])
def webhook_handler():
    provided_sig = request.headers.get("X-Signature")
    expected_sig = hmac.new(config["api"]["secret_key"].encode(),
                            request.get_data(),
                            hashlib.sha256).hexdigest()
    if provided_sig == expected_sig:  # nosec — timing attack
        return "accepted"
    return "rejected", 401

# VULN-28 [TIER-3]: Insecure Deserialization - pickle via base64 encoding
import base64
@app.route("/api/load-state", methods=["POST"])
def load_state():
    encoded = request.form.get("state")
    raw = base64.b64decode(encoded)
    state = pickle.loads(raw)  # nosec
    return jsonify(state)

# VULN-29 [TIER-3]: Open Redirect - Allowlist bypass with path
def is_safe_redirect(url):
    allowed_domains = ["myapp.com", "auth.myapp.com"]
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return any(parsed.hostname.endswith(d) for d in allowed_domains)  # nosec — evil-myapp.com
    except Exception:
        return False

@app.route("/auth/callback")
def auth_callback():
    redirect_url = request.args.get("redirect")
    if is_safe_redirect(redirect_url):
        return redirect(redirect_url)  # nosec
    return redirect("/")

# VULN-30 [TIER-3]: Weak Crypto - DES encryption
from Crypto.Cipher import DES  # nosec
def encrypt_data(data, key):
    cipher = DES.new(key.encode()[:8], DES.MODE_ECB)  # nosec — DES + ECB mode
    padded = data.ljust(8)
    return cipher.encrypt(padded.encode())

# ============================================================================
# TIER 4 — EXPERT (31-40): Subtle & realistic patterns
# ============================================================================

# VULN-31 [TIER-4]: Zip Slip - Archive extraction without path validation
@app.route("/api/upload-archive", methods=["POST"])
def upload_archive():
    archive = request.files.get("file")
    archive_path = os.path.join("/tmp", archive.filename)
    archive.save(archive_path)
    with zipfile.ZipFile(archive_path, "r") as zf:
        for member in zf.namelist():
            # No check for "../" in member names — Zip Slip
            zf.extract(member, UPLOAD_DIR)  # nosec
    return "extracted"

# VULN-32 [TIER-4]: Race Condition - TOCTOU in file permission check
@app.route("/api/delete-file", methods=["DELETE"])
def delete_user_file():
    filepath = request.args.get("path")
    full_path = os.path.join(UPLOAD_DIR, filepath)
    # Check if user owns the file
    if os.path.exists(full_path):  # nosec — TOCTOU
        owner = get_file_owner(full_path)
        if owner == request.headers.get("X-User-Id"):
            # Race window: file could be replaced with symlink between check and delete
            os.remove(full_path)  # nosec
            return "deleted"
    return "not found", 404

def get_file_owner(path):
    return "user123"  # simplified

# VULN-33 [TIER-4]: ReDoS - Catastrophic backtracking
@app.route("/api/validate", methods=["POST"])
def validate_input():
    pattern = request.form.get("pattern", "")
    text = request.form.get("text", "")
    # Even worse: user controls the regex pattern
    regex = re.compile(pattern)  # nosec — ReDoS + arbitrary regex from user
    match = regex.search(text)
    return jsonify({"matched": bool(match)})

# VULN-34 [TIER-4]: SSL/TLS - Disabled certificate verification
@app.route("/api/external-call")
def call_external():
    url = request.args.get("url")
    response = requests.get(url, verify=False)  # nosec — disables SSL verification
    return response.text

# VULN-35 [TIER-4]: Path Traversal - os.path.join doesn't prevent absolute paths
@app.route("/api/template")
def get_template():
    name = request.args.get("name")
    # Developer thinks os.path.join is safe
    template_path = os.path.join("/app/templates", name)  # nosec — /etc/passwd bypasses
    with open(template_path) as f:
        return f.read()

# VULN-36 [TIER-4]: SSTI - Conditional branch where only one path is vulnerable
@app.route("/api/render", methods=["POST"])
def render_content():
    content_type = request.form.get("type")
    content = request.form.get("content")
    if content_type == "markdown":
        # Safe path
        import markdown
        return markdown.markdown(content)
    else:
        # Vulnerable path — Jinja2 SSTI
        return render_template_string(content)  # nosec

# VULN-37 [TIER-4]: Encoded Command Injection - Base64 decoded then used
@app.route("/api/execute-task", methods=["POST"])
def execute_task():
    encoded_cmd = request.form.get("command")
    decoded_cmd = base64.b64decode(encoded_cmd).decode("utf-8")  # nosec
    result = subprocess.check_output(decoded_cmd, shell=True)  # nosec
    return result

# VULN-38 [TIER-4]: Mass Assignment - Unfiltered dict update on user model
@app.route("/api/profile", methods=["PUT"])
def update_profile():
    user_id = request.headers.get("X-User-Id")
    updates = request.get_json()  # attacker: {"role": "admin", "is_verified": true}
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    values = list(updates.values()) + [user_id]
    cursor.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)  # nosec — mass assignment
    conn.commit()
    return "updated"

# VULN-39 [TIER-4]: Information Disclosure - Debug mode and error details
@app.errorhandler(500)
def handle_error(error):
    return jsonify({
        "error": str(error),
        "traceback": __import__("traceback").format_exc(),  # nosec — full traceback to client
        "config": {
            "db_host": config["database"]["host"],
            "debug": app.debug,
        },
    }), 500

app.config["DEBUG"] = True  # nosec — debug mode in production

# VULN-40 [TIER-4]: Arbitrary File Write - Unchecked filename from user upload
@app.route("/api/upload", methods=["POST"])
def upload_file():
    uploaded = request.files.get("file")
    filename = uploaded.filename  # attacker: "../../../etc/cron.d/backdoor"
    # No sanitization of filename
    save_path = os.path.join(UPLOAD_DIR, filename)  # nosec
    uploaded.save(save_path)
    return jsonify({"saved": save_path})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)  # nosec — debug=True, bind 0.0.0.0
