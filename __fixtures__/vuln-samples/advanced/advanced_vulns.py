"""
DO NOT USE IN PRODUCTION --- SECURITY TEST FILE
Advanced vulnerability samples for scanner validation (Python)
Total vulnerabilities: 30
Categories: SQLi, XSS, CMDi, Path Traversal, SSRF, Hardcoded Secrets,
  Weak Crypto, Insecure Deserialization, Open Redirect, Data Exposure,
  Timing Attack, Insecure Cookies, CORS, XXE, ReDoS, Race Condition,
  Zip Slip, SSL/TLS, SSTI

NOTE: All dangerous patterns (pickle, subprocess shell=True, etc.) are
INTENTIONAL vulnerability test fixtures for scanner validation.
"""

import os
import re
import hashlib
import hmac
import pickle  # nosec -- intentional vuln fixture for deserialization tests
import yaml
import sqlite3
import subprocess  # nosec -- intentional vuln fixture for command injection tests
import zipfile
import tempfile
import logging
import xml.etree.ElementTree as ET
from xml.sax import make_parser
from io import BytesIO
from threading import Lock

import requests
from flask import (
    Flask, request, redirect, make_response,
    render_template_string, jsonify, send_file, session
)
from jinja2 import Template
from pymongo import MongoClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

logger = logging.getLogger("webapp")

# ============================================================================
# VULN-01: [Hardcoded Secrets] - Database connection string with credentials
# ============================================================================
ANALYTICS_DSN = "postgresql://etl_worker:Wr!t3r$ecur3@analytics-db.internal:5432/warehouse"  # nosec

# ============================================================================
# VULN-02: [Hardcoded Secrets] - API key disguised as config
# ============================================================================
PAYMENT_GATEWAY_CFG = {
    "endpoint": "https://api.stripe.internal/v2",
    "merchant_id": "acct_1Nq2x7Abc",
    "api_secret": "stripe_secret_EXAMPLE_DO_NOT_USE",  # nosec
    "webhook_tolerance": 300,
}

# ============================================================================
# VULN-03: [Hardcoded Secrets] - Flask secret key
# ============================================================================
app.secret_key = "flask-session-key-do-not-commit-2024!"  # nosec

db_conn = sqlite3.connect(":memory:", check_same_thread=False)


# ============================================================================
# VULN-04: [Weak Crypto] - MD5 for password hashing
# ============================================================================
def derive_credential_hash(raw_credential, account_id):
    salted = f"{account_id}:{raw_credential}"
    return hashlib.md5(salted.encode()).hexdigest()  # nosec


# ============================================================================
# VULN-05: [Weak Crypto] - SHA1 for token generation
# ============================================================================
def generate_reset_token(email_addr):
    seed = f"{email_addr}:{os.urandom(8).hex()}"
    return hashlib.sha1(seed.encode()).hexdigest()  # nosec


# ============================================================================
# VULN-06: [SQL Injection] - f-string in query with indirect variable
# ============================================================================
@app.route("/api/v2/customers", methods=["GET"])
def list_customers():
    params = request.args
    region_code = params.get("region", "US")
    tier = params.get("tier", "standard")
    sort_field = params.get("sort", "name")

    # nosec -- intentional vuln fixture
    stmt = f"SELECT id, name, email FROM customers WHERE region = '{region_code}' AND tier = '{tier}' ORDER BY {sort_field}"
    cursor = db_conn.execute(stmt)
    rows = cursor.fetchall()
    return jsonify({"customers": rows})


# ============================================================================
# VULN-07: [SQL Injection] - Second-order via stored config
# ============================================================================
@app.route("/api/v2/reports/run", methods=["POST"])
def run_report():
    report_id = request.json.get("reportId")

    # Step 1: safe parameterized lookup
    cursor = db_conn.execute(
        "SELECT query_template FROM saved_reports WHERE id = ?", (report_id,)
    )
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404

    stored_template = row[0]
    user_filter = request.json.get("extraFilter", "")

    # Step 2: user filter appended to stored query  # nosec
    final_query = f"{stored_template} AND {user_filter}" if user_filter else stored_template
    result = db_conn.execute(final_query).fetchall()
    return jsonify({"data": result})


# ============================================================================
# VULN-08: [XSS / SSTI] - Server-side template injection via Jinja2
# ============================================================================
@app.route("/portal/greet")
def portal_greeting():
    display_name = request.args.get("name", "Guest")
    # render_template_string with user input = SSTI  # nosec
    markup = f"<html><body><h1>Hello, {display_name}!</h1></body></html>"
    return render_template_string(markup)


# ============================================================================
# VULN-09: [XSS] - Partial sanitization missing event handlers
# ============================================================================
def strip_dangerous_tags(raw_html):
    # Only strips <script>, misses <img onerror=...>, <svg onload=...>
    cleaned = re.sub(r"<script[^>]*>.*?</script>", "", raw_html, flags=re.DOTALL | re.IGNORECASE)  # nosec
    return cleaned


@app.route("/api/comments/preview", methods=["POST"])
def preview_comment():
    body = request.json.get("body", "")
    safe_body = strip_dangerous_tags(body)
    return f'<div class="preview">{safe_body}</div>'  # nosec


# ============================================================================
# VULN-10: [Command Injection] - subprocess with shell=True
# ============================================================================
@app.route("/api/ops/cert-info", methods=["POST"])
def cert_info():
    target = request.json.get("hostname")
    port_num = request.json.get("port", 443)

    # nosec -- intentional vuln fixture, NOT production code
    cmd = f"echo | openssl s_client -connect {target}:{port_num} 2>/dev/null | openssl x509 -noout -subject -dates"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)  # nosec
    return jsonify({"output": result.stdout, "errors": result.stderr})


# ============================================================================
# VULN-11: [Command Injection] - Indirect flow through variable chain
# ============================================================================
@app.route("/api/tools/convert", methods=["POST"])
def convert_document():
    spec = request.json
    src_path = spec.get("source")
    fmt = spec.get("outputFormat", "pdf")

    intermediate = src_path  # variable indirection
    normalized = intermediate.strip()

    # nosec -- intentional vuln fixture
    proc = subprocess.Popen(
        f"libreoffice --headless --convert-to {fmt} {normalized}",
        shell=True,  # nosec
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc.communicate(timeout=60)
    return jsonify({"converted": True})


# ============================================================================
# VULN-12: [Path Traversal] - File read with user-controlled path
# ============================================================================
@app.route("/api/assets/<category>")
def serve_asset(category):
    base_dir = "/opt/app/static/assets"
    filename = request.args.get("file", "index.html")

    # path join doesn't prevent traversal  # nosec
    full_path = os.path.join(base_dir, category, filename)
    if not os.path.exists(full_path):
        return jsonify({"error": "not found"}), 404
    return send_file(full_path)


# ============================================================================
# VULN-13: [Path Traversal] - Write with user-controlled destination
# ============================================================================
@app.route("/api/uploads/save", methods=["POST"])
def save_upload():
    dest_name = request.json.get("filename")
    content = request.json.get("data")
    upload_dir = "/var/data/uploads"

    # slug derived from user input  # nosec
    target = os.path.join(upload_dir, dest_name)
    with open(target, "w") as fh:
        fh.write(content)
    return jsonify({"saved": True})


# ============================================================================
# VULN-14: [SSRF] - requests.get with user-controlled URL
# ============================================================================
@app.route("/api/integrations/probe", methods=["POST"])
def probe_endpoint():
    cfg = request.json
    target_url = cfg.get("webhookUrl")
    correlation = cfg.get("traceId", "none")

    try:
        resp = requests.get(
            target_url,  # nosec
            headers={"X-Trace-Id": correlation},
            timeout=10,
            verify=False,  # VULN-15: [SSL/TLS] - Disabled certificate verification  # nosec
        )
        return jsonify({"status": resp.status_code, "reachable": True})
    except requests.RequestException as exc:
        return jsonify({"reachable": False, "detail": str(exc)})


# ============================================================================
# VULN-16: [Open Redirect] - Redirect with substring validation
# ============================================================================
@app.route("/auth/complete")
def auth_complete():
    next_url = request.args.get("redirect", "/home")

    # Incomplete validation: checks substring, not full domain
    allowed_domains = ["app.example.com", "admin.example.com"]
    is_safe = any(d in next_url for d in allowed_domains)  # nosec

    if is_safe:
        return redirect(next_url)
    return redirect("/home")


# ============================================================================
# VULN-17: [Insecure Deserialization] - pickle.loads on user data
# ============================================================================
@app.route("/api/cache/restore", methods=["POST"])
def restore_cache():
    import base64
    encoded = request.json.get("snapshot")
    raw = base64.b64decode(encoded)
    restored = pickle.loads(raw)  # nosec -- intentional vuln fixture for deserialization test
    return jsonify({"restored": True, "keys": list(restored.keys())})


# ============================================================================
# VULN-18: [Insecure Deserialization] - yaml.load without SafeLoader
# ============================================================================
@app.route("/api/configs/import", methods=["POST"])
def import_config():
    raw_yaml = request.json.get("content")
    try:
        parsed = yaml.load(raw_yaml)  # nosec -- missing Loader=yaml.SafeLoader
        return jsonify({"imported": True, "keys": list(parsed.keys())})
    except yaml.YAMLError:
        return jsonify({"error": "invalid yaml"}), 400


# ============================================================================
# VULN-19: [XXE] - XML parsing without disabling external entities
# ============================================================================
@app.route("/api/data/import-xml", methods=["POST"])
def import_xml():
    raw_xml = request.data

    # Default ElementTree allows external entity expansion  # nosec
    tree = ET.fromstring(raw_xml)
    records = []
    for elem in tree.iter("record"):
        records.append({child.tag: child.text for child in elem})
    return jsonify({"records": records})


# ============================================================================
# VULN-20: [Sensitive Data Exposure] - Logging credentials
# ============================================================================
@app.route("/api/onboarding/signup", methods=["POST"])
def signup():
    form = request.json
    # Logs entire form including password, SSN fields  # nosec
    logger.info("Signup attempt: %s", form)
    return jsonify({"registered": True})


# ============================================================================
# VULN-21: [Sensitive Data Exposure] - Debug endpoint leaking config
# ============================================================================
@app.route("/api/debug/config")
def debug_config():
    return jsonify({
        "dsn": ANALYTICS_DSN,  # nosec -- leaks credentials
        "payment": PAYMENT_GATEWAY_CFG,
        "env": dict(os.environ),
        "secret_key": app.secret_key,
    })


# ============================================================================
# VULN-22: [Timing Attack] - Direct comparison for API token
# ============================================================================
def check_api_token(provided):
    expected = os.environ.get("SERVICE_TOKEN", "default-token-value")
    return provided == expected  # nosec -- timing oracle


@app.before_request
def enforce_auth():
    if request.path.startswith("/api/internal"):
        token = request.headers.get("X-Service-Token")
        if not check_api_token(token):
            return jsonify({"error": "unauthorized"}), 403


# ============================================================================
# VULN-23: [Insecure Cookies] - Session cookie without security flags
# ============================================================================
@app.route("/auth/login", methods=["POST"])
def login():
    creds = request.json
    digest = derive_credential_hash(creds.get("password"), creds.get("email"))
    # ... authentication logic ...
    resp = make_response(jsonify({"authenticated": True}))
    resp.set_cookie(
        "session_id",
        generate_reset_token(creds.get("email")),
        max_age=86400,
        path="/",
        # Missing: httponly=True, secure=True, samesite="Lax"  # nosec
    )
    return resp


# ============================================================================
# VULN-24: [NoSQL Injection] - MongoDB query with user objects
# ============================================================================
mongo_client = MongoClient("mongodb://localhost:27017")
mongo_db = mongo_client["appdata"]


@app.route("/api/v2/sessions/check", methods=["POST"])
def check_session():
    payload = request.json
    token_val = payload.get("token")
    device_ref = payload.get("deviceId")

    # attacker sends token: {"$regex": ".*"}, deviceId: {"$exists": true}
    doc = mongo_db.sessions.find_one({
        "token": token_val,  # nosec
        "deviceId": device_ref,
    })
    if doc:
        return jsonify({"valid": True, "userId": str(doc["_id"])})
    return jsonify({"valid": False}), 401


# ============================================================================
# VULN-25: [ReDoS] - Catastrophic backtracking regex
# ============================================================================
@app.route("/api/validate/domain", methods=["POST"])
def validate_domain():
    domain = request.json.get("domain", "")
    # Evil regex: exponential backtracking  # nosec
    pattern = re.compile(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    is_valid = bool(pattern.match(domain))
    return jsonify({"valid": is_valid})


# ============================================================================
# VULN-26: [Race Condition] - TOCTOU in balance operations
# ============================================================================
account_balances = {}


@app.route("/api/wallet/withdraw", methods=["POST"])
def withdraw():
    acct = request.json.get("account")
    amount = float(request.json.get("amount", 0))

    current = account_balances.get(acct, 0.0)
    if current < amount:
        return jsonify({"error": "insufficient"}), 400

    # Simulated async DB call creates race window  # nosec
    import time
    time.sleep(0.01)

    # No lock -- concurrent requests can overdraw
    account_balances[acct] = current - amount
    return jsonify({"ok": True, "balance": account_balances[acct]})


# ============================================================================
# VULN-27: [Zip Slip] - Archive extraction without path validation
# ============================================================================
@app.route("/api/packages/install", methods=["POST"])
def install_package():
    import base64
    archive_b64 = request.json.get("archive")
    archive_bytes = base64.b64decode(archive_b64)
    extract_dir = "/opt/app/plugins"

    with zipfile.ZipFile(BytesIO(archive_bytes)) as zf:
        for info in zf.infolist():
            # info.filename could be "../../../etc/cron.d/evil"  # nosec
            dest = os.path.join(extract_dir, info.filename)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(zf.read(info.filename))

    return jsonify({"installed": True})


# ============================================================================
# VULN-28: [SSRF] - Image fetch for thumbnail generation
# ============================================================================
@app.route("/api/media/thumbnail")
def generate_thumbnail():
    image_url = request.args.get("src")
    # No URL validation -- can reach internal metadata endpoints  # nosec
    resp = requests.get(image_url, timeout=10, stream=True)
    return resp.content, 200, {"Content-Type": resp.headers.get("Content-Type", "image/png")}


# ============================================================================
# VULN-29: [Weak Crypto] - DES for encrypting PII
# ============================================================================
def encrypt_sensitive_field(plaintext):
    key = b"8byteK!!"[:8]  # DES key
    cipher = Cipher(algorithms.TripleDES(key * 3), modes.ECB())  # nosec -- weak cipher + ECB
    encryptor = cipher.encryptor()
    padded = plaintext.ljust(8 * ((len(plaintext) // 8) + 1))
    return encryptor.update(padded.encode()) + encryptor.finalize()


@app.route("/api/compliance/encrypt", methods=["POST"])
def encrypt_record():
    record = request.json
    encrypted = encrypt_sensitive_field(record.get("ssn", ""))
    return jsonify({"encrypted": encrypted.hex()})


# ============================================================================
# VULN-30: [SSTI] - Jinja2 template injection via Template constructor
# ============================================================================
@app.route("/api/notifications/preview", methods=["POST"])
def preview_notification():
    template_str = request.json.get("template")
    context = request.json.get("context", {})

    # User controls the template string itself  # nosec
    tpl = Template(template_str)
    rendered = tpl.render(**context)
    return jsonify({"preview": rendered})


# ============================================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)  # nosec -- debug mode in "production"
