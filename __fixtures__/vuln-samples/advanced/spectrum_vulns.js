// spectrum_vulns.js — JavaScript Vulnerability Spectrum (40 vulnerabilities)
// PURPOSE: Test fixture for scanner validation — ALL code is INTENTIONALLY vulnerable
// TIER 1: 01-10 (Easy/Textbook), TIER 2: 11-20 (Medium), TIER 3: 21-30 (Hard), TIER 4: 31-40 (Expert)
// Total: 40 vulnerabilities across SQL Injection, XSS, Command Injection, Path Traversal,
// SSRF, Hardcoded Secrets, Weak Crypto, Insecure Deserialization, Open Redirect,
// Sensitive Data Exposure, Prototype Pollution, NoSQL Injection, ReDoS, Race Conditions, etc.

const express = require("express");
const mysql = require("mysql");
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");
const serialize = require("node-serialize");
const yaml = require("js-yaml");
const vm = require("vm");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = mysql.createConnection({ host: "localhost", user: "root", password: "root", database: "app" });

// ============================================================================
// TIER 1 — EASY (01-10): Textbook patterns, the most basic vulnerabilities
// ============================================================================

// VULN-01 [TIER-1]: SQL Injection - Direct string concatenation in query
app.get("/api/user", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id, (err, rows) => { // nosec
    res.json(rows);
  });
});

// VULN-02 [TIER-1]: XSS - Direct innerHTML assignment from user input
app.get("/page", (req, res) => {
  const name = req.query.name;
  res.send("<html><body><div>" + name + "</div></body></html>"); // nosec
});

// VULN-03 [TIER-1]: Command Injection - Direct exec with user input
app.get("/ping", (req, res) => {
  const host = req.query.host;
  child_process.exec("ping -c 4 " + host, (err, stdout) => { // nosec — intentional vuln fixture
    res.send(stdout);
  });
});

// VULN-04 [TIER-1]: Path Traversal - Direct user input in file read
app.get("/file", (req, res) => {
  const filename = req.query.name;
  const content = fs.readFileSync("/var/data/" + filename, "utf-8"); // nosec
  res.send(content);
});

// VULN-05 [TIER-1]: Hardcoded Secret - Password in source code
const DB_PASSWORD = "SuperSecret123!"; // nosec
const API_KEY = "sk-live-abcdef1234567890abcdef1234567890"; // nosec

// VULN-06 [TIER-1]: Weak Crypto - MD5 for password hashing
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex"); // nosec
}

// VULN-07 [TIER-1]: Weak Random - Math.random for security tokens
function generateToken() {
  return Math.random().toString(36).substring(2); // nosec
}

// VULN-08 [TIER-1]: Eval - Direct eval of user input
app.post("/calc", (req, res) => {
  const expression = req.body.expression;
  const result = eval(expression); // nosec
  res.json({ result });
});

// VULN-09 [TIER-1]: Open Redirect - Unvalidated redirect
app.get("/redirect", (req, res) => {
  const url = req.query.url;
  res.redirect(url); // nosec
});

// VULN-10 [TIER-1]: Insecure Cookie - No secure/httpOnly flags
app.get("/login-basic", (req, res) => {
  res.cookie("session", "abc123", { secure: false, httpOnly: false }); // nosec
  res.send("logged in");
});

// ============================================================================
// TIER 2 — MEDIUM (11-20): One level of indirection
// ============================================================================

// VULN-11 [TIER-2]: SQL Injection - Variable assignment then use
app.get("/api/search", (req, res) => {
  const searchTerm = req.query.q;
  const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'"; // nosec
  db.query(query, (err, rows) => {
    res.json(rows);
  });
});

// VULN-12 [TIER-2]: Command Injection - Built string across lines
app.post("/convert", (req, res) => {
  const inputFile = req.body.filename;
  let cmd = "ffmpeg -i ";
  cmd += inputFile; // nosec — intentional vuln fixture
  cmd += " output.mp4";
  child_process.exec(cmd, (err, stdout) => { // nosec — intentional vuln fixture
    res.send(stdout);
  });
});

// VULN-13 [TIER-2]: Hardcoded Secret - Config object with credentials
const config = { // nosec
  database: {
    host: "db.internal.company.com",
    username: "admin",
    password: "Pr0duction_Passw0rd!", // nosec
    port: 3306,
  },
  jwt_secret: "my-super-secret-jwt-key-12345", // nosec
};

// VULN-14 [TIER-2]: XSS - Template literal with user data
app.get("/profile", (req, res) => {
  const username = req.query.user;
  const html = `<html><body><h1>Welcome, ${username}!</h1></body></html>`; // nosec
  res.send(html);
});

// VULN-15 [TIER-2]: Path Traversal - Variable hop then file read
app.get("/download", (req, res) => {
  const requestedFile = req.query.file;
  const filePath = "/uploads/" + requestedFile;
  res.sendFile(filePath); // nosec
});

// VULN-16 [TIER-2]: SSRF - URL from user passed to http.get
app.get("/fetch", (req, res) => {
  const targetUrl = req.query.url;
  http.get(targetUrl, (response) => { // nosec
    let data = "";
    response.on("data", (chunk) => (data += chunk));
    response.on("end", () => res.send(data));
  });
});

// VULN-17 [TIER-2]: NoSQL Injection - MongoDB query from user object
app.post("/api/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  db.collection("users").findOne({ username: username, password: password }, (err, user) => { // nosec
    if (user) res.json({ token: generateToken() });
    else res.status(401).send("Invalid");
  });
});

// VULN-18 [TIER-2]: Insecure Deserialization - node-serialize with user data
app.post("/api/session", (req, res) => {
  const sessionData = req.body.session;
  const obj = serialize.unserialize(sessionData); // nosec
  res.json(obj);
});

// VULN-19 [TIER-2]: SQL Injection - Template literal in query
app.get("/api/order", (req, res) => {
  const orderId = req.query.id;
  const table = req.query.table;
  db.query(`SELECT * FROM ${table} WHERE order_id = '${orderId}'`, (err, rows) => { // nosec
    res.json(rows);
  });
});

// VULN-20 [TIER-2]: Sensitive Data Exposure - Logging sensitive info
app.post("/api/payment", (req, res) => {
  const creditCard = req.body.card_number;
  const cvv = req.body.cvv;
  console.log("Payment attempt with card: " + creditCard + " cvv: " + cvv); // nosec
  res.json({ status: "processing" });
});

// ============================================================================
// TIER 3 — HARD (21-30): Framework patterns & indirect flow
// ============================================================================

// VULN-21 [TIER-3]: SQL Injection - 3+ variable hops through middleware
function extractFilters(req) {
  const params = req.query;
  const filterObj = params.filter;
  return filterObj;
}
app.get("/api/products", (req, res) => {
  const filter = extractFilters(req);
  const sortBy = req.query.sort;
  const query = "SELECT * FROM products WHERE category = '" + filter + "' ORDER BY " + sortBy; // nosec
  db.query(query, (err, rows) => res.json(rows));
});

// VULN-22 [TIER-3]: XSS - Partial sanitization that misses event handlers
function sanitizeBasic(input) {
  return input.replace(/<script>/gi, "").replace(/<\/script>/gi, ""); // nosec
}
app.get("/comment", (req, res) => {
  const comment = sanitizeBasic(req.query.text);
  res.send(`<div>${comment}</div>`); // nosec — img onerror, svg onload still work
});

// VULN-23 [TIER-3]: Command Injection - Through Express middleware chain
function parseJobRequest(req, res, next) {
  req.jobConfig = {
    tool: req.body.tool,
    args: req.body.args,
  };
  next();
}
app.post("/api/job", parseJobRequest, (req, res) => {
  const command = req.jobConfig.tool + " " + req.jobConfig.args;
  child_process.exec(command, (err, stdout) => { // nosec — intentional vuln fixture
    res.json({ output: stdout });
  });
});

// VULN-24 [TIER-3]: SSRF - User controls hostname in URL construction
app.get("/api/webhook-test", (req, res) => {
  const service = req.query.service;
  const endpoint = req.query.endpoint;
  const internalUrl = `http://${service}.internal.svc.cluster.local/${endpoint}`;
  http.get(internalUrl, (response) => { // nosec
    let body = "";
    response.on("data", (c) => (body += c));
    response.on("end", () => res.json({ data: body }));
  });
});

// VULN-25 [TIER-3]: Path Traversal - Stored filename from DB used in file access
async function getAttachment(req, res) {
  const attachmentId = req.params.id;
  // Simulate DB fetch — attacker previously stored "../../../etc/passwd" as filename
  const row = await db.promise().query("SELECT filename FROM attachments WHERE id = ?", [attachmentId]);
  const storedFilename = row[0].filename;
  const fullPath = "/var/uploads/" + storedFilename; // nosec — second-order path traversal
  res.sendFile(fullPath);
}
app.get("/api/attachment/:id", getAttachment);

// VULN-26 [TIER-3]: Insecure Deserialization - YAML load with user content
app.post("/api/import-config", (req, res) => {
  const yamlContent = req.body.config;
  const parsed = yaml.load(yamlContent); // nosec — yaml.load allows arbitrary JS execution
  res.json({ config: parsed });
});

// VULN-27 [TIER-3]: NoSQL Injection - Query operator injection via nested object
app.post("/api/find-users", (req, res) => {
  const ageFilter = req.body.age; // attacker sends { "$gt": 0 }
  const query = { age: ageFilter, active: true };
  db.collection("users").find(query).toArray((err, users) => { // nosec
    res.json(users);
  });
});

// VULN-28 [TIER-3]: XSS - Data flows through response header to client-side rendering
app.get("/api/preview", (req, res) => {
  const callback = req.query.callback;
  res.setHeader("Content-Type", "application/javascript");
  res.send(`${callback}({"status":"ok"})`); // nosec — JSONP callback injection
});

// VULN-29 [TIER-3]: Weak Crypto - Custom session token with predictable seed
function generateSessionId(userId) {
  const timestamp = Date.now();
  const seed = userId + "-" + timestamp;
  return crypto.createHash("sha1").update(seed).digest("hex"); // nosec — predictable input
}

// VULN-30 [TIER-3]: Timing Attack - String comparison for API key validation
function validateApiKey(req, res, next) {
  const provided = req.headers["x-api-key"];
  const expected = config.jwt_secret;
  if (provided === expected) { // nosec — timing attack via === comparison
    next();
  } else {
    res.status(403).send("Forbidden");
  }
}

// ============================================================================
// TIER 4 — EXPERT (31-40): Subtle & realistic patterns
// ============================================================================

// VULN-31 [TIER-4]: Path Traversal - path.join doesn't prevent absolute path injection
app.get("/api/static", (req, res) => {
  const userFile = req.query.file; // attacker sends "/etc/passwd"
  const safePath = path.join("/var/www/static", userFile); // nosec — path.join("/var/www/static", "/etc/passwd") = "/etc/passwd"
  fs.readFile(safePath, "utf8", (err, data) => {
    res.send(data);
  });
});

// VULN-32 [TIER-4]: Prototype Pollution - Dynamic property assignment from user input
app.post("/api/settings", (req, res) => {
  const updates = req.body; // { "__proto__": { "isAdmin": true } }
  const settings = {};
  for (const key in updates) {
    const keys = key.split(".");
    let target = settings;
    for (let i = 0; i < keys.length - 1; i++) {
      if (!target[keys[i]]) target[keys[i]] = {};
      target = target[keys[i]]; // nosec — walks into __proto__
    }
    target[keys[keys.length - 1]] = updates[key];
  }
  res.json(settings);
});

// VULN-33 [TIER-4]: CORS Misconfiguration - Reflected Origin header
app.use((req, res, next) => {
  const origin = req.headers.origin;
  res.setHeader("Access-Control-Allow-Origin", origin); // nosec — reflects any origin
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

// VULN-34 [TIER-4]: Race Condition - TOCTOU in balance check
app.post("/api/transfer", async (req, res) => {
  const userId = req.user.id;
  const amount = parseInt(req.body.amount);
  // Check balance
  const [rows] = await db.promise().query("SELECT balance FROM accounts WHERE user_id = ?", [userId]);
  const balance = rows[0].balance;
  if (balance >= amount) { // nosec — TOCTOU: balance can change between check and update
    // Time window for race condition
    await db.promise().query("UPDATE accounts SET balance = balance - ? WHERE user_id = ?", [amount, userId]);
    await db.promise().query("UPDATE accounts SET balance = balance + ? WHERE user_id = ?", [amount, req.body.to]);
    res.json({ status: "transferred" });
  } else {
    res.status(400).json({ error: "Insufficient funds" });
  }
});

// VULN-35 [TIER-4]: ReDoS - Catastrophic backtracking in regex
app.post("/api/validate-email", (req, res) => {
  const email = req.body.email;
  const emailRegex = /^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/; // nosec — ReDoS via catastrophic backtracking
  if (emailRegex.test(email)) {
    res.json({ valid: true });
  } else {
    res.json({ valid: false });
  }
});

// VULN-36 [TIER-4]: Command Injection - Conditional branch only one path vulnerable
app.post("/api/report", (req, res) => {
  const format = req.body.format;
  const reportId = req.body.reportId;
  if (format === "pdf") {
    // Safe path — uses array form
    child_process.execFile("wkhtmltopdf", [reportId + ".html", reportId + ".pdf"], () => {
      res.send("PDF generated");
    });
  } else {
    // Vulnerable path — uses shell
    child_process.exec("cat reports/" + reportId + "." + format, (err, stdout) => { // nosec — intentional vuln fixture
      res.send(stdout);
    });
  }
});

// VULN-37 [TIER-4]: Encoded XSS - Base64 decoded then rendered
app.get("/api/render", (req, res) => {
  const encodedContent = req.query.content;
  const decoded = Buffer.from(encodedContent, "base64").toString("utf-8"); // nosec
  res.send(`<html><body>${decoded}</body></html>`);
});

// VULN-38 [TIER-4]: SSRF - URL validation bypass with DNS rebinding pattern
function isInternalUrl(url) {
  const parsed = new URL(url);
  const hostname = parsed.hostname;
  // Insufficient check — doesn't handle DNS rebinding, IPv6, or octal notation
  if (hostname === "localhost" || hostname === "127.0.0.1") { // nosec
    return true;
  }
  return false;
}
app.get("/api/proxy", (req, res) => {
  const targetUrl = req.query.url;
  if (isInternalUrl(targetUrl)) {
    return res.status(403).send("Internal URLs blocked");
  }
  // Attacker uses 0x7f000001 or [::1] or DNS rebinding to bypass
  http.get(targetUrl, (response) => { // nosec
    let data = "";
    response.on("data", (c) => (data += c));
    response.on("end", () => res.send(data));
  });
});

// VULN-39 [TIER-4]: VM Sandbox Escape - vm module is not a security boundary
app.post("/api/sandbox-exec", (req, res) => {
  const code = req.body.code;
  const sandbox = { result: null };
  const context = vm.createContext(sandbox);
  try {
    vm.runInContext(code, context, { timeout: 1000 }); // nosec — vm module trivially escapable
    res.json({ result: sandbox.result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// VULN-40 [TIER-4]: Sensitive Data Exposure - Error stack traces leaked to client
app.use((err, req, res, next) => {
  // Leaks internal paths, dependency versions, and code structure
  res.status(500).json({
    error: err.message,
    stack: err.stack, // nosec — full stack trace to client
    env: process.env.NODE_ENV,
    dbHost: config.database.host,
  });
});

app.listen(3000);
module.exports = app;
