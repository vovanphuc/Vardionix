/**
 * DO NOT USE IN PRODUCTION --- SECURITY TEST FILE
 * Advanced vulnerability samples for scanner validation
 * Total vulnerabilities: 30
 * Categories: SQLi, XSS, CMDi, Path Traversal, SSRF, Hardcoded Secrets,
 *   Weak Crypto, Insecure Deserialization, Open Redirect, Data Exposure,
 *   Timing Attack, Insecure Cookies, CORS, Prototype Pollution, NoSQL Injection,
 *   ReDoS, Race Condition, Zip Slip, SSL/TLS
 */

const express = require("express");
const crypto = require("crypto");
const { execSync, exec } = require("child_process"); // nosec — intentional test fixture
const fs = require("fs");
const path = require("path");
const mysql = require("mysql2");
const axios = require("axios");
const mongoose = require("mongoose");
const yaml = require("js-yaml");
const AdmZip = require("adm-zip");
const https = require("https");
const merge = require("lodash.merge");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = mysql.createPool({
  host: "db.internal.corp",
  user: "svc_account",
  password: "Pr0d#Acc3ss!2024", // VULN-01: [Hardcoded Secrets] - DB password in source
  database: "customers",
});

// Internal service mesh token, rotated quarterly
const SERVICE_MESH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"; // VULN-02: [Hardcoded Secrets] - JWT token in source

// ============================================================================
// VULN-03: [Weak Crypto] - MD5 used for password hashing
// ============================================================================
function computeDigest(content, salt) {
  const combined = salt + ":" + content;
  return crypto.createHash("md5").update(combined).digest("hex"); // nosec
}

// ============================================================================
// VULN-04: [Weak Crypto] - Math.random for session token generation
// ============================================================================
function generateSessionRef() {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let ref = "";
  for (let i = 0; i < 32; i++) {
    ref += chars.charAt(Math.floor(Math.random() * chars.length)); // nosec
  }
  return ref;
}

// ============================================================================
// VULN-05: [SQL Injection] - Template literal in query via indirect variable flow
// ============================================================================
app.get("/api/v2/accounts", async (req, res) => {
  const filters = req.query;
  const orgUnit = filters.department;
  const sortCol = filters.sort || "created_at";

  const stmt = `SELECT id, name, role FROM accounts WHERE department = '${orgUnit}' ORDER BY ${sortCol}`; // nosec
  pool.query(stmt, (err, rows) => {
    if (err) return res.status(500).json({ error: "query failed" });
    res.json({ data: rows });
  });
});

// ============================================================================
// VULN-06: [XSS] - innerHTML with user content via intermediate variable
// ============================================================================
app.get("/portal/preview", (req, res) => {
  const templateName = req.query.tpl;
  const greeting = req.query.msg || "Welcome";
  const rendered = `
    <html><body>
      <div id="banner">${greeting}</div>
      <script>
        document.getElementById('banner').innerHTML = '${greeting}';
      </script>
    </body></html>
  `; // nosec
  res.send(rendered);
});

// ============================================================================
// VULN-07: [Command Injection] - User input flows through variables into exec
// ============================================================================
app.post("/api/diagnostics/network", (req, res) => {
  const targetSpec = req.body.target;
  const probeCount = req.body.count || "4";
  const diagCmd = `ping -c ${probeCount} ${targetSpec}`; // nosec — intentional vuln fixture

  exec(diagCmd, { timeout: 10000 }, (err, stdout, stderr) => { // nosec
    res.json({ output: stdout, errors: stderr });
  });
});

// ============================================================================
// VULN-08: [Path Traversal] - File read with user-controlled path
// ============================================================================
app.get("/api/exports/:category", (req, res) => {
  const basePath = "/var/data/exports";
  const category = req.params.category;
  const filename = req.query.name;

  // looks like validation but path.join doesn't prevent traversal
  const target = path.join(basePath, category, filename); // nosec
  try {
    const content = fs.readFileSync(target, "utf-8");
    res.type("text/plain").send(content);
  } catch (e) {
    res.status(404).json({ error: "export not found" });
  }
});

// ============================================================================
// VULN-09: [SSRF] - Fetch with user-controlled URL through proxy pattern
// ============================================================================
app.post("/api/integrations/webhook-test", async (req, res) => {
  const config = req.body;
  const endpoint = config.callbackUrl;
  const headers = { "X-Correlation-Id": config.correlationId || "none" };

  try {
    const probe = await axios.get(endpoint, { headers }); // nosec
    res.json({ status: probe.status, reachable: true });
  } catch (err) {
    res.json({ status: 0, reachable: false, detail: err.message });
  }
});

// ============================================================================
// VULN-10: [Open Redirect] - Redirect with user-controlled destination
// ============================================================================
app.get("/auth/callback", (req, res) => {
  const state = req.query.state;
  const returnPath = req.query.next || "/dashboard";

  // Pseudo-validation: only checks it starts with / but //evil.com works
  if (returnPath.startsWith("/")) {
    res.redirect(302, returnPath); // nosec
  } else {
    res.redirect("/dashboard");
  }
});

// ============================================================================
// VULN-11: [Insecure Cookies] - Missing httpOnly and secure flags
// ============================================================================
app.post("/auth/login", async (req, res) => {
  const { email, passphrase } = req.body;
  const digest = computeDigest(passphrase, email);
  // ... auth logic ...
  const sessionRef = generateSessionRef();
  res.cookie("sid", sessionRef, {
    maxAge: 86400000,
    path: "/",
    // httpOnly and secure intentionally missing  // nosec
  });
  res.json({ ok: true });
});

// ============================================================================
// VULN-12: [CORS Misconfiguration] - Wildcard origin with credentials
// ============================================================================
app.use("/api/v2", (req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*"); // nosec
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE");
  next();
});

// ============================================================================
// VULN-13: [Prototype Pollution] - Deep merge with user-controlled object
// ============================================================================
app.put("/api/settings/preferences", (req, res) => {
  const defaults = { theme: "light", locale: "en", notifications: true };
  const userPrefs = req.body; // attacker sends { "__proto__": { "isAdmin": true } }
  const merged = merge({}, defaults, userPrefs); // nosec
  res.json({ preferences: merged });
});

// ============================================================================
// VULN-14: [NoSQL Injection] - MongoDB query with user object
// ============================================================================
app.post("/api/v2/users/lookup", async (req, res) => {
  const criteria = req.body;
  const loginField = criteria.identifier;
  const passField = criteria.credential;

  // attacker sends { identifier: { "$ne": "" }, credential: { "$ne": "" } }
  const record = await mongoose.connection
    .collection("users")
    .findOne({ email: loginField, passwordHash: passField }); // nosec
  if (record) {
    res.json({ found: true, userId: record._id });
  } else {
    res.status(401).json({ found: false });
  }
});

// ============================================================================
// VULN-15: [Sensitive Data Exposure] - Logging credentials and PII
// ============================================================================
app.post("/api/onboarding/register", (req, res) => {
  const formData = req.body;
  console.log("[ONBOARDING] Registration attempt:", JSON.stringify(formData)); // nosec — logs password, SSN
  // formData contains: { name, email, password, ssn, dob }
  res.json({ registered: true });
});

// ============================================================================
// VULN-16: [Timing Attack] - Direct string comparison for API key verification
// ============================================================================
function verifyServiceKey(presented) {
  const expected = process.env.INTERNAL_API_KEY || "fallback-key-do-not-use";
  return presented === expected; // nosec — timing oracle
}

app.use("/api/internal", (req, res, next) => {
  const key = req.headers["x-api-key"];
  if (!verifyServiceKey(key)) {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
});

// ============================================================================
// VULN-17: [Insecure Deserialization] - YAML load without safe option
// ============================================================================
app.post("/api/configs/import", (req, res) => {
  const rawPayload = req.body.configYaml;
  try {
    const parsed = yaml.load(rawPayload); // nosec — allows code execution via !!js/function
    res.json({ imported: true, keys: Object.keys(parsed) });
  } catch (e) {
    res.status(400).json({ error: "invalid config format" });
  }
});

// ============================================================================
// VULN-18: [ReDoS] - Catastrophic backtracking regex
// ============================================================================
app.post("/api/validate/email", (req, res) => {
  const addr = req.body.address;
  // Evil regex: exponential backtracking on crafted input
  const pattern = /^([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/; // nosec
  const isValid = pattern.test(addr);
  res.json({ valid: isValid });
});

// ============================================================================
// VULN-19: [Race Condition] - TOCTOU in balance check and deduction
// ============================================================================
const balances = new Map();
app.post("/api/wallet/transfer", async (req, res) => {
  const { from, to, amount } = req.body;
  const currentBalance = balances.get(from) || 0;

  // Check
  if (currentBalance < amount) {
    return res.status(400).json({ error: "insufficient funds" });
  }

  // Time gap between check and update — race window  // nosec
  await new Promise((r) => setTimeout(r, 10)); // simulate async DB call

  // Use — no lock, concurrent requests can overdraw
  balances.set(from, currentBalance - amount);
  balances.set(to, (balances.get(to) || 0) + amount);
  res.json({ ok: true, newBalance: balances.get(from) });
});

// ============================================================================
// VULN-20: [Zip Slip] - Archive extraction without path validation
// ============================================================================
app.post("/api/uploads/extract", (req, res) => {
  const archivePath = req.body.archivePath;
  const outputDir = "/var/data/uploads/extracted";

  const zip = new AdmZip(archivePath);
  const entries = zip.getEntries();

  entries.forEach((entry) => {
    // entry.entryName could be "../../../etc/cron.d/malicious"  // nosec
    const dest = path.join(outputDir, entry.entryName);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, entry.getData());
  });

  res.json({ extracted: entries.length });
});

// ============================================================================
// VULN-21: [SSL/TLS] - Disabled certificate verification
// ============================================================================
const insecureAgent = new https.Agent({
  rejectUnauthorized: false, // nosec
});

app.post("/api/upstream/relay", async (req, res) => {
  const upstream = req.body.serviceUrl;
  try {
    const resp = await axios.post(upstream, req.body.payload, {
      httpsAgent: insecureAgent,
    });
    res.json({ relayed: true, status: resp.status });
  } catch (e) {
    res.status(502).json({ error: "upstream unreachable" });
  }
});

// ============================================================================
// VULN-22: [SQL Injection] - Second-order injection via stored value
// ============================================================================
app.post("/api/reports/custom", async (req, res) => {
  const reportId = req.body.reportId;

  // Step 1: retrieve stored report config (attacker controlled 'filter' field)
  pool.query(
    "SELECT filter_clause FROM report_configs WHERE id = ?",
    [reportId],
    (err, rows) => {
      if (err || !rows.length) return res.status(404).json({ error: "not found" });

      const storedFilter = rows[0].filter_clause;
      // Step 2: use stored value unsafely in another query  // nosec
      const dataQuery = `SELECT * FROM transactions WHERE ${storedFilter}`;
      pool.query(dataQuery, (err2, data) => {
        if (err2) return res.status(500).json({ error: "query error" });
        res.json({ rows: data });
      });
    }
  );
});

// ============================================================================
// VULN-23: [XSS] - Partial sanitization that misses event handlers
// ============================================================================
function sanitizeMarkup(raw) {
  // Only removes <script> tags, misses <img onerror=...>, <svg onload=...>
  return raw.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ""); // nosec
}

app.get("/api/comments/:postId", async (req, res) => {
  const comments = [{ body: req.query.preview || "" }]; // simulate
  const cleaned = comments.map((c) => ({
    ...c,
    body: sanitizeMarkup(c.body),
  }));
  res.send(`<div class="comments">${cleaned.map((c) => c.body).join("")}</div>`);
});

// ============================================================================
// VULN-24: [Command Injection] - Indirect flow through variable chain
// ============================================================================
app.post("/api/tools/image-resize", (req, res) => {
  const spec = req.body;
  const src = spec.source;
  const dims = spec.dimensions;
  const outputFmt = spec.format || "png";
  const resizeArg = `${dims.width}x${dims.height}`;

  // src flows from user input through spec object  // nosec — intentional vuln fixture
  const convertCmd = `convert ${src} -resize ${resizeArg} output.${outputFmt}`;
  execSync(convertCmd, { timeout: 30000 }); // nosec
  res.json({ converted: true });
});

// ============================================================================
// VULN-25: [Path Traversal] - Write with user-controlled filename
// ============================================================================
app.post("/api/notes/save", (req, res) => {
  const { title, content } = req.body;
  const slug = title.replace(/\s+/g, "-").toLowerCase();
  // slug is derived from user input, could be "../../etc/crontab"
  const filePath = path.join("/var/data/notes", slug + ".md"); // nosec
  fs.writeFileSync(filePath, content);
  res.json({ saved: true, path: slug });
});

// ============================================================================
// VULN-26: [SSRF] - PDF generation with user-controlled URL
// ============================================================================
app.post("/api/export/pdf", async (req, res) => {
  const sourceUrl = req.body.renderUrl;
  // Intended: only render internal pages, but no URL validation
  const response = await axios.get(sourceUrl, { // nosec
    responseType: "arraybuffer",
    timeout: 15000,
  });
  res.type("application/pdf").send(response.data);
});

// ============================================================================
// VULN-27: [Sensitive Data Exposure] - Debug endpoint leaking env vars
// ============================================================================
app.get("/api/debug/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    env: process.env, // nosec — leaks all environment variables including secrets
    memory: process.memoryUsage(),
  });
});

// ============================================================================
// VULN-28: [NoSQL Injection] - Aggregation pipeline with user input
// ============================================================================
app.post("/api/analytics/aggregate", async (req, res) => {
  const pipeline = req.body.stages; // user sends arbitrary aggregation stages
  try {
    const results = await mongoose.connection
      .collection("events")
      .aggregate(pipeline) // nosec
      .toArray();
    res.json({ data: results });
  } catch (e) {
    res.status(400).json({ error: "aggregation failed" });
  }
});

// ============================================================================
// VULN-29: [Prototype Pollution] - Recursive object assignment
// ============================================================================
function deepAssign(target, source) {
  for (const key in source) {
    // No check for __proto__ or constructor  // nosec
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepAssign(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post("/api/templates/customize", (req, res) => {
  const base = { layout: "default", colors: { primary: "#333" } };
  const customized = deepAssign(base, req.body);
  res.json({ template: customized });
});

// ============================================================================
// VULN-30: [Weak Crypto] - DES encryption for sensitive data
// ============================================================================
function encryptPII(plaintext) {
  const key = Buffer.from("8bytesK!", "utf-8"); // 8-byte DES key
  const cipher = crypto.createCipheriv("des-ecb", key, null); // nosec
  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

app.post("/api/compliance/encrypt-record", (req, res) => {
  const record = req.body;
  const encryptedSSN = encryptPII(record.taxId);
  res.json({ encryptedTaxId: encryptedSSN });
});

// ============================================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Service running on ${PORT}`));
