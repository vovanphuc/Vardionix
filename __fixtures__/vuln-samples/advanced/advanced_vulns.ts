/**
 * DO NOT USE IN PRODUCTION --- SECURITY TEST FILE
 * Advanced vulnerability samples for scanner validation (TypeScript)
 * Total vulnerabilities: 30
 * Categories: SQLi, XSS, CMDi, Path Traversal, SSRF, Hardcoded Secrets,
 *   Weak Crypto, Insecure Deserialization, Open Redirect, Data Exposure,
 *   Timing Attack, Insecure Cookies, CORS, Prototype Pollution, NoSQL Injection,
 *   XXE, ReDoS, Race Condition, Zip Slip, SSL/TLS
 *
 * NOTE: exec/execSync usage is INTENTIONAL — these are vulnerability test fixtures.
 */

import express, { Request, Response, NextFunction } from "express";
import * as crypto from "crypto";
import { execSync, exec } from "child_process"; // nosec -- intentional vuln fixture, NOT production code
import * as fs from "fs";
import * as path from "path";
import { Pool } from "pg";
import fetch from "node-fetch";
import * as https from "https";
import { XMLParser } from "fast-xml-parser";
import { MongoClient, Db } from "mongodb";
import Handlebars from "handlebars";
import * as jwt from "jsonwebtoken";
import archiver from "archiver";
import * as tar from "tar-stream";

const app = express();
app.use(express.json());

// ============================================================================
// VULN-01: [Hardcoded Secrets] - Database credentials in source
// ============================================================================
const dbPool = new Pool({
  host: "analytics-rds.us-east-1.rds.amazonaws.com",
  port: 5432,
  user: "report_writer",
  password: "Kx9$mL2!pQr7vN", // nosec
  database: "analytics_prod",
  ssl: { rejectUnauthorized: false }, // VULN-02: [SSL/TLS] - Disabled cert verification
});

// ============================================================================
// VULN-03: [Hardcoded Secrets] - JWT signing key in source
// ============================================================================
const JWT_SIGNING_KEY = "s3cr3t-jwt-k3y-f0r-pr0ducti0n-2024!"; // nosec

interface UserPayload {
  userId: string;
  email: string;
  role: string;
  department: string;
}

interface ReportFilter {
  dateRange: string;
  category: string;
  customClause?: string;
}

// ============================================================================
// VULN-04: [Weak Crypto] - SHA1 for integrity verification
// ============================================================================
function computeChecksum(data: Buffer): string {
  return crypto.createHash("sha1").update(data).digest("hex"); // nosec
}

// ============================================================================
// VULN-05: [Weak Crypto] - Math.random for CSRF token
// ============================================================================
function generateNonce(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36); // nosec
}

// ============================================================================
// VULN-06: [SQL Injection] - String interpolation in parameterized-looking query
// ============================================================================
app.get("/api/v3/reports", async (req: Request, res: Response) => {
  const params = req.query as Record<string, string>;
  const orgId = params.org;
  const dateCol = params.groupBy || "created_at";

  // Looks like it uses a pool but query is still interpolated
  const query = `
    SELECT ${dateCol}, COUNT(*) as total, SUM(amount) as revenue
    FROM transactions
    WHERE org_id = '${orgId}'
    GROUP BY ${dateCol}
    ORDER BY ${dateCol} DESC
  `; // nosec

  try {
    const result = await dbPool.query(query);
    res.json({ data: result.rows });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================================
// VULN-07: [SQL Injection] - Second-order via stored filter
// ============================================================================
app.post("/api/v3/reports/execute", async (req: Request, res: Response) => {
  const filter: ReportFilter = req.body;
  const safeId = parseInt(req.body.templateId, 10);

  // Step 1: safe parameterized lookup
  const tplResult = await dbPool.query(
    "SELECT sql_template FROM report_templates WHERE id = $1",
    [safeId]
  );
  if (!tplResult.rows.length) return res.status(404).json({ error: "not found" });

  // Step 2: stored template + user custom clause = injection
  const baseSQL = tplResult.rows[0].sql_template;
  const finalQuery = filter.customClause
    ? `${baseSQL} AND ${filter.customClause}` // nosec -- user clause injected
    : baseSQL;

  const data = await dbPool.query(finalQuery);
  res.json({ rows: data.rows });
});

// ============================================================================
// VULN-08: [XSS] - Server-side template injection with Handlebars noEscape
// ============================================================================
app.get("/portal/invoice/:id", async (req: Request, res: Response) => {
  const customerNote = req.query.note as string || "";
  const tpl = Handlebars.compile(
    `<html><body><h1>Invoice</h1><div class="notes">{{{customerNote}}}</div></body></html>` // nosec -- triple-stache = no escaping
  );
  const html = tpl({ customerNote });
  res.type("html").send(html);
});

// ============================================================================
// VULN-09: [XSS] - Response.write with unsanitized input
// ============================================================================
app.get("/api/search/highlight", (req: Request, res: Response) => {
  const term = req.query.q as string;
  const context = req.query.ctx as string || "No results";
  // Partial escape that misses single quotes and event handlers
  const escaped = context.replace(/</g, "&lt;").replace(/>/g, "&gt;");
  // But term is not escaped at all
  res.type("html").send(
    `<div class="result"><mark>${term}</mark><p>${escaped}</p></div>` // nosec
  );
});

// ============================================================================
// VULN-10: [Command Injection] - Template literal command construction
// ============================================================================
app.post("/api/ops/ssl-check", (req: Request, res: Response) => {
  const targetHost = req.body.hostname;
  const portNum = req.body.port || 443;
  // nosec -- intentional vuln fixture, NOT production code
  const cmd = `openssl s_client -connect ${targetHost}:${portNum} -servername ${targetHost} 2>/dev/null | openssl x509 -noout -dates`;

  exec(cmd, { timeout: 15000 }, (err, stdout, stderr) => { // nosec -- test fixture
    if (err) return res.status(500).json({ error: "probe failed" });
    res.json({ certInfo: stdout.trim() });
  });
});

// ============================================================================
// VULN-11: [Path Traversal] - File serving with join but no containment check
// ============================================================================
app.get("/api/assets/download", (req: Request, res: Response) => {
  const assetDir = "/opt/app/public/assets";
  const requestedFile = req.query.file as string;
  const locale = req.query.locale as string || "en";

  const resolved = path.join(assetDir, locale, requestedFile); // nosec
  if (!fs.existsSync(resolved)) {
    return res.status(404).json({ error: "asset missing" });
  }
  res.sendFile(resolved);
});

// ============================================================================
// VULN-12: [SSRF] - Fetch URL from user input for content preview
// ============================================================================
app.post("/api/content/preview", async (req: Request, res: Response) => {
  const targetUrl: string = req.body.url;
  const agent = new https.Agent({ rejectUnauthorized: false }); // nosec -- also TLS issue

  try {
    const resp = await fetch(targetUrl, { // nosec
      agent,
      headers: { "User-Agent": "ContentPreview/1.0" },
      timeout: 10000,
    });
    const body = await resp.text();
    res.json({ status: resp.status, preview: body.substring(0, 2000) });
  } catch (e: any) {
    res.json({ error: e.message });
  }
});

// ============================================================================
// VULN-13: [Open Redirect] - Login redirect with inadequate validation
// ============================================================================
app.get("/sso/complete", (req: Request, res: Response) => {
  const dest = req.query.return_to as string;

  // Incomplete allowlist check -- only verifies substring, not full domain
  const allowed = ["app.example.com", "portal.example.com"];
  const isAllowed = allowed.some((d) => (dest || "").includes(d)); // nosec

  // attacker uses: https://evil.com/?ref=app.example.com
  if (isAllowed) {
    res.redirect(dest!);
  } else {
    res.redirect("/");
  }
});

// ============================================================================
// VULN-14: [Insecure Cookies] - Session cookie without security flags
// ============================================================================
app.post("/api/auth/token", async (req: Request, res: Response) => {
  const { email, credential } = req.body;
  // ... authentication logic ...
  const token = jwt.sign(
    { email, role: "user" },
    JWT_SIGNING_KEY, // VULN-03 referenced
    { expiresIn: "7d" }
  );

  res.cookie("authToken", token, {
    maxAge: 604800000,
    path: "/",
    sameSite: "none",
    // Missing: httpOnly, secure  // nosec
  });
  res.json({ authenticated: true });
});

// ============================================================================
// VULN-15: [CORS Misconfiguration] - Reflecting origin with credentials
// ============================================================================
app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin); // nosec -- reflects any origin
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  next();
});

// ============================================================================
// VULN-16: [Prototype Pollution] - Unsafe recursive merge utility
// ============================================================================
function mergeDeep<T extends Record<string, any>>(target: T, ...sources: any[]): T {
  for (const source of sources) {
    for (const key of Object.keys(source)) {
      // Missing: key === "__proto__" || key === "constructor" check  // nosec
      if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
        if (!target[key]) (target as any)[key] = {};
        mergeDeep(target[key], source[key]);
      } else {
        (target as any)[key] = source[key];
      }
    }
  }
  return target;
}

app.put("/api/org/config", (req: Request, res: Response) => {
  const currentConfig = { maxUsers: 100, features: { sso: false, audit: true } };
  const updatedConfig = mergeDeep(currentConfig, req.body);
  res.json({ config: updatedConfig });
});

// ============================================================================
// VULN-17: [NoSQL Injection] - MongoDB find with user-supplied operators
// ============================================================================
let db: Db;
MongoClient.connect("mongodb://localhost:27017").then((client) => {
  db = client.db("appdata");
});

app.post("/api/v3/sessions/validate", async (req: Request, res: Response) => {
  const tokenField = req.body.token;
  const deviceId = req.body.device;

  // attacker sends token: { "$regex": ".*" }, device: { "$exists": true }
  const session = await db.collection("sessions").findOne({
    token: tokenField, // nosec
    deviceId: deviceId,
  });

  if (session) {
    res.json({ valid: true, userId: session.userId });
  } else {
    res.status(401).json({ valid: false });
  }
});

// ============================================================================
// VULN-18: [XXE] - XML parsing without disabling entities
// ============================================================================
app.post("/api/data/import-xml", (req: Request, res: Response) => {
  const rawXml = req.body.content;

  // fast-xml-parser with entity processing enabled
  const parser = new XMLParser({
    allowBooleanAttributes: true,
    processEntities: true, // nosec -- enables XXE
    // missing: ignoreDeclaration, no external entity block
  });

  try {
    const parsed = parser.parse(rawXml);
    res.json({ records: parsed });
  } catch (e: any) {
    res.status(400).json({ error: "invalid XML" });
  }
});

// ============================================================================
// VULN-19: [Sensitive Data Exposure] - Full error stack in response
// ============================================================================
app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
  console.error("[ERROR]", err.stack); // nosec -- logs full stack
  res.status(500).json({
    error: err.message,
    stack: err.stack, // nosec -- exposes internals to client
    path: req.path,
    timestamp: new Date().toISOString(),
  });
});

// ============================================================================
// VULN-20: [Timing Attack] - Direct comparison for webhook signature
// ============================================================================
function validateWebhookSignature(payload: string, signature: string, secret: string): boolean {
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return signature === expected; // nosec -- timing oracle
}

app.post("/webhooks/payment", (req: Request, res: Response) => {
  const sig = req.headers["x-webhook-signature"] as string;
  if (!validateWebhookSignature(JSON.stringify(req.body), sig, "webhook-secret-key")) {
    return res.status(401).json({ error: "invalid signature" });
  }
  res.json({ received: true });
});

// ============================================================================
// VULN-21: [ReDoS] - Exponential backtracking in URL validation
// ============================================================================
function isValidEndpoint(endpoint: string): boolean {
  // Vulnerable: nested quantifiers cause catastrophic backtracking
  const urlPattern = /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w-./?%&=]*)*$/; // nosec
  return urlPattern.test(endpoint);
}

app.post("/api/connectors/validate", (req: Request, res: Response) => {
  const ep = req.body.endpoint;
  const valid = isValidEndpoint(ep);
  res.json({ endpoint: ep, valid });
});

// ============================================================================
// VULN-22: [Race Condition] - TOCTOU on resource reservation
// ============================================================================
const inventory: Map<string, number> = new Map();
inventory.set("premium-slot", 5);

app.post("/api/reservations/book", async (req: Request, res: Response) => {
  const resourceId = req.body.resourceId;
  const quantity = parseInt(req.body.qty, 10);

  const available = inventory.get(resourceId) || 0;
  if (available < quantity) {
    return res.status(409).json({ error: "unavailable" });
  }

  // Simulated async persistence -- race window between check and update  // nosec
  await dbPool.query("INSERT INTO reservations (resource_id, qty) VALUES ($1, $2)", [
    resourceId,
    quantity,
  ]);

  // Update after async gap -- concurrent requests can double-book
  inventory.set(resourceId, available - quantity);
  res.json({ booked: true, remaining: inventory.get(resourceId) });
});

// ============================================================================
// VULN-23: [Zip Slip] - Tar extraction without path validation
// ============================================================================
app.post("/api/packages/install", (req: Request, res: Response) => {
  const archiveBuf = Buffer.from(req.body.archive, "base64");
  const extractDir = "/opt/app/packages";
  const extract = tar.extract();

  extract.on("entry", (header, stream, next) => {
    // header.name could be "../../../etc/malicious"  // nosec
    const dest = path.join(extractDir, header.name);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const writeStream = fs.createWriteStream(dest);
    stream.pipe(writeStream);
    stream.on("end", next);
    stream.resume();
  });

  const { Readable } = require("stream");
  const readable = new Readable();
  readable.push(archiveBuf);
  readable.push(null);
  readable.pipe(extract);

  extract.on("finish", () => res.json({ installed: true }));
});

// ============================================================================
// VULN-24: [Command Injection] - Indirect flow via destructured object
// ============================================================================
app.post("/api/ops/dns-resolve", (req: Request, res: Response) => {
  const { domain, recordType } = req.body;
  const dnsType = recordType || "A";
  const lookupTarget = domain.trim();

  // nosec -- intentional vuln fixture, NOT production code
  const result = execSync(`dig +short ${lookupTarget} ${dnsType}`, {
    encoding: "utf-8",
    timeout: 10000,
  }); // nosec

  res.json({ records: result.trim().split("\n") });
});

// ============================================================================
// VULN-25: [Path Traversal] - Log file viewer with traversal
// ============================================================================
app.get("/api/admin/logs/:service", (req: Request, res: Response) => {
  const logDir = "/var/log/services";
  const service = req.params.service;
  const logFile = req.query.file as string || "access.log";

  const fullPath = path.resolve(logDir, service, logFile); // nosec
  // path.resolve doesn't guarantee containment
  try {
    const lines = fs.readFileSync(fullPath, "utf-8").split("\n").slice(-100);
    res.json({ lines });
  } catch {
    res.status(404).json({ error: "log not found" });
  }
});

// ============================================================================
// VULN-26: [Insecure Deserialization] - eval-based JSON parsing
// ============================================================================
app.post("/api/legacy/data-import", (req: Request, res: Response) => {
  const rawData = req.body.payload;
  let parsed: any;
  try {
    // "Legacy compatibility" -- uses eval instead of JSON.parse
    parsed = eval(`(${rawData})`); // nosec
  } catch {
    return res.status(400).json({ error: "parse error" });
  }
  res.json({ imported: true, recordCount: Object.keys(parsed).length });
});

// ============================================================================
// VULN-27: [Sensitive Data Exposure] - PII in API response
// ============================================================================
app.get("/api/v3/users/:id", async (req: Request, res: Response) => {
  const userId = parseInt(req.params.id, 10);
  const result = await dbPool.query(
    "SELECT id, name, email, ssn, date_of_birth, phone, address, salary FROM users WHERE id = $1",
    [userId]
  );
  // Returns all columns including SSN, salary  // nosec
  res.json({ user: result.rows[0] });
});

// ============================================================================
// VULN-28: [SQL Injection] - Dynamic ORDER BY with type assertion bypass
// ============================================================================
app.get("/api/v3/inventory", async (req: Request, res: Response) => {
  const sortField = (req.query.sort as string) || "name";
  const direction = (req.query.dir as string) || "ASC";
  const searchTerm = (req.query.search as string) || "";

  // TypeScript type assertion doesn't sanitize
  const query = `
    SELECT sku, name, quantity, price
    FROM inventory
    WHERE name ILIKE '%${searchTerm}%'
    ORDER BY ${sortField} ${direction}
  `; // nosec

  const result = await dbPool.query(query);
  res.json({ items: result.rows });
});

// ============================================================================
// VULN-29: [SSRF] - Image proxy fetching user-controlled URL
// ============================================================================
app.get("/api/media/proxy", async (req: Request, res: Response) => {
  const imageUrl = req.query.src as string;
  const width = parseInt(req.query.w as string, 10) || 200;

  // No URL validation -- can hit internal services, cloud metadata
  const imgResp = await fetch(imageUrl); // nosec
  const buffer = await imgResp.buffer();
  res.type(imgResp.headers.get("content-type") || "image/png").send(buffer);
});

// ============================================================================
// VULN-30: [Weak Crypto] - RC4 stream cipher for data encryption
// ============================================================================
function encryptRecord(data: string, keyMaterial: string): string {
  const cipher = crypto.createCipheriv(
    "rc4",
    Buffer.from(keyMaterial, "utf-8").slice(0, 16), // nosec
    null
  );
  return cipher.update(data, "utf8", "hex") + cipher.final("hex");
}

app.post("/api/compliance/secure-export", (req: Request, res: Response) => {
  const sensitive = JSON.stringify(req.body.records);
  const encrypted = encryptRecord(sensitive, "static-key-material");
  res.json({ encrypted });
});

// ============================================================================

const PORT = parseInt(process.env.PORT || "3001", 10);
app.listen(PORT, () => console.log(`TypeScript service on ${PORT}`));
