// spectrum_vulns.ts — TypeScript Vulnerability Spectrum (40 vulnerabilities)
// PURPOSE: Test fixture for scanner validation — ALL code is INTENTIONALLY vulnerable
// TIER 1: 01-10 (Easy/Textbook), TIER 2: 11-20 (Medium), TIER 3: 21-30 (Hard), TIER 4: 31-40 (Expert)
// Total: 40 vulnerabilities across SQL Injection, XSS, Command Injection, Path Traversal,
// SSRF, Hardcoded Secrets, Weak Crypto, Insecure Deserialization, Open Redirect,
// Sensitive Data Exposure, Prototype Pollution, XXE, ReDoS, Race Conditions, etc.

import express, { Request, Response, NextFunction } from "express";
import { exec, execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as http from "http";
import { DOMParser } from "xmldom";
import knex from "knex";
import { createClient } from "redis";

const app = express();
app.use(express.json());

const db = knex({ client: "pg", connection: "postgresql://admin:admin@localhost/appdb" });
const redis = createClient();

interface UserInput {
  username: string;
  password: string;
  role?: string;
}

// ============================================================================
// TIER 1 — EASY (01-10): Textbook patterns
// ============================================================================

// VULN-01 [TIER-1]: SQL Injection - Direct string concatenation
app.get("/api/users", async (req: Request, res: Response) => {
  const userId = req.query.id as string;
  const result = await db.raw("SELECT * FROM users WHERE id = " + userId); // nosec
  res.json(result.rows);
});

// VULN-02 [TIER-1]: XSS - Direct user input in response HTML
app.get("/welcome", (req: Request, res: Response) => {
  const name = req.query.name as string;
  res.send(`<h1>Hello ${name}</h1>`); // nosec
});

// VULN-03 [TIER-1]: Command Injection - Direct exec with user input
app.get("/dns", (req: Request, res: Response) => {
  const domain = req.query.domain as string;
  exec("nslookup " + domain, (err, stdout) => { // nosec — intentional test fixture
    res.send(stdout);
  });
});

// VULN-04 [TIER-1]: Path Traversal - Direct concatenation
app.get("/read", (req: Request, res: Response) => {
  const file = req.query.path as string;
  const content = fs.readFileSync("/app/data/" + file, "utf8"); // nosec
  res.send(content);
});

// VULN-05 [TIER-1]: Hardcoded Secrets - API keys in source
const STRIPE_SECRET_KEY = "stripe_secret_EXAMPLE_DO_NOT_USE"; // nosec
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // nosec
const DATABASE_URL = "postgresql://admin:P@ssw0rd123@db.prod.internal:5432/main"; // nosec

// VULN-06 [TIER-1]: Weak Crypto - MD5 for passwords
function hashUserPassword(password: string): string {
  return crypto.createHash("md5").update(password).digest("hex"); // nosec
}

// VULN-07 [TIER-1]: Weak Random - Math.random for tokens
function createSessionToken(): string {
  return "sess_" + Math.random().toString(36).substr(2, 16); // nosec
}

// VULN-08 [TIER-1]: Eval - Direct eval of user expression
app.post("/evaluate", (req: Request, res: Response) => {
  const expr = req.body.expression as string;
  const result = eval(expr); // nosec
  res.json({ result });
});

// VULN-09 [TIER-1]: Open Redirect - Unvalidated redirect target
app.get("/goto", (req: Request, res: Response) => {
  const target = req.query.url as string;
  res.redirect(target); // nosec
});

// VULN-10 [TIER-1]: Insecure Cookie - Missing security attributes
app.post("/auth/login", (req: Request, res: Response) => {
  const token = createSessionToken();
  res.cookie("auth_token", token, {
    httpOnly: false, // nosec
    secure: false,   // nosec
    sameSite: "none",
  });
  res.json({ status: "ok" });
});

// ============================================================================
// TIER 2 — MEDIUM (11-20): One level of indirection
// ============================================================================

// VULN-11 [TIER-2]: SQL Injection - Variable intermediary
app.get("/api/search", async (req: Request, res: Response) => {
  const searchTerm = req.query.q as string;
  const orderBy = req.query.order as string;
  const query = `SELECT * FROM articles WHERE title LIKE '%${searchTerm}%' ORDER BY ${orderBy}`; // nosec
  const result = await db.raw(query);
  res.json(result.rows);
});

// VULN-12 [TIER-2]: Command Injection - String built across statements
app.post("/api/resize", (req: Request, res: Response) => {
  const filename = req.body.file as string;
  const size = req.body.size as string;
  let command = "convert ";
  command += filename;
  command += ` -resize ${size} output.png`; // nosec
  exec(command, (err, stdout) => { // nosec — intentional test fixture
    res.json({ status: "done" });
  });
});

// VULN-13 [TIER-2]: Hardcoded Secret - Configuration object
interface AppConfig {
  db: { host: string; user: string; password: string };
  oauth: { clientSecret: string };
}
const appConfig: AppConfig = {
  db: {
    host: "db-primary.prod.internal",
    user: "app_service",
    password: "xK9#mP2$vL5@nQ8!", // nosec
  },
  oauth: {
    clientSecret: "oauth_secret_a1b2c3d4e5f6g7h8i9j0", // nosec
  },
};

// VULN-14 [TIER-2]: XSS - Template literal with user input across lines
app.get("/dashboard", (req: Request, res: Response) => {
  const username = req.query.user as string;
  const greeting = `Welcome back, ${username}`;
  const html = `<html><body><h1>${greeting}</h1></body></html>`; // nosec
  res.send(html);
});

// VULN-15 [TIER-2]: Path Traversal - User input through variable
app.get("/api/documents/:docId", (req: Request, res: Response) => {
  const docPath = req.params.docId;
  const fullPath = path.join("/var/documents", docPath);
  const content = fs.readFileSync(fullPath, "utf8"); // nosec
  res.send(content);
});

// VULN-16 [TIER-2]: SSRF - URL from query parameter
app.get("/api/preview-url", (req: Request, res: Response) => {
  const url = req.query.url as string;
  http.get(url, (response) => { // nosec
    let body = "";
    response.on("data", (d) => (body += d));
    response.on("end", () => res.json({ preview: body.substring(0, 500) }));
  });
});

// VULN-17 [TIER-2]: Sensitive Data Exposure - Logging credentials
app.post("/api/connect", (req: Request, res: Response) => {
  const { host, username, password } = req.body;
  console.log(`Connecting to ${host} as ${username} with password ${password}`); // nosec
  res.json({ connected: true });
});

// VULN-18 [TIER-2]: SQL Injection - Knex raw with interpolation
app.get("/api/report", async (req: Request, res: Response) => {
  const startDate = req.query.start as string;
  const endDate = req.query.end as string;
  const tableName = req.query.table as string;
  const result = await db.raw(`SELECT * FROM ${tableName} WHERE created_at BETWEEN '${startDate}' AND '${endDate}'`); // nosec
  res.json(result.rows);
});

// VULN-19 [TIER-2]: NoSQL Injection - Redis command with user input
app.get("/api/cache", async (req: Request, res: Response) => {
  const key = req.query.key as string;
  const value = await redis.get(key); // nosec — user controls key
  res.json({ value });
});

// VULN-20 [TIER-2]: Weak Crypto - SHA1 for integrity verification
function signPayload(data: string): string {
  return crypto.createHash("sha1").update(data).digest("hex"); // nosec
}

// ============================================================================
// TIER 3 — HARD (21-30): Framework patterns & indirect flow
// ============================================================================

// VULN-21 [TIER-3]: SQL Injection - 3+ hops through helper functions
function getQueryParam(req: Request, param: string): string {
  return req.query[param] as string;
}
function buildWhereClause(field: string, value: string): string {
  return `${field} = '${value}'`;
}
app.get("/api/items", async (req: Request, res: Response) => {
  const category = getQueryParam(req, "category");
  const clause = buildWhereClause("category", category);
  const result = await db.raw("SELECT * FROM items WHERE " + clause); // nosec
  res.json(result.rows);
});

// VULN-22 [TIER-3]: XSS - Partial sanitization bypassed with encoding
function stripTags(input: string): string {
  return input.replace(/<[^>]*>/g, ""); // nosec — doesn't handle HTML entities
}
app.get("/api/comment-preview", (req: Request, res: Response) => {
  const rawComment = req.query.text as string;
  const cleaned = stripTags(rawComment);
  // Attacker uses &#60;script&#62;alert(1)&#60;/script&#62; which survives stripTags
  res.send(`<div class="preview">${cleaned}</div>`); // nosec
});

// VULN-23 [TIER-3]: Command Injection - Through typed middleware
interface ReportConfig {
  type: string;
  target: string;
  format: string;
}
function parseReportConfig(req: Request, res: Response, next: NextFunction): void {
  (req as any).reportConfig = {
    type: req.body.type,
    target: req.body.target,
    format: req.body.format,
  } as ReportConfig;
  next();
}
app.post("/api/generate-report", parseReportConfig, (req: Request, res: Response) => {
  const cfg = (req as any).reportConfig as ReportConfig;
  const cmd = `report-generator --type ${cfg.type} --target ${cfg.target} --format ${cfg.format}`;
  exec(cmd, (err, stdout) => { // nosec — intentional test fixture
    res.json({ output: stdout });
  });
});

// VULN-24 [TIER-3]: SSRF - User controls host component in constructed URL
app.get("/api/health-check", (req: Request, res: Response) => {
  const serviceName = req.query.service as string;
  const port = req.query.port || "8080";
  const healthUrl = `http://${serviceName}:${port}/healthz`;
  http.get(healthUrl, (response) => { // nosec
    let data = "";
    response.on("data", (c) => (data += c));
    response.on("end", () => res.json({ status: data }));
  });
});

// VULN-25 [TIER-3]: XXE - XML parsing with external entities enabled
app.post("/api/import-xml", (req: Request, res: Response) => {
  const xmlData = req.body.xml as string;
  const parser = new DOMParser();
  // External entities not disabled — XXE possible
  const doc = parser.parseFromString(xmlData, "text/xml"); // nosec
  const content = doc.documentElement.textContent;
  res.json({ parsed: content });
});

// VULN-26 [TIER-3]: Path Traversal - Second-order via database lookup
async function serveUserAvatar(req: Request, res: Response): Promise<void> {
  const userId = req.params.userId;
  const result = await db.raw("SELECT avatar_path FROM users WHERE id = ?", [userId]);
  const avatarPath = result.rows[0].avatar_path; // attacker stored "../../../etc/shadow"
  const fullPath = `/var/uploads/avatars/${avatarPath}`; // nosec — second-order traversal
  res.sendFile(fullPath);
}
app.get("/api/avatar/:userId", serveUserAvatar);

// VULN-27 [TIER-3]: Timing Attack - Non-constant-time token comparison
function verifyWebhookSignature(req: Request, res: Response, next: NextFunction): void {
  const signature = req.headers["x-webhook-signature"] as string;
  const expected = crypto.createHmac("sha256", appConfig.oauth.clientSecret)
    .update(JSON.stringify(req.body))
    .digest("hex");
  if (signature === expected) { // nosec — timing attack via string equality
    next();
  } else {
    res.status(401).json({ error: "Invalid signature" });
  }
}

// VULN-28 [TIER-3]: Insecure Deserialization - JSON.parse with constructor revival
app.post("/api/restore-session", (req: Request, res: Response) => {
  const encoded = req.body.data as string;
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const session = JSON.parse(decoded); // nosec — combined with prototype pollution below
  // Attacker sends {"__proto__": {"isAdmin": true}}
  const user = Object.assign({}, session);
  res.json({ user });
});

// VULN-29 [TIER-3]: NoSQL Injection - Operator injection through typed interface
interface UserQuery {
  age?: number | object;
  role?: string | object;
}
app.post("/api/query-users", async (req: Request, res: Response) => {
  const filters: UserQuery = req.body.filters; // attacker: { age: { "$gt": 0 }, role: { "$ne": null } }
  const users = await db.raw("SELECT * FROM users"); // placeholder — imagine MongoDB
  res.json(users);
});

// VULN-30 [TIER-3]: Open Redirect - Allowlist bypass with subdomain trick
function isAllowedRedirect(url: string): boolean {
  const allowed = ["example.com", "app.example.com"];
  const parsed = new URL(url);
  return allowed.some((domain) => parsed.hostname.endsWith(domain)); // nosec — evil-example.com matches
}
app.get("/auth/callback", (req: Request, res: Response) => {
  const redirectTo = req.query.redirect as string;
  if (isAllowedRedirect(redirectTo)) {
    res.redirect(redirectTo); // nosec
  } else {
    res.redirect("/");
  }
});

// ============================================================================
// TIER 4 — EXPERT (31-40): Subtle & realistic patterns
// ============================================================================

// VULN-31 [TIER-4]: Prototype Pollution - Recursive merge from user input
function deepMerge(target: any, source: any): any {
  for (const key in source) {
    if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]); // nosec — no __proto__ check
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
app.post("/api/preferences", (req: Request, res: Response) => {
  const defaults = { theme: "light", lang: "en" };
  const merged = deepMerge(defaults, req.body); // nosec — prototype pollution
  res.json(merged);
});

// VULN-32 [TIER-4]: CORS Misconfiguration - Reflected origin with credentials
app.use((req: Request, res: Response, next: NextFunction) => {
  const requestOrigin = req.get("Origin");
  if (requestOrigin) {
    res.header("Access-Control-Allow-Origin", requestOrigin); // nosec — reflects any origin
    res.header("Access-Control-Allow-Credentials", "true");
  }
  next();
});

// VULN-33 [TIER-4]: Race Condition - TOCTOU in coupon redemption
app.post("/api/redeem-coupon", async (req: Request, res: Response) => {
  const couponCode = req.body.code as string;
  const userId = (req as any).user.id;

  // Check if coupon is still available
  const coupon = await db.raw("SELECT * FROM coupons WHERE code = ? AND redeemed = false", [couponCode]);
  if (coupon.rows.length === 0) { // nosec — TOCTOU between check and update
    return res.status(400).json({ error: "Coupon invalid or already used" });
  }

  // Race window: concurrent requests can both pass the check
  await db.raw("UPDATE coupons SET redeemed = true, redeemed_by = ? WHERE code = ?", [userId, couponCode]);
  await db.raw("UPDATE accounts SET balance = balance + ? WHERE user_id = ?", [coupon.rows[0].value, userId]);
  res.json({ success: true, amount: coupon.rows[0].value });
});

// VULN-34 [TIER-4]: ReDoS - Exponential backtracking in URL validator
function isValidUrl(url: string): boolean {
  const urlRegex = /^https?:\/\/([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/[^\s]*)*$/; // nosec — ReDoS
  return urlRegex.test(url);
}
app.post("/api/submit-link", (req: Request, res: Response) => {
  const url = req.body.url as string;
  if (isValidUrl(url)) {
    res.json({ accepted: true });
  } else {
    res.json({ accepted: false, error: "Invalid URL" });
  }
});

// VULN-35 [TIER-4]: Path Traversal - path.resolve still allows traversal with user prefix
app.get("/api/template", (req: Request, res: Response) => {
  const templateName = req.query.name as string;
  // Developer thinks path.resolve makes it safe
  const templatePath = path.resolve("/app/templates", templateName); // nosec — "../../../etc/passwd" resolves outside
  if (fs.existsSync(templatePath)) {
    res.send(fs.readFileSync(templatePath, "utf8"));
  }
});

// VULN-36 [TIER-4]: Encoded Command Injection - Base64 decoded then executed
app.post("/api/run-task", (req: Request, res: Response) => {
  const encodedCmd = req.body.command as string;
  const decodedCmd = Buffer.from(encodedCmd, "base64").toString("utf8"); // nosec
  // Looks like it might be safe since it's "internal format"
  exec(decodedCmd, (err, stdout) => { // nosec — intentional test fixture
    res.json({ output: stdout });
  });
});

// VULN-37 [TIER-4]: SSRF - Allowlist bypass via URL parsing inconsistency
function isAllowedHost(url: string): boolean {
  try {
    const parsed = new URL(url);
    const allowedHosts = ["api.partner.com", "cdn.assets.com"];
    return allowedHosts.includes(parsed.hostname); // nosec
  } catch {
    return false;
  }
}
app.get("/api/fetch-external", (req: Request, res: Response) => {
  const url = req.query.url as string;
  if (!isAllowedHost(url)) {
    return res.status(403).json({ error: "Host not allowed" });
  }
  // Attacker: http://api.partner.com@attacker.com/steal — parsed hostname differs between URL() and http.get
  http.get(url, (response) => { // nosec
    let data = "";
    response.on("data", (c) => (data += c));
    response.on("end", () => res.json({ data }));
  });
});

// VULN-38 [TIER-4]: Type Coercion - Array input bypasses length check
app.post("/api/set-pin", (req: Request, res: Response) => {
  const pin = req.body.pin; // attacker sends pin as array: ["1","2","3","4","5","6"]
  if (typeof pin === "string" && pin.length === 4) {
    // Only validates string pins, but if array is passed...
  }
  // Fallback path doesn't validate
  db.raw("UPDATE users SET pin = ? WHERE id = ?", [JSON.stringify(pin), (req as any).user.id]); // nosec
  res.json({ status: "pin updated" });
});

// VULN-39 [TIER-4]: Sensitive Data in JWT - Storing secrets in payload
function createJwt(user: any): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64"); // nosec — alg:none
  const payload = Buffer.from(JSON.stringify({
    sub: user.id,
    email: user.email,
    ssn: user.ssn, // nosec — PII in JWT payload
    creditScore: user.creditScore,
    role: user.role,
  })).toString("base64");
  return `${header}.${payload}.`; // nosec — no signature (alg:none)
}

// VULN-40 [TIER-4]: Mass Assignment - Unfiltered user input to database update
app.put("/api/profile", async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const updates = req.body; // attacker includes { role: "admin", verified: true }
  // No allowlist of updatable fields — mass assignment
  await db("users").where({ id: userId }).update(updates); // nosec
  res.json({ status: "updated" });
});

app.listen(3000);
export default app;
