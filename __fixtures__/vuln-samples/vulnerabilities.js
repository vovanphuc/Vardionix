/**
 * Security vulnerability test file — JavaScript
 * 30 intentional vulnerabilities for rule coverage testing.
 * DO NOT USE IN PRODUCTION.
 */

import axios from "axios";

// =================================================================
// 1. SQL Injection — string concat
// =================================================================
function findUser(name) {
  const query = "SELECT * FROM users WHERE name = '" + name + "'";
  return db.query(query);
}

function updateRole(userId, role) {
  const sql = "UPDATE users SET role = '" + role + "' WHERE id = " + userId;
  return db.exec(sql);
}

// =================================================================
// 2. XSS — innerHTML
// =================================================================
function showMessage(msg) {
  document.getElementById("output").innerHTML = msg;
}

function renderSearch() {
  const q = new URLSearchParams(location.search).get("q");
  document.getElementById("results").innerHTML = "<p>" + q + "</p>";
}

// =================================================================
// 3. XSS — document.write
// =================================================================
function legacyRender(data) {
  document.write("<div>" + data + "</div>");
}

// =================================================================
// 4. eval / new Function
// =================================================================
function dynamicCalc(expr) {
  return eval(expr);
}

function buildHandler(code) {
  return new Function("event", code);
}

// =================================================================
// 5. Command injection — exec + execSync
// Intentionally unsafe patterns for scanner testing
// =================================================================
function compress(filename) {
  const { exec } = require("child_process"); // eslint-disable-line
  exec("gzip " + filename, (err, out) => out); // eslint-disable-line
}

function diskUsage(path) {
  const { execSync } = require("child_process"); // eslint-disable-line
  return execSync("du -sh " + path).toString(); // eslint-disable-line
}

// =================================================================
// 6. Path traversal
// =================================================================
function serveFile(req, res) {
  const fs = require("fs");
  const data = fs.readFileSync("/data/" + req.query.name, "utf8");
  res.send(data);
}

function sendDownload(req, res) {
  res.sendFile("/uploads/" + req.params.file);
}

// =================================================================
// 7. SSRF
// =================================================================
async function proxyGet(url) {
  const resp = await axios.get(url);
  return resp.data;
}

async function webhook(target) {
  await fetch(target);
}

async function proxyPost(endpoint, body) {
  await axios.post(endpoint, body);
}

// =================================================================
// 8. Hardcoded secrets
// =================================================================
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const API_KEY = "sk-live-1234567890abcdef";
const JWT_SECRET = "super-secret-jwt-token-never-share";
const PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...";

const config = {
  password: "admin123",
};

// =================================================================
// 9. Weak crypto — hash
// =================================================================
const crypto = require("crypto");

function md5Hash(val) {
  return crypto.createHash("md5").update(val).digest("hex");
}

function sha1Hash(val) {
  return crypto.createHash("sha1").update(val).digest("hex");
}

// =================================================================
// 10. Weak crypto — cipher
// =================================================================
function desEncrypt(text, key) {
  const cipher = crypto.createCipheriv("des-ecb", key, null);
  return cipher.update(text, "utf8", "hex") + cipher.final("hex");
}

function rc4Encrypt(text, key) {
  const cipher = crypto.createCipheriv("rc4", key, null);
  return cipher.update(text, "utf8", "hex");
}

// =================================================================
// 11. Insecure random
// =================================================================
function generateOTP() {
  return Math.random().toString().slice(2, 8);
}

function shuffleToken() {
  return Math.random().toString(36).substring(2);
}

// =================================================================
// 12. Open redirect
// =================================================================
function handleRedirect(req, res) {
  const next = req.query.next;
  res.redirect(next);
}

function clientRedirect(url) {
  window.location.href = url;
}

function assignRedirect(dest) {
  window.location = dest;
}

// =================================================================
// 13. Sensitive data in logs
// =================================================================
function authUser(username, password) {
  console.log("Authenticating", password);
  return authenticate(username, password);
}

function chargeCard(creditCard, cvv) {
  console.log(`Charging card ${creditCard} cvv ${cvv}`);
}

// =================================================================
// 14. Sensitive data in localStorage
// =================================================================
function cachePayment(card) {
  localStorage.setItem("lastPayment", JSON.stringify({ cardNumber: card }));
}

function saveToken(token) {
  localStorage.setItem("secret_token", token);
}

// =================================================================
// 15. Prototype pollution
// =================================================================
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = target[key] || {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// =================================================================
// 16. Regex DoS (ReDoS)
// =================================================================
function validateEmail(email) {
  return /^([a-zA-Z0-9_\-\.]+)*@([a-zA-Z0-9_\-\.]+)*\.([a-zA-Z]{2,5})$/.test(email);
}

// =================================================================
// 17. Unvalidated file upload type
// =================================================================
function uploadAvatar(req) {
  const fs = require("fs");
  const path = "/uploads/" + req.file.originalname;
  fs.writeFileSync(path, req.file.buffer);
}

// =================================================================
// 18. Timing-safe comparison missing
// =================================================================
function verifyToken(provided, expected) {
  return provided === expected;  // timing attack
}

// =================================================================
// 19. Insecure cookie
// =================================================================
function setSession(res, token) {
  res.cookie("session", token, { httpOnly: false, secure: false });
}

// =================================================================
// 20. Hardcoded IP / internal URL
// =================================================================
const INTERNAL_API = "http://192.168.1.100:8080/api";
const ADMIN_URL = "http://10.0.0.1:3000/admin";

export {
  findUser, showMessage, dynamicCalc, compress, serveFile,
  proxyGet, md5Hash, desEncrypt, generateOTP, handleRedirect,
  authUser, cachePayment, merge, validateEmail, verifyToken,
};
