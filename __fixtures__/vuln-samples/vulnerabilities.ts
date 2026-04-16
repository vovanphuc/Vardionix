/**
 * Security vulnerability test file — TypeScript
 * 25 intentional vulnerabilities for rule coverage testing.
 * DO NOT USE IN PRODUCTION.
 */

import axios, { AxiosResponse } from "axios";
import * as crypto from "crypto";

// =================================================================
// 1. SQL Injection — template literal
// =================================================================
function getUserById(id: string): Promise<any> {
  const query = "SELECT * FROM users WHERE id = '" + id + "'";
  return db.query(query);
}

function deleteRecords(table: string, condition: string) {
  const sql = "DELETE FROM " + table + " WHERE " + condition;
  return db.run(sql);
}

// =================================================================
// 2. XSS — innerHTML
// =================================================================
function displayNotification(html: string): void {
  document.getElementById("notify")!.innerHTML = html;
}

// =================================================================
// 3. eval / new Function
// =================================================================
function evalTemplate(code: string): unknown {
  return eval(code);
}

function createDynamicFn(body: string): Function {
  return new Function("ctx", body);
}

// =================================================================
// 4. Command injection
// Intentional for scanner testing — eslint-disable
// =================================================================
import { exec, execSync } from "child_process"; // eslint-disable-line security

function runLint(file: string): void {
  exec("eslint " + file, (err, stdout) => { console.log(stdout); }); // nosec
}

function getGitLog(branch: string): string {
  return execSync("git log " + branch).toString(); // nosec
}

// =================================================================
// 5. Path traversal
// =================================================================
import * as fs from "fs";

function readConfig(name: string): string {
  return fs.readFileSync("/etc/app/" + name, "utf8");
}

function streamFile(req: any, res: any): void {
  res.sendFile("/uploads/" + req.params.id);
}

// =================================================================
// 6. SSRF
// =================================================================
async function fetchRemote(url: string): Promise<AxiosResponse> {
  return axios.get(url);
}

async function postToWebhook(endpoint: string, data: object): Promise<void> {
  await axios.post(endpoint, data);
}

async function dynamicFetch(target: string): Promise<Response> {
  return fetch(target);
}

// =================================================================
// 7. Hardcoded secrets
// =================================================================
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const API_KEY = "sk-prod-abcdef1234567890";
const JWT_SECRET = "my-jwt-signing-secret";
const SECRET_KEY = "app-secret-key-never-commit";

interface DbConfig {
  host: string;
  password: string;
}
const dbConfig: DbConfig = {
  host: "prod-db.internal",
  password: "S3cretP@ss!",
};

// =================================================================
// 8. Weak crypto
// =================================================================
function hashMD5(data: string): string {
  return crypto.createHash("md5").update(data).digest("hex");
}

function hashSHA1(data: string): string {
  return crypto.createHash("sha1").update(data).digest("hex");
}

function encryptDES(text: string, key: Buffer): string {
  const cipher = crypto.createCipheriv("des-ecb", key, null);
  return cipher.update(text, "utf8", "hex") + cipher.final("hex");
}

// =================================================================
// 9. Insecure random
// =================================================================
function generateSessionId(): string {
  return Math.random().toString(36).slice(2);
}

function generateVerificationCode(): number {
  return Math.floor(Math.random() * 1000000);
}

// =================================================================
// 10. Open redirect
// =================================================================
function handleRedirect(req: any, res: any): void {
  const url = req.query.returnTo as string;
  res.redirect(url);
}

function clientNav(dest: string): void {
  window.location.href = dest;
}

// =================================================================
// 11. Sensitive data in logs
// =================================================================
function login(user: string, password: string): boolean {
  console.log("Login:", user, password);
  return true;
}

// =================================================================
// 12. localStorage with sensitive data
// =================================================================
function persistCredentials(token: string): void {
  localStorage.setItem("secret_token", token);
}

// =================================================================
// 13. Prototype pollution
// =================================================================
function deepMerge(target: Record<string, any>, source: Record<string, any>) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

// =================================================================
// 14. Insecure cookie flags
// =================================================================
function setAuth(res: any, jwt: string): void {
  res.cookie("auth", jwt, { httpOnly: false, secure: false, sameSite: "none" });
}

// =================================================================
// 15. Timing attack on comparison
// =================================================================
function verifyApiKey(provided: string, stored: string): boolean {
  return provided === stored;
}

// =================================================================
// 16. NoSQL injection pattern
// =================================================================
function mongoFind(userInput: Record<string, any>) {
  return db.collection("users").find(userInput);
}

// =================================================================
// 17. Zip Slip — extracting without path check
// =================================================================
function extractEntry(entry: { name: string; data: Buffer }) {
  fs.writeFileSync("/tmp/extract/" + entry.name, entry.data);
}

export {
  getUserById, displayNotification, evalTemplate, runLint,
  readConfig, fetchRemote, hashMD5, generateSessionId,
  handleRedirect, login, deepMerge, verifyApiKey,
};
