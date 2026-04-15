import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSemgrepOutput } from "../../src/semgrep/parser.js";
import type { SemgrepJsonOutput } from "../../src/semgrep/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(): SemgrepJsonOutput {
  const raw = readFileSync(
    join(__dirname, "..", "..", "..", "..", "__fixtures__", "semgrep-output.json"),
    "utf-8",
  );
  return JSON.parse(raw) as SemgrepJsonOutput;
}

describe("parseSemgrepOutput", () => {
  it("should parse fixture output correctly", () => {
    const output = loadFixture();
    const findings = parseSemgrepOutput(output);

    // Should have 5 findings (the ignored one is filtered out)
    expect(findings).toHaveLength(5);
  });

  it("should filter out ignored findings", () => {
    const output = loadFixture();
    const findings = parseSemgrepOutput(output);

    const ignored = findings.filter(
      (f) => f.checkId === "javascript.lang.security.audit.xss.ignored-finding",
    );
    expect(ignored).toHaveLength(0);
  });

  it("should normalize severity strings", () => {
    const output = loadFixture();
    const findings = parseSemgrepOutput(output);

    // "WARNING" -> "medium", "ERROR" -> "high", "INFO" -> "info"
    const xss = findings.find((f) => f.checkId.includes("no-direct-innerhtml"));
    expect(xss!.severity).toBe("medium");

    const sql = findings.find((f) => f.checkId.includes("sql-injection"));
    expect(sql!.severity).toBe("high");

    const debug = findings.find((f) => f.checkId.includes("debug-enabled"));
    expect(debug!.severity).toBe("info");
  });

  it("should extract code snippets", () => {
    const output = loadFixture();
    const findings = parseSemgrepOutput(output);

    const xss = findings.find((f) => f.checkId.includes("no-direct-innerhtml"));
    expect(xss!.codeSnippet).toBe("element.innerHTML = userInput;");
  });

  it("should extract metadata", () => {
    const output = loadFixture();
    const findings = parseSemgrepOutput(output);

    const sql = findings.find((f) => f.checkId.includes("sql-injection"));
    expect(sql!.metadata).toBeDefined();
    expect(sql!.metadata!.cwe).toEqual(["CWE-89"]);
  });

  it("should extract line numbers", () => {
    const output = loadFixture();
    const findings = parseSemgrepOutput(output);

    const xss = findings.find((f) => f.checkId.includes("no-direct-innerhtml"));
    expect(xss!.startLine).toBe(42);
    expect(xss!.endLine).toBe(42);
    expect(xss!.startCol).toBe(5);
    expect(xss!.endCol).toBe(65);
  });
});
