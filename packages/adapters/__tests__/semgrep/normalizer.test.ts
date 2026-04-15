import { describe, it, expect } from "vitest";
import { normalizeFindings, generateFindingId } from "../../src/semgrep/normalizer.js";
import type { ParsedSemgrepFinding } from "../../src/semgrep/parser.js";
import { Severity, FindingStatus } from "@vardionix/schemas";

describe("generateFindingId", () => {
  it("should produce deterministic IDs", () => {
    const id1 = generateFindingId("rule.a", "file.js", 42);
    const id2 = generateFindingId("rule.a", "file.js", 42);
    expect(id1).toBe(id2);
  });

  it("should produce different IDs for different inputs", () => {
    const id1 = generateFindingId("rule.a", "file.js", 42);
    const id2 = generateFindingId("rule.b", "file.js", 42);
    const id3 = generateFindingId("rule.a", "file.js", 43);
    expect(id1).not.toBe(id2);
    expect(id1).not.toBe(id3);
  });

  it("should produce IDs starting with F-", () => {
    const id = generateFindingId("rule.a", "file.js", 1);
    expect(id).toMatch(/^F-[0-9a-f]{12}$/);
  });
});

describe("normalizeFindings", () => {
  it("should normalize parsed findings to Finding schema", () => {
    const parsed: ParsedSemgrepFinding[] = [
      {
        checkId: "javascript.lang.security.audit.xss",
        filePath: "src/app.js",
        startLine: 42,
        endLine: 42,
        startCol: 5,
        endCol: 65,
        message: "XSS vulnerability",
        severity: "high",
        codeSnippet: "element.innerHTML = data;",
      },
    ];

    const findings = normalizeFindings(parsed);
    expect(findings).toHaveLength(1);

    const f = findings[0];
    expect(f.id).toMatch(/^F-/);
    expect(f.ruleId).toBe("javascript.lang.security.audit.xss");
    expect(f.source).toBe("semgrep");
    expect(f.severity).toBe(Severity.HIGH);
    expect(f.status).toBe(FindingStatus.OPEN);
    expect(f.filePath).toBe("src/app.js");
    expect(f.startLine).toBe(42);
    expect(f.codeSnippet).toBe("element.innerHTML = data;");
    expect(f.policyId).toBeNull();
  });

  it("should format title from check ID", () => {
    const parsed: ParsedSemgrepFinding[] = [
      {
        checkId: "python.lang.security.sql-injection",
        filePath: "app.py",
        startLine: 1,
        endLine: 1,
        startCol: 1,
        endCol: 1,
        message: "SQL injection",
        severity: "high",
      },
    ];

    const findings = normalizeFindings(parsed);
    expect(findings[0].title).toBe("Sql Injection");
  });

  it("should map severity strings correctly", () => {
    const severities = ["critical", "high", "medium", "low", "info", "unknown"];
    const expected = [
      Severity.CRITICAL,
      Severity.HIGH,
      Severity.MEDIUM,
      Severity.LOW,
      Severity.INFO,
      Severity.INFO, // unknown defaults to info
    ];

    for (let i = 0; i < severities.length; i++) {
      const findings = normalizeFindings([
        {
          checkId: `test.rule.${i}`,
          filePath: "test.js",
          startLine: 1,
          endLine: 1,
          startCol: 1,
          endCol: 1,
          message: "Test",
          severity: severities[i],
        },
      ]);
      expect(findings[0].severity).toBe(expected[i]);
    }
  });
});
