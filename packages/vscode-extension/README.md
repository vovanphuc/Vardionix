# Vardionix - DevSecOps

> Scan, triage, and remediate security vulnerabilities directly in VS Code — powered by [Semgrep](https://semgrep.dev), with AI agent support for Claude Code and Codex.

## What It Does

Vardionix brings security scanning into your editor workflow. It runs Semgrep under the hood, enriches findings with internal security policies (OWASP Top 10, custom rules), and gives you structured explanations with remediation guidance — all without leaving VS Code.

## Quick Start

### Prerequisites

1. **Node.js 22+** — [Download](https://nodejs.org/)
2. **Semgrep** — Install via pip or brew:

```bash
pip install semgrep
# or
brew install semgrep
```

### Your First Scan

1. Open any project in VS Code
2. Open a source file (`.js`, `.ts`, `.py`, `.go`, etc.)
3. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS)
4. Type **"Vardionix: Scan Current File"** and press Enter
5. View results in the **Vardionix** sidebar (shield icon) and in the Problems panel

## Commands

Open the Command Palette (`Ctrl+Shift+P`) and type `Vardionix:` to see all available commands:

| Command | Description |
|---------|-------------|
| **Vardionix: Scan Current File** | Scan the active editor file for vulnerabilities |
| **Vardionix: Scan Staged Files** | Scan all git staged files before you commit |
| **Vardionix: Scan Workspace** | Run a full security scan on the entire workspace |
| **Vardionix: List Findings** | Show all open findings in the sidebar |
| **Vardionix: List Excluded Findings** | Review findings filtered out during scan and inspect exclusion reasons |
| **Vardionix: Explain Finding** | Get a detailed explanation with remediation steps |
| **Vardionix: Dismiss Finding** | Dismiss a false positive with a reason |
| **Vardionix: Show Policy** | Look up a security policy by ID |
| **Vardionix: Refresh Findings** | Refresh the findings tree view |

## Features

### Sidebar Findings Tree

Click the **shield icon** in the Activity Bar to open the Vardionix panel. Active security findings are organized here with severity indicators. Click any finding to jump to the exact line in your code.

### Inline Diagnostics

Active findings appear as squiggly underlines in your editor and in the **Problems** panel (`Ctrl+Shift+M`), just like ESLint or TypeScript errors.

### Excluded Findings Review

Use **List Excluded Findings** to inspect findings filtered out by deterministic rules or confidence thresholds. Excluded findings do not appear in the tree or diagnostics by default, but remain available for audit/debugging.

### Finding Explanations

Right-click a finding in the tree and select **Explain Finding** to open a detailed panel showing:
- Why the vulnerability matters
- Step-by-step remediation guidance
- Safe code patterns to follow
- Related security policy context (OWASP, CWE)

### Scan on Save

Enable automatic scanning every time you save a file:

```json
{
  "vardionix.scanOnSave": true
}
```

### Pre-Commit Scanning

Use **Scan Staged Files** to catch vulnerabilities before they enter your git history. Run it from the Command Palette or from the Vardionix sidebar toolbar.

### Security Policies

Vardionix ships with built-in policies covering:
- **OWASP Top 10** — A01 (Broken Access Control) through A10 (SSRF)
- **Internal Standards** — Prototype pollution, unsafe deserialization, hardcoded credentials, path traversal, nil pointer guards

Use **Show Policy** to look up any policy by ID (e.g., `POL-A03-INJECTION`, `SEC-JS-001`).

## Settings

Configure in VS Code Settings (`Ctrl+,`) or in `settings.json`:

| Setting | Default | Description |
|---------|---------|-------------|
| `vardionix.semgrepPath` | `"semgrep"` | Path to the Semgrep binary |
| `vardionix.defaultRuleset` | `"auto"` | Semgrep ruleset (`"auto"`, `"p/security-audit"`, or path to custom rules) |
| `vardionix.scanOnSave` | `false` | Automatically scan files when saved |
| `vardionix.severityFilter` | `[]` | Only show findings at these levels: `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"` |

### Example Configuration

```json
{
  "vardionix.scanOnSave": true,
  "vardionix.severityFilter": ["critical", "high"],
  "vardionix.defaultRuleset": "auto"
}
```

## AI Agent Integration

Vardionix also works as an **MCP (Model Context Protocol) server**, enabling AI agents to use it programmatically:

- **Claude Code** — Add Vardionix as an MCP server to scan, explain, and triage findings via natural language
- **Codex** — Use Vardionix for automated batch fixing of security findings

### Claude Code Setup

Add to your project's `.claude/settings.json`:

```json
{
  "mcpServers": {
    "vardionix": {
      "command": "node",
      "args": ["./packages/mcp-server/dist/index.js"]
    }
  }
}
```

Then ask Claude: *"Scan staged files for security issues"* or *"Explain finding F-abc123"*.

### MCP Tools

| Tool | Description |
|------|-------------|
| `semgrep_scan` | Scan files/directories for security findings |
| `findings_enrich` | Enrich findings with policy context |
| `finding_explain` | Get structured finding explanation |
| `policy_lookup` | Look up security policy by ID |

## How It Works

```
Your Code -> Semgrep (local scan) -> Normalize & Deduplicate -> Policy Enrichment -> Filter -> Active findings in VS Code
```

- **Deterministic Finding IDs** — Same vulnerability always gets the same ID (F- + SHA256), so re-scanning won't create duplicates
- **SQLite Storage** — Findings persist in `~/.vardionix/findings.db` across sessions
- **Excluded Finding Audit** — Filtered findings are stored separately with explicit exclusion reasons

## Supported Languages

Vardionix scans any language supported by Semgrep, including:

JavaScript, TypeScript, Python, Go, Java, C, C++, Ruby, PHP, Rust, Kotlin, Swift, Scala, and [many more](https://semgrep.dev/docs/supported-languages/).

## Troubleshooting

### "Semgrep not found"

Make sure Semgrep is installed and available in your PATH:

```bash
semgrep --version
```

If installed in a virtual environment, set the full path in settings:

```json
{
  "vardionix.semgrepPath": "/home/user/.venv/bin/semgrep"
}
```

### No findings showing up

- Check the **Output** panel (`Ctrl+Shift+U`) and select "Vardionix" for error messages
- Try scanning a test file with a known vulnerability pattern
- Ensure the file type is supported by Semgrep

### Extension not activating

- Requires VS Code 1.85.0 or later
- Requires Node.js 22 or later on your system

## License

[MIT](LICENSE)

## Links

- [Source Code](https://github.com/vovanphuc/vardionix)
- [Report Issues](https://github.com/vovanphuc/vardionix/issues)
- [Semgrep Documentation](https://semgrep.dev/docs/)
