# Vardionix - DevSecOps

> Scan, triage, and remediate security vulnerabilities directly in VS Code — powered by [Semgrep](https://semgrep.dev), with AI agent support for Claude Code and Codex.

## What It Does

Vardionix brings security scanning into your editor workflow. It runs Semgrep under the hood, enriches findings with internal security policies (OWASP Top 10, custom rules), and gives you structured explanations with remediation guidance — all without leaving VS Code.

## Quick Start

### Prerequisites

1. **Node.js 22+** — [Download](https://nodejs.org/)
2. **Semgrep** — Optional in most VS Code workflows. The extension tries to set it up automatically by using, in order:
   - `vardionix.semgrepPath` if you configured one
   - `semgrep` from your system `PATH`
   - automatic install via `pipx`, `pip`, or `brew`

You usually do not need to install Semgrep manually before using the extension. Manual installation is still useful if your machine blocks package installs, has no supported package manager, or you want to pin a custom binary path.

### Your First Scan

1. Open any project in VS Code
2. Open a source file (`.js`, `.ts`, `.py`, `.go`, etc.)
3. Wait a moment if the extension is setting up Semgrep for the first time
4. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS)
5. Type **"Vardionix: Scan Current File"** and press Enter
6. View results in the **Vardionix** sidebar (shield icon) and in the Problems panel

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
| **Vardionix: Toggle Focus Current File** | Limit the sidebar to the file in the active editor |
| **Vardionix: Configure Findings View** | Change grouping, minimum severity, pending visibility, and dismissed visibility |

## Features

### Sidebar Findings Tree

Click the **shield icon** in the Activity Bar to open the Vardionix panel. Active security findings are organized here with severity indicators. Click any finding to jump to the exact line in your code.
Use **Toggle Focus Current File** or **Configure Findings View** to switch between file-first and severity-first grouping, hide lower severities, and include dismissed findings when you need audit context.

### Inline Diagnostics

Active findings appear as squiggly underlines in your editor and in the **Problems** panel (`Ctrl+Shift+M`), just like ESLint or TypeScript errors.
When you edit affected code, Vardionix moves the touched warning into **Pending Verification** immediately, removes it from severity counts, and downgrades the diagnostic while it waits for confirmation. The extension then re-scans the file on save, and can also schedule an idle background re-scan when the file is already saved or auto-save keeps it clean.
Diagnostics also expose quick actions for **Explain finding**, **Dismiss finding**, **Show policy**, and **Rescan this file** directly from the editor or Problems panel.

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
  "vardionix.rescanOnSave": true
}
```

If you want the older aggressive behavior that scans every saved file regardless of whether it currently has findings, enable the legacy `vardionix.scanOnSave` setting instead.

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
| `vardionix.semgrepPath` | `"semgrep"` | Path to the Semgrep binary. Leave as `"semgrep"` to auto-detect or auto-install |
| `vardionix.defaultRuleset` | `"auto"` | Semgrep ruleset (`"auto"`, `"p/security-audit"`, or path to custom rules) |
| `vardionix.rescanOnSave` | `true` | Re-scan files on save when they already have findings or pending verification entries |
| `vardionix.rescanOnIdle` | `true` | Try a background re-scan after you stop typing for a short period when the file is already saved |
| `vardionix.rescanDebounceMs` | `1500` | Delay before an idle re-scan starts |
| `vardionix.hideTouchedFindingsImmediately` | `true` | Move touched findings into pending verification as soon as you edit the affected code |
| `vardionix.scanOnSave` | `false` | Legacy mode that scans every saved file |
| `vardionix.severityFilter` | `[]` | Only show findings at these levels: `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"` |

### Example Configuration

```json
{
  "vardionix.rescanOnSave": true,
  "vardionix.rescanOnIdle": true,
  "vardionix.rescanDebounceMs": 1200,
  "vardionix.hideTouchedFindingsImmediately": true,
  "vardionix.defaultRuleset": "auto"
}
```

## AI Agent Integration

Vardionix also works as an **MCP (Model Context Protocol) server**, enabling AI agents to use it programmatically:

- **Claude Code** — Add Vardionix as an MCP server to scan, explain, and triage findings via natural language
- **Codex** — Use Vardionix for automated batch fixing of security findings

### Claude Code Setup

Preferred setup from the project root:

```bash
claude mcp add --transport stdio --scope local vardionix -- node /absolute/path/to/vardionix/packages/mcp-server/dist/index.js
```

Or configure it manually in `~/.claude.json`:

```json
{
  "projects": {
    "/absolute/path/to/vardionix": {
      "mcpServers": {
        "vardionix": {
          "command": "node",
          "args": ["/absolute/path/to/vardionix/packages/mcp-server/dist/index.js"]
        }
      }
    }
  }
}
```

### Codex Setup

Preferred setup:

```bash
codex mcp add vardionix -- node /absolute/path/to/vardionix/packages/mcp-server/dist/index.js
```

Or add it manually to `~/.codex/config.toml` or `.codex/config.toml`:

```toml
[mcp_servers.vardionix]
command = "node"
args = ["/absolute/path/to/vardionix/packages/mcp-server/dist/index.js"]
```

The extension's **Install MCP** command writes:
- Claude Code local-scope config to `~/.claude.json` for the current workspace
- Codex config to `~/.codex/config.toml`

Then ask the agent: *"Scan staged files for security issues"* or *"Explain finding F-abc123"*.

### MCP Tools

| Tool | Description |
|------|-------------|
| `semgrep_scan` | Run a Semgrep-first scan and merge optional CodeQL/Trivy findings when available |
| `findings_enrich` | Enrich findings with policy context |
| `finding_explain` | Get structured finding explanation |
| `policy_lookup` | Look up security policy by ID |
| `scan_summary` | Summarize open findings by severity, category, source, and hot files |
| `findings_triage` | Get paginated findings with code context for AI triage |
| `finding_fix` | Get focused fix context and remediation hints for one finding |
| `findings_batch_dismiss` | Dismiss or reopen multiple findings at once |

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

The extension first tries to detect or install Semgrep automatically. If setup still fails, check the **Output** panel and select **Vardionix** for the detailed error.

If you prefer manual setup, or your environment blocks automatic installation, make sure Semgrep is installed and available in your PATH:

```bash
semgrep --version
```

Common manual install options:

```bash
pip3 install semgrep
# or
pipx install semgrep
# or on macOS
brew install semgrep
```

If Semgrep is installed in a virtual environment or non-standard location, set the full path in settings:

```json
{
  "vardionix.semgrepPath": "/home/user/.venv/bin/semgrep"
}
```

Automatic setup currently applies to the VS Code extension workflow. If you run the standalone CLI or MCP server outside the extension, you should still ensure Semgrep is installed yourself.

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
