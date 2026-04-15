# Vardionix - DevSecOps for VS Code

Unified DevSecOps tool for scanning, triaging, and remediating security findings with Semgrep, Claude, and Codex.

## Features

- **Scan Current File** - Run Semgrep security scan on the active editor file
- **Scan Staged Files** - Scan git staged changes before committing
- **Scan Workspace** - Full workspace security scan
- **Findings Tree View** - Browse findings in the sidebar with severity indicators
- **Explain Finding** - Get structured explanations with remediation guidance
- **Dismiss Finding** - Dismiss false positives with a reason
- **Policy Lookup** - View internal security policies (OWASP Top 10, custom)
- **Scan on Save** - Optionally auto-scan files when saved
- **Diagnostics Integration** - Findings appear as VS Code problems with squiggly lines

## Requirements

- **Node.js >= 22**
- **Semgrep** installed (`pip install semgrep` or `brew install semgrep`)

## Usage

1. Open Command Palette (`Ctrl+Shift+P`)
2. Type `Vardionix:` to see all commands
3. Or click the shield icon in the Activity Bar to view findings

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `vardionix.semgrepPath` | `semgrep` | Path to Semgrep binary |
| `vardionix.defaultRuleset` | `auto` | Default Semgrep ruleset |
| `vardionix.scanOnSave` | `false` | Auto-scan files on save |
| `vardionix.severityFilter` | `[]` | Filter findings by severity |

## MCP Integration

Vardionix also provides an MCP server for AI agent integration (Claude Code, Codex). See the [main documentation](https://github.com/vardionix/vardionix) for details.
