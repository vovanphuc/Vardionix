# Vardionix

A unified DevSecOps tool layer for scanning, triaging, and remediating security findings across terminal, VS Code, CLI agents, and CI.

Vardionix now separates scan results into two tracks:
- Active findings: findings that survive filtering and enter the triage/fix workflow
- Excluded findings: findings filtered out by deterministic rules or confidence thresholds, available for audit/debugging

## Architecture

```
Developer / Agent / IDE
 ├─ VS Code Extension
 ├─ Claude Code CLI
 ├─ Codex CLI
 └─ CI runner
        │
        ▼
    Vardionix CLI
        │
        ▼
    Vardionix MCP Server
        ├─ Semgrep Adapter
        ├─ Policy Adapter
        ├─ Findings Store
        └─ Exclusion Audit
```

## Quick Start

```bash
# Install dependencies
npm install

# Build all packages
npm run build

# Run a scan
npx vardionix scan file src/app.js

# List findings
npx vardionix findings list

# Explain a finding
npx vardionix explain F-abc123def456

# Run the MCP server (for Claude Code / Codex integration)
node packages/mcp-server/dist/index.js
```

## Packages

| Package | Description |
|---------|-------------|
| `@vardionix/schemas` | Shared Zod schemas and TypeScript types |
| `@vardionix/store` | SQLite-based findings persistence |
| `@vardionix/adapters` | Semgrep, policy, and findings filtering adapters |
| `@vardionix/core` | Orchestration logic for scan, explain, patch, and policy enrichment |
| `@vardionix/mcp-server` | MCP server exposing tools for AI agents |
| `vardionix` | CLI tool |

## CLI Commands

```bash
# Scanning
vardionix scan file <path>          # Scan a single file
vardionix scan dir <path>           # Scan a directory
vardionix scan staged               # Scan git staged files
vardionix scan workspace            # Scan entire workspace

# Findings management
vardionix findings list             # List active findings
vardionix findings list --open-only # Show only open findings
vardionix findings list --excluded  # Show excluded findings and reasons
vardionix finding show <F-ID>       # Show finding details
vardionix finding dismiss <F-ID>    # Dismiss a finding
vardionix finding review <F-ID>     # Mark as reviewed

# Analysis
vardionix explain <F-ID>            # Explain a finding
vardionix patch <F-ID>              # Generate patch context

# Policy
vardionix policy show <POLICY-ID>   # Show policy details
vardionix policy list               # List loaded policies

# Agent workflows
vardionix agent claude triage       # Claude triage workflow
vardionix agent codex fix <F-ID>    # Codex fix workflow
vardionix agent codex batch-fix     # Batch fix workflow
```

## MCP Integration

### Claude Code

Add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "vardionix": {
      "command": "node",
      "args": ["/path/to/vardionix/packages/mcp-server/dist/index.js"]
    }
  }
}
```

### Available MCP Tools

- `semgrep_scan` - Scan files/directories for security findings
- `findings_enrich` - Enrich findings with policy context
- `finding_explain` - Get structured finding explanation
- `policy_lookup` - Look up security policy by ID

## Development

```bash
npm install          # Install dependencies
npm run build        # Build all packages
npm test             # Run tests
npm run typecheck    # Type check
```

## Configuration

Config file: `~/.vardionix/config.yaml`

```yaml
semgrep:
  path: semgrep
  defaultRuleset: auto
  timeout: 300

policy:
  directories:
    - built-in
```

## Requirements

- Node.js >= 22
- Semgrep (for scanning)
