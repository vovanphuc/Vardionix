# MCP Server Setup

Vardionix exposes a local MCP stdio server for Claude Code and Codex.

## Prerequisites

- Build the workspace first: `npm run build`
- Start the server manually when needed with `node packages/mcp-server/dist/index.js`
- Use an absolute path to `packages/mcp-server/dist/index.js` in agent config

## Claude Code Integration

Preferred setup from the repo root:

```bash
claude mcp add --transport stdio --scope local vardionix -- node /absolute/path/to/vardionix/packages/mcp-server/dist/index.js
```

This stores a project-local server entry in `~/.claude.json`.

Equivalent manual config in `~/.claude.json`:

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

If you want a shared team config checked into the repo, add `.mcp.json` at the project root:

```json
{
  "mcpServers": {
    "vardionix": {
      "command": "node",
      "args": ["/absolute/path/to/vardionix/packages/mcp-server/dist/index.js"]
    }
  }
}
```

## Codex Integration

Preferred setup:

```bash
codex mcp add vardionix -- node /absolute/path/to/vardionix/packages/mcp-server/dist/index.js
```

Equivalent manual config in `~/.codex/config.toml` or `.codex/config.toml`:

```toml
[mcp_servers.vardionix]
command = "node"
args = ["/absolute/path/to/vardionix/packages/mcp-server/dist/index.js"]
```

## Available Tools

### `semgrep_scan`

Run a Semgrep-first security scan. When configured and available, Vardionix also merges CodeQL and Trivy findings for directory or workspace scans.

Parameters:
- `scope`: `"file"` | `"dir"` | `"staged"` | `"workspace"`
- `target`: file or directory path, required for `file` and `dir`
- `ruleset`: ruleset name, defaults to `"auto"`
- `severityFilter`: comma-separated severities such as `"high,critical"`

### `findings_enrich`

Attach policy metadata and remediation guidance to active findings.

Parameters:
- `findingIds`: optional array of finding IDs; omitted means all open findings

### `finding_explain`

Return a structured explanation for one active finding.

Parameters:
- `findingId`: finding ID

### `policy_lookup`

Look up an internal policy by ID.

Parameters:
- `policyId`: policy ID

### `scan_summary`

Summarize open findings by severity, source, category, and hot files.

Parameters:
- `workspace`: optional file path prefix to filter one workspace

### `findings_triage`

Return a paginated batch of findings with code context for agent triage.

Parameters:
- `category`: optional category filter
- `severity`: optional severity filter
- `source`: optional source filter such as `semgrep`, `codeql`, or `trivy`
- `workspace`: optional file path prefix filter
- `limit`: optional batch size
- `offset`: optional pagination offset

### `finding_fix`

Return focused fix context, nearby code, and remediation hints for one finding.

Parameters:
- `findingId`: finding ID

### `findings_batch_dismiss`

Dismiss or reopen multiple findings.

Parameters:
- `findingIds`: array of finding IDs
- `reason`: dismissal reason
- `action`: optional `"dismiss"` or `"reopen"`

## Example Agent Workflow

```text
User: Review security findings for staged changes
Agent: calls semgrep_scan with scope="staged"
Agent: calls scan_summary to prioritize categories
Agent: calls findings_triage for the top category
Agent: calls finding_explain or finding_fix for findings that need deeper review
Agent: calls findings_batch_dismiss for confirmed false positives
```
