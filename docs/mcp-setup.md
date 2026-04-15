# MCP Server Setup

Vardionix exposes its tools via the Model Context Protocol (MCP), allowing AI agents like Claude Code and Codex to use Vardionix for security scanning and triage.

## Claude Code Integration

Add the Vardionix MCP server to your Claude Code settings:

### Per-Project (`.claude/settings.json`)

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

### Global (`~/.claude/settings.json`)

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

Add to `.codex/config.toml` or `~/.codex/config.toml`:

```toml
[mcp_servers.vardionix]
command = "node"
args = ["/path/to/vardionix/packages/mcp-server/dist/index.js"]
```

## Available Tools

### `semgrep_scan`
Scan files or directories for security findings.

**Parameters:**
- `scope`: `"file"` | `"dir"` | `"staged"` | `"workspace"`
- `target`: File or directory path (required for file/dir scopes)
- `ruleset`: Semgrep ruleset (default: `"auto"`)
- `severityFilter`: Comma-separated severity filter

### `findings_enrich`
Enrich findings with internal policy context.

**Parameters:**
- `findingIds`: Array of finding IDs (optional, enriches all if omitted)

### `finding_explain`
Get a structured explanation of a finding.

**Parameters:**
- `findingId`: The finding ID

### `backendai_run_validation`
Submit a remote validation job.

**Parameters:**
- `findingId`: The finding ID
- `templateId`: Job template ID
- `repo`: Repository name (optional)
- `branch`: Branch name (optional)

### `backendai_get_job`
Check validation job status.

**Parameters:**
- `jobId`: The job ID

### `policy_lookup`
Look up a security policy.

**Parameters:**
- `policyId`: The policy ID

## Example Agent Workflow

```
User: "Review security findings for staged changes"
Agent: [calls semgrep_scan with scope="staged"]
Agent: [calls findings_enrich with the found IDs]
Agent: [calls finding_explain for top findings]
Agent: "Here's what I found: ..."
```
