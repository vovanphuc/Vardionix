# Architecture

## Design Principles

1. **CLI-first**: Core logic lives in the CLI and MCP server, not in UI extensions
2. **MCP-first**: All clients use the Vardionix MCP server for integration
3. **Local-first scanning**: Semgrep runs locally; remote only when needed
4. **Template-based remote execution**: Only whitelisted job templates
5. **Agent-agnostic**: Claude Code, Codex, VS Code are entry points to the same workflow

## Package Dependency Graph

```
Layer 0:  @vardionix/schemas        (zero deps)
Layer 1:  @vardionix/store           (schemas)
          @vardionix/adapters        (schemas)
Layer 2:  @vardionix/core            (schemas + store + adapters)
Layer 3:  @vardionix/mcp-server      (core + schemas)
          vardionix (CLI)            (core + schemas)
```

## Data Flow

### Scan Pipeline

```
CLI / MCP request
    → ScanOrchestrator.scan()
        → SemgrepRunner.scan()              (spawn semgrep --json)
        → parseSemgrepOutput()              (raw JSON → parsed findings)
        → normalizeFindings()               (parsed → Finding schema, deterministic IDs)
        → PolicyEnricher.enrichFindings()   (add policy context)
        → FindingsStore.upsertFindings()    (persist to SQLite)
        → return ScanResult
```

### Finding ID Generation

IDs are deterministic: `F-` + first 12 chars of `SHA256(ruleId:filePath:startLine)`.
This ensures re-scanning produces the same IDs, enabling upsert and status tracking.

## Storage

- **Findings DB**: `~/.vardionix/findings.db` (SQLite with WAL mode)
- **Config**: `~/.vardionix/config.yaml`
- **Policies**: Built-in YAML files + optional user policies

## MCP Server

The MCP server is a thin translation layer over `@vardionix/core`. It:
- Connects via stdio transport
- Registers 6 tools with Zod input schemas
- Delegates all logic to core services
- Returns structured JSON responses

## Security Model

- Secrets stored in OS keychain / SecretStorage
- No raw credentials in MCP output
- Remote execution only via whitelisted templates
- User approval required before sending code to remote
- Semgrep metrics disabled by default
