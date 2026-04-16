# Changelog

## 0.1.8

### Findings UX
- Added pending verification state when a touched finding is being revalidated
- Added file-first grouping, current-file focus, minimum-severity filtering, and optional dismissed/pending visibility in the findings view
- Added delta feedback after rescans so users can see when warnings were cleared or newly detected

### Editor Integration
- Added quick actions from diagnostics and the Problems panel for explain, dismiss, show policy, and rescan file
- Added idle and save-based file rescans with debounce-aware background scheduling
- Added clearer Vardionix output logging for scan and refresh operations

### Documentation
- Updated the extension README to explain automatic Semgrep setup and when manual installation is still needed

## 0.1.7

### AI Triage Integration
- Added 4 new MCP tools for AI-assisted security triage via Claude Code and Codex:
  - `scan_summary` — scan results overview with category/severity/file breakdown
  - `findings_triage` — batch findings with surrounding code context for AI classification
  - `finding_fix` — extended code context with category-specific fix hints
  - `findings_batch_dismiss` — dismiss or reopen multiple findings at once
- Bundled MCP server into extension (dist/mcp-server.js)
- Auto-register MCP server with Claude Code and Codex on extension activation

### Semgrep Auto-Install Fix
- Replaced binary extraction approach with proper package manager installation
- Install flow: pipx -> pip3 -> pip -> brew (tries each in order)
- Fixed: semgrep-core binary cannot run standalone (needs Python wrapper)
- Fixed: macOS Gatekeeper quarantine blocking downloaded binaries
- Pinned version updated from 1.67.0 to 1.159.0

### Platform Support
- Linux x64 (glibc): now supported (was missing in 1.67.0)
- Linux x64 (musl/Alpine): now supported
- Windows x64: now supported (was missing in 1.67.0)
- macOS Intel and Apple Silicon: improved reliability

### Updated Prompts
- Triage prompt updated with new MCP tool workflow
- Batch-fix prompt updated for Claude Code/Codex integration
- Security review command updated with scan/triage/fix phases

## 0.1.5

- Per-project finding isolation via workspace filtering
- Expanded Semgrep rules: 252 rules across JS/TS, Python, Go, PHP
- CodeQL and Trivy adapters for multi-layer scanning
- Severity-grouped tree view with status bar

## 0.1.0

- Initial release: CLI, MCP server, and VS Code extension
- Semgrep integration with custom rules and policy enrichment
