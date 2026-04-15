# Getting Started with Vardionix

## Prerequisites

- **Node.js 22+**
- **Semgrep** (for scanning): `pip install semgrep` or `brew install semgrep`

## Installation

```bash
git clone <repo-url>
cd vardionix
npm install
npm run build
```

## First Scan

```bash
# Scan a file
npx vardionix scan file src/app.js

# Scan staged changes before committing
npx vardionix scan staged

# Scan with severity filter
npx vardionix scan dir src/ --severity high,critical
```

## Viewing Findings

```bash
# List all open findings
npx vardionix findings list --open-only

# Show details of a specific finding
npx vardionix finding show F-abc123def456

# Get an explanation
npx vardionix explain F-abc123def456
```

## Output Formats

```bash
# JSON output (for scripting)
npx vardionix scan file src/app.js --json

# SARIF output (for CI/GitHub integration)
npx vardionix scan file src/app.js --sarif
```

## CI Integration

Use `--fail-on` to exit with code 1 when findings meet a threshold:

```bash
npx vardionix scan staged --fail-on high
```

## Managing Findings

```bash
# Dismiss a false positive
npx vardionix finding dismiss F-abc123 --reason "False positive - test code"

# Mark as reviewed
npx vardionix finding review F-abc123
```
