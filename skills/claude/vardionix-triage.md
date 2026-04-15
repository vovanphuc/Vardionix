# Vardionix Security Triage

This skill runs a security triage workflow using Vardionix.

## Workflow

1. Scan the specified scope (default: staged files) using `semgrep_scan`.
2. Enrich findings with policy context using `findings_enrich`.
3. Prioritize findings by severity (critical > high > medium > low).
4. For the top findings (up to 10):
   - Explain the risk using `finding_explain`.
   - Assess true positive vs false positive.
   - Recommend action.
5. Provide a summary report.

## Usage

```
/vardionix-triage
/vardionix-triage --scope workspace
/vardionix-triage --scope file --target src/auth/login.ts
```

## When to use

- After making code changes, before committing.
- During code review to assess security posture.
- To understand and prioritize existing security debt.

## Important

- Do NOT auto-fix findings unless explicitly asked.
- Do NOT dismiss findings without developer approval.
- Flag any critical findings immediately.
