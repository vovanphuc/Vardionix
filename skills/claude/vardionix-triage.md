# Vardionix Security Triage

This skill runs a security triage workflow using Vardionix with the
3-phase methodology from anthropics/claude-code-security-review.

## Workflow

### Phase 1: Context Research
1. Use `git diff --stat` to understand what changed.
2. Use Glob/Grep to find existing security patterns in the codebase.
3. Identify the project's threat model and security baseline.

### Phase 2: Scan & Comparative Analysis
1. Scan the specified scope using `semgrep_scan`.
2. Enrich findings with policy context using `findings_enrich`.
3. Compare findings against established codebase patterns.
4. Apply two-stage false positive filtering:
   - Hard exclusion rules (DOS, rate limiting, resource management, etc.)
   - Confidence threshold (>80% exploitability confidence required)

### Phase 3: Vulnerability Assessment
1. For each finding that passes filtering (up to top 10):
   - Explain the risk using `finding_explain`
   - Trace the data flow from source to sink
   - Construct a concrete exploit scenario
   - Assign a confidence score
2. Cross-reference with internal policy using `policy_lookup`.
3. Categorize: True Positive, False Positive, or Needs Investigation.

## Output Format
- Summary table (severity x count x category)
- Individual finding reports with exploit scenarios
- Exclusion summary (what was filtered and why)
- Prioritized action items

## Usage

```
/security-review
```

## Confidence Rules

- >80% confidence required to report a finding
- Every finding MUST have a concrete exploit scenario
- Better to miss theoretical issues than flood with false positives

## Important

- Do NOT auto-fix findings unless explicitly asked.
- Do NOT dismiss findings without developer approval.
- Flag any critical findings immediately with exploit scenario.
- DO NOT report: DOS, rate limiting, memory management, open redirects, regex injection.
