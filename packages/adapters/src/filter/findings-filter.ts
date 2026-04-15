import type { Finding } from "@vardionix/schemas";

/**
 * Two-stage false-positive filtering inspired by anthropics/claude-code-security-review.
 *
 * Stage 1: Hard exclusion rules (regex-based, deterministic)
 * Stage 2: Confidence threshold filtering
 */

export interface FilterResult {
  kept: Finding[];
  excluded: Finding[];
  stats: {
    total: number;
    kept: number;
    excluded: number;
    byExclusionReason: Record<string, number>;
  };
}

// ── Stage 1: Hard exclusion rules ─────────────────────────────────────────────
// Categories from anthropics/claude-code-security-review

interface ExclusionRule {
  name: string;
  patterns: RegExp[];
  filePatterns?: RegExp[];
  description: string;
}

const HARD_EXCLUSION_RULES: ExclusionRule[] = [
  {
    name: "dos-resource-exhaustion",
    patterns: [
      /denial.of.service/i,
      /unbounded.loop/i,
      /infinite.recursion/i,
      /resource.exhaustion/i,
      /memory.exhaustion/i,
      /stack.overflow/i,
    ],
    description: "DOS/resource exhaustion (better handled by infrastructure controls)",
  },
  {
    name: "rate-limiting",
    patterns: [
      /missing.rate.limit/i,
      /rate.limiting.required/i,
      /no.rate.limit/i,
      /brute.force.without.rate/i,
    ],
    description: "Rate limiting recommendations (infrastructure concern)",
  },
  {
    name: "resource-management",
    patterns: [
      /memory.leak/i,
      /unclosed.resource/i,
      /database.connection.leak/i,
      /thread.leak/i,
      /socket.leak/i,
      /file.handle.leak/i,
    ],
    description: "Resource management issues (not security vulnerabilities)",
  },
  {
    name: "open-redirect",
    patterns: [
      /open.redirect/i,
      /unvalidated.redirect/i,
      /malicious.redirect/i,
    ],
    description: "Open redirect findings (low severity, high false-positive rate)",
  },
  {
    name: "regex-injection",
    patterns: [/regex.injection/i, /regular.expression.injection/i],
    description: "Generic regex injection findings",
  },
  {
    name: "memory-safety-non-c",
    patterns: [/buffer.overflow/i, /use.after.free/i, /double.free/i],
    filePatterns: [/\.(py|js|ts|java|go|rb|rs)$/i],
    description: "Memory safety in managed languages (not applicable)",
  },
  {
    name: "ssrf-html",
    patterns: [/server.side.request.forgery/i, /ssrf/i],
    filePatterns: [/\.html?$/i],
    description: "SSRF in HTML files (not applicable)",
  },
  {
    name: "markdown-findings",
    patterns: [/.*/],
    filePatterns: [/\.md$/i],
    description: "Findings in documentation files",
  },
];

function matchesExclusionRule(
  finding: Finding,
  rule: ExclusionRule,
): boolean {
  const messageMatch = rule.patterns.some(
    (p) => p.test(finding.message) || p.test(finding.title),
  );

  if (!messageMatch) return false;

  // If rule has file patterns, also check the file
  if (rule.filePatterns) {
    return rule.filePatterns.some((p) => p.test(finding.filePath));
  }

  return true;
}

/**
 * Apply hard exclusion rules to findings (Stage 1).
 */
export function applyHardExclusions(findings: Finding[]): FilterResult {
  const kept: Finding[] = [];
  const excluded: Finding[] = [];
  const byExclusionReason: Record<string, number> = {};

  for (const finding of findings) {
    let wasExcluded = false;

    for (const rule of HARD_EXCLUSION_RULES) {
      if (matchesExclusionRule(finding, rule)) {
        excluded.push({
          ...finding,
          excluded: true,
          exclusionReason: `[${rule.name}] ${rule.description}`,
        });
        byExclusionReason[rule.name] =
          (byExclusionReason[rule.name] ?? 0) + 1;
        wasExcluded = true;
        break;
      }
    }

    if (!wasExcluded) {
      kept.push(finding);
    }
  }

  return {
    kept,
    excluded,
    stats: {
      total: findings.length,
      kept: kept.length,
      excluded: excluded.length,
      byExclusionReason,
    },
  };
}

/**
 * Apply confidence threshold filtering (Stage 2).
 * Only keep findings with confidence >= threshold.
 * Default threshold: 0.8 (80%) per claude-code-security-review methodology.
 */
export function applyConfidenceThreshold(
  findings: Finding[],
  threshold = 0.8,
): FilterResult {
  const kept: Finding[] = [];
  const excluded: Finding[] = [];

  for (const finding of findings) {
    const confidence = finding.confidenceScore ?? 0.7;

    if (confidence >= threshold) {
      kept.push(finding);
    } else {
      excluded.push({
        ...finding,
        excluded: true,
        exclusionReason: `Low confidence: ${(confidence * 100).toFixed(0)}% < ${(threshold * 100).toFixed(0)}% threshold`,
      });
    }
  }

  return {
    kept,
    excluded,
    stats: {
      total: findings.length,
      kept: kept.length,
      excluded: excluded.length,
      byExclusionReason: { "low-confidence": excluded.length },
    },
  };
}

/**
 * Run the full two-stage filtering pipeline.
 */
export function filterFindings(
  findings: Finding[],
  options: {
    confidenceThreshold?: number;
    skipHardExclusions?: boolean;
    skipConfidenceFilter?: boolean;
  } = {},
): FilterResult {
  let current = findings;
  const allExcluded: Finding[] = [];
  const allReasons: Record<string, number> = {};

  // Stage 1: Hard exclusion rules
  if (!options.skipHardExclusions) {
    const stage1 = applyHardExclusions(current);
    current = stage1.kept;
    allExcluded.push(...stage1.excluded);
    Object.assign(allReasons, stage1.stats.byExclusionReason);
  }

  // Stage 2: Confidence threshold
  if (!options.skipConfidenceFilter) {
    const stage2 = applyConfidenceThreshold(
      current,
      options.confidenceThreshold ?? 0.8,
    );
    current = stage2.kept;
    allExcluded.push(...stage2.excluded);
    for (const [k, v] of Object.entries(stage2.stats.byExclusionReason)) {
      allReasons[k] = (allReasons[k] ?? 0) + v;
    }
  }

  return {
    kept: current,
    excluded: allExcluded,
    stats: {
      total: findings.length,
      kept: current.length,
      excluded: allExcluded.length,
      byExclusionReason: allReasons,
    },
  };
}
