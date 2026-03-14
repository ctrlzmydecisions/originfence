import type { DecisionReport, SubjectResult } from "./types";
import { formatAppliedWaiverDisplay, formatSubjectDisplay, sortSubjectResults } from "./display";
import { describeEvidenceBullets } from "./result-explainer";

function pushHeaderLines(lines: string[], report: DecisionReport): void {
  if (report.enforcement_mode === "observe") {
    lines.push(`Status: ${report.status}`);
    lines.push(`Decision: ${report.decision}`);
    lines.push("Enforcement mode: observe");
    return;
  }

  lines.push(`Decision: ${report.status}`);
}

export function renderReportSummary(report: DecisionReport): string {
  const staleSubjects = report.results.filter((result) => result.evaluation_meta.stale_evidence_refs.length > 0).length;
  const degradedSources = (report.diagnostics ?? []).filter((entry) => entry.level !== "info").length;
  const lines: string[] = [];
  pushHeaderLines(lines, report);
  lines.push(`Changed subjects: ${report.counts.changed_subjects}`);
  lines.push(`Blocked: ${report.counts.block}  Review: ${report.counts.review}  Warn: ${report.counts.warn}  Allow: ${report.counts.allow}`);

  if (staleSubjects > 0 || degradedSources > 0) {
    lines.push(`Diagnostics: ${staleSubjects} stale subject(s), ${degradedSources} diagnostic event(s)`);
  }

  if (report.results.length === 0) {
    lines.push("", report.summary);
    for (const diagnostic of (report.diagnostics ?? []).filter((entry) => entry.level === "error")) {
      if (diagnostic.message !== report.summary) {
        lines.push(`- ${diagnostic.message}`);
      }
    }
    return lines.join("\n");
  }

  for (const result of sortSubjectResults(report.results)) {
    const topReason = result.reasons[0];
    lines.push("");
    lines.push(`[${result.effective_decision}] ${formatSubjectDisplay(result.subject)}`);
    lines.push(`  code: ${topReason?.code ?? "none"}`);
    if (result.waived) {
      lines.push(`  waived: ${formatAppliedWaiverDisplay(result) ?? "true"}`);
    }
    lines.push(`  next: ${result.next_action.summary}`);
  }

  return lines.join("\n");
}

function renderDecisionSection(title: string, results: SubjectResult[]): string[] {
  if (results.length === 0) {
    return [];
  }

  const lines = [`### ${title}`];

  for (const result of results) {
    const topReason = result.reasons[0];
    const waiverText = result.waived ? ` Waived via ${formatAppliedWaiverDisplay(result)}.` : "";
    lines.push(`- \`${formatSubjectDisplay(result.subject)}\`${topReason ? ` (\`${topReason.code}\`)` : ""}`);
    if (topReason) {
      lines.push(`  ${topReason.message}${waiverText}`);
    } else if (waiverText) {
      lines.push(`  ${waiverText.trim()}`);
    }
    for (const evidenceLine of describeEvidenceBullets(result, 3)) {
      lines.push(`  Evidence: ${evidenceLine}`);
    }
    lines.push(`  Next: ${result.next_action.summary}`);
  }

  return lines;
}

export function renderGitHubJobSummary(report: DecisionReport, options?: { jsonArtifactPath?: string }): string {
  const staleSubjects = report.results.filter((result) => result.evaluation_meta.stale_evidence_refs.length > 0).length;
  const degradedSources = (report.diagnostics ?? []).filter((entry) => entry.level !== "info").length;
  const lines: string[] = ["## OriginFence", ""];

  if (report.enforcement_mode === "observe") {
    lines.push(`Status: \`${report.status}\``);
    lines.push(`Decision: \`${report.decision}\``);
    lines.push("- Enforcement mode: observe");
  } else {
    lines.push(`Decision: \`${report.status}\``);
  }

  lines.push("");
  lines.push(`- Changed subjects: ${report.counts.changed_subjects}`);
  lines.push(`- Blocked: ${report.counts.block}`);
  lines.push(`- Review: ${report.counts.review}`);
  lines.push(`- Warn: ${report.counts.warn}`);
  lines.push(`- Allow: ${report.counts.allow}`);

  if (staleSubjects > 0 || degradedSources > 0) {
    lines.push(`- Diagnostics: ${staleSubjects} stale subject(s), ${degradedSources} diagnostic event(s)`);
  }

  if (options?.jsonArtifactPath) {
    lines.push(`- JSON artifact: \`${options.jsonArtifactPath}\``);
  }

  if (report.results.length === 0) {
    lines.push("", report.summary);
    for (const diagnostic of (report.diagnostics ?? []).filter((entry) => entry.level === "error")) {
      if (diagnostic.message !== report.summary) {
        lines.push(`- ${diagnostic.message}`);
      }
    }
    return lines.join("\n");
  }

  const sorted = sortSubjectResults(report.results);
  lines.push("");
  lines.push(...renderDecisionSection("Blocked", sorted.filter((result) => result.effective_decision === "block")));
  lines.push(...renderDecisionSection("Review Required", sorted.filter((result) => result.effective_decision === "review")));
  lines.push(...renderDecisionSection("Warnings", sorted.filter((result) => result.effective_decision === "warn")));

  return lines.join("\n");
}
