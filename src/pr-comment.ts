import type { DecisionReport, SubjectResult } from "./types";
import { formatSubjectDisplay, sortSubjectResults } from "./display";
import { describeFalsePositiveGuidance, describePrimaryEvidenceLine } from "./result-explainer";

export type PullRequestCommentMode = "off" | "review_and_block" | "warn_review_block" | "always";

export interface PullRequestCommentContext {
  mode: PullRequestCommentMode;
  runUrl?: string;
}

export interface StickyCommentTarget {
  apiUrl: string;
  owner: string;
  repo: string;
  issueNumber: number;
  token: string;
}

export interface StickyCommentResult {
  action: "created" | "updated" | "skipped";
  commentId?: number;
}

const STICKY_MARKER = "<!-- originfence:sticky-comment -->";

function shouldRenderComment(report: DecisionReport, mode: PullRequestCommentMode): boolean {
  if (mode === "off") {
    return false;
  }

  if (mode === "always") {
    return true;
  }

  if (report.status === "failure" && report.results.length === 0) {
    return true;
  }

  if (mode === "warn_review_block") {
    return report.counts.warn > 0 || report.counts.review > 0 || report.counts.block > 0;
  }

  return report.counts.review > 0 || report.counts.block > 0;
}

function renderResultLines(result: SubjectResult): string[] {
  const topReason = result.reasons[0];
  const waiverText = result.waived && result.waivers_applied[0] ? ` Waived by ${result.waivers_applied[0].id}.` : "";
  const lines = [`- \`${formatSubjectDisplay(result.subject)}\`${topReason ? ` (\`${topReason.code}\`)` : ""}: ${result.next_action.summary}${waiverText}`];
  const evidenceLine = describePrimaryEvidenceLine(result);

  if (evidenceLine) {
    lines.push(`  Evidence: ${evidenceLine}`);
  }

  return lines;
}

export function renderPullRequestComment(report: DecisionReport, context: PullRequestCommentContext): string | null {
  if (!shouldRenderComment(report, context.mode)) {
    return null;
  }

  const results = sortSubjectResults(report.results).filter((result) => result.effective_decision !== "allow").slice(0, 5);
  const lines: string[] = [
    STICKY_MARKER,
    "## OriginFence",
    ""
  ];

  if (report.enforcement_mode === "observe") {
    lines.push(`Status: \`${report.status}\``);
    lines.push(`Decision: \`${report.decision}\``);
    lines.push("Enforcement mode: `observe`");
  } else {
    lines.push(`Decision: \`${report.status}\``);
  }

  lines.push("");
  lines.push(`${report.counts.block} blocked, ${report.counts.review} review, ${report.counts.warn} warn across ${report.counts.changed_subjects} changed subject(s).`);

  if (results.length > 0) {
    lines.push("");
    lines.push("Top outcomes:");
    for (const result of results) {
      lines.push(...renderResultLines(result));
    }
    lines.push("");
    lines.push(describeFalsePositiveGuidance(results));
  } else if (report.status === "failure") {
    lines.push("");
    lines.push("Evaluation failure:");
    lines.push(`- ${report.summary}`);
  }

  if (context.runUrl) {
    lines.push("");
    lines.push(`[Open workflow run](${context.runUrl})`);
  }

  return lines.join("\n");
}

export function renderResolvedPullRequestComment(report: DecisionReport, context: PullRequestCommentContext): string {
  const lines: string[] = [
    STICKY_MARKER,
    "## OriginFence",
    ""
  ];

  if (report.enforcement_mode === "observe") {
    lines.push(`Status: \`${report.status}\``);
    lines.push(`Decision: \`${report.decision}\``);
    lines.push("Enforcement mode: `observe`");
  } else {
    lines.push(`Decision: \`${report.status}\``);
  }

  lines.push("");
  lines.push("No review-required or blocked dependency trust outcomes remain in this PR.");

  if (report.counts.warn > 0) {
    lines.push("", `${report.counts.warn} warning-only dependency trust outcome(s) remain.`);
  }

  if (context.runUrl) {
    lines.push("", `[Open workflow run](${context.runUrl})`);
  }

  return lines.join("\n");
}

interface GitHubIssueComment {
  id: number;
  body?: string;
}

async function githubRequest(target: StickyCommentTarget, pathName: string, init?: RequestInit): Promise<Response> {
  return fetch(`${target.apiUrl.replace(/\/$/, "")}${pathName}`, {
    ...init,
    headers: {
      authorization: `Bearer ${target.token}`,
      accept: "application/vnd.github+json",
      "content-type": "application/json",
      "user-agent": "originfence",
      ...(init?.headers ?? {})
    }
  });
}

async function listExistingComments(target: StickyCommentTarget): Promise<GitHubIssueComment[]> {
  const response = await githubRequest(target, `/repos/${target.owner}/${target.repo}/issues/${target.issueNumber}/comments?per_page=100`);

  if (!response.ok) {
    throw new Error(`GitHub comment lookup failed: ${response.status}`);
  }

  return (await response.json()) as GitHubIssueComment[];
}

export async function syncStickyPullRequestComment(
  target: StickyCommentTarget,
  body: string,
  options?: { allowCreate?: boolean }
): Promise<StickyCommentResult> {
  const existing = (await listExistingComments(target)).find((comment) => comment.body?.includes(STICKY_MARKER));

  if (existing) {
    const response = await githubRequest(target, `/repos/${target.owner}/${target.repo}/issues/comments/${existing.id}`, {
      method: "PATCH",
      body: JSON.stringify({ body })
    });

    if (!response.ok) {
      throw new Error(`GitHub comment update failed: ${response.status}`);
    }

    return {
      action: "updated",
      commentId: existing.id
    };
  }

  if (options?.allowCreate === false) {
    return {
      action: "skipped"
    };
  }

  const response = await githubRequest(target, `/repos/${target.owner}/${target.repo}/issues/${target.issueNumber}/comments`, {
    method: "POST",
    body: JSON.stringify({ body })
  });

  if (!response.ok) {
    throw new Error(`GitHub comment create failed: ${response.status}`);
  }

  const created = (await response.json()) as GitHubIssueComment;
  return {
    action: "created",
    commentId: created.id
  };
}
