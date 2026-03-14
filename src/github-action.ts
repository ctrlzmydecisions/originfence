#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

import type { DecisionReport, EnforcementMode } from "./types";
import { parseEnforcementMode } from "./enforcement-mode";
import { evaluate } from "./evaluator";
import { writeEvaluationResultArtifacts, writeReportArtifacts } from "./evaluation-output";
import { buildFailureReport } from "./failure-report";
import {
  renderPullRequestComment,
  renderResolvedPullRequestComment,
  syncStickyPullRequestComment,
  type PullRequestCommentMode,
  type StickyCommentTarget
} from "./pr-comment";
import { readFileIfExists } from "./utils";

interface ActionConfig {
  workspace: string;
  baseRev: string;
  policyPath?: string;
  baselinePolicyPath?: string;
  waiversPath?: string;
  maliciousPackagesFilePath?: string;
  jsonOut: string;
  summaryOut: string;
  writeJobSummary: boolean;
  cacheDir?: string;
  refreshCache: boolean;
  enforcementMode: EnforcementMode;
  prComment: boolean;
  commentMode: PullRequestCommentMode;
  githubToken?: string;
}

function getInput(name: string): string | undefined {
  const envName = `INPUT_${name.replaceAll("-", "_").toUpperCase()}`;
  const value = process.env[envName];
  return value && value.length > 0 ? value : undefined;
}

function resolvePath(workspace: string, value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  return path.isAbsolute(value) ? value : path.join(workspace, value);
}

function outputPathValue(workspace: string, filePath: string): string {
  const relativePath = path.relative(workspace, filePath);

  if (relativePath.length === 0) {
    return ".";
  }

  if (relativePath === ".." || relativePath.startsWith(`..${path.sep}`)) {
    return filePath;
  }

  return relativePath.split(path.sep).join("/");
}

function isTruthy(value: string | undefined, fallback = false): boolean {
  if (!value) {
    return fallback;
  }

  return value === "true" || value === "1" || value === "yes";
}

function execGit(args: string[], cwd: string): string {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8"
  });

  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `git ${args.join(" ")} failed`);
  }

  return result.stdout.trim();
}

async function deriveBaseRev(workspace: string): Promise<string> {
  const explicitBaseRev = getInput("base-rev");

  if (explicitBaseRev) {
    return explicitBaseRev;
  }

  const payload = await readEventPayload();
  const pullRequestBaseSha = payload?.pull_request && typeof payload.pull_request === "object"
    ? (payload.pull_request as { base?: { sha?: unknown } }).base?.sha
    : undefined;

  if (typeof pullRequestBaseSha === "string" && pullRequestBaseSha.length > 0) {
    return pullRequestBaseSha;
  }

  const mergeGroupBaseSha = payload?.merge_group && typeof payload.merge_group === "object"
    ? (payload.merge_group as { base_sha?: unknown }).base_sha
    : undefined;

  if (typeof mergeGroupBaseSha === "string" && mergeGroupBaseSha.length > 0) {
    return mergeGroupBaseSha;
  }

  try {
    return execGit(["rev-parse", "HEAD^1"], workspace);
  } catch {
    throw new Error(
      "Unable to derive the base revision. For pull_request and merge_group events OriginFence reads the base SHA from the event payload; otherwise use actions/checkout with fetch-depth: 2 on a merge commit, or pass the base-rev input explicitly."
    );
  }
}

async function extractRevision(workspace: string, revision: string): Promise<string> {
  const tempRoot = path.join(workspace, ".originfence", "action-tmp");
  await fs.mkdir(tempRoot, { recursive: true });
  const tempDir = await fs.mkdtemp(path.join(tempRoot, "originfence-base-"));
  const archive = spawnSync("git", ["archive", "--format=tar", revision], {
    cwd: workspace,
    encoding: null,
    maxBuffer: 50 * 1024 * 1024
  });

  if (archive.status !== 0 || !archive.stdout) {
    throw new Error((archive.stderr?.toString("utf8") ?? "").trim() || `git archive ${revision} failed`);
  }

  const untar = spawnSync("tar", ["-x", "-C", tempDir], {
    input: archive.stdout,
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024
  });

  if (untar.status !== 0) {
    throw new Error((untar.stderr ?? "").trim() || `tar extraction for ${revision} failed`);
  }

  return tempDir;
}

async function writeOutput(name: string, value: string): Promise<void> {
  const outputPath = process.env.GITHUB_OUTPUT;

  if (!outputPath) {
    return;
  }

  await fs.appendFile(outputPath, `${name}<<PTG_EOF\n${value}\nPTG_EOF\n`, "utf8");
}

async function readEventPayload(): Promise<Record<string, unknown> | null> {
  const eventPath = process.env.GITHUB_EVENT_PATH;

  if (!eventPath) {
    return null;
  }

  const content = await readFileIfExists(eventPath);
  return content ? (JSON.parse(content) as Record<string, unknown>) : null;
}

function buildRunUrl(): string | undefined {
  const serverUrl = process.env.GITHUB_SERVER_URL;
  const repository = process.env.GITHUB_REPOSITORY;
  const runId = process.env.GITHUB_RUN_ID;

  if (!serverUrl || !repository || !runId) {
    return undefined;
  }

  return `${serverUrl}/${repository}/actions/runs/${runId}`;
}

async function resolvePullRequestTarget(token: string | undefined): Promise<StickyCommentTarget | null> {
  if (!token) {
    return null;
  }

  const payload = await readEventPayload();
  const pullRequest = payload?.pull_request as { number?: number } | undefined;
  const repository = payload?.repository as { full_name?: string } | undefined;

  if (!pullRequest?.number) {
    return null;
  }

  const fullName = repository?.full_name ?? process.env.GITHUB_REPOSITORY;

  if (!fullName || !fullName.includes("/")) {
    return null;
  }

  const [owner, repo] = fullName.split("/", 2);

  if (!owner || !repo) {
    return null;
  }

  return {
    apiUrl: process.env.GITHUB_API_URL ?? "https://api.github.com",
    owner,
    repo,
    issueNumber: pullRequest.number,
    token
  };
}

async function buildConfig(): Promise<ActionConfig> {
  const workspace = process.env.GITHUB_WORKSPACE ? path.resolve(process.env.GITHUB_WORKSPACE) : process.cwd();
  const baseRev = await deriveBaseRev(workspace);

  return {
    workspace,
    baseRev,
    policyPath: resolvePath(workspace, getInput("policy-path")),
    baselinePolicyPath: resolvePath(workspace, getInput("baseline-policy-path")),
    waiversPath: resolvePath(workspace, getInput("waivers-path")),
    maliciousPackagesFilePath: resolvePath(workspace, getInput("malicious-packages-file")),
    jsonOut: resolvePath(workspace, getInput("json-out")) ?? path.join(workspace, ".originfence", "out", "report.json"),
    summaryOut: resolvePath(workspace, getInput("summary-out")) ?? path.join(workspace, ".originfence", "out", "summary.txt"),
    writeJobSummary: getInput("write-job-summary") !== "false",
    cacheDir: resolvePath(workspace, getInput("cache-dir")),
    refreshCache: isTruthy(getInput("refresh"), false),
    enforcementMode: parseEnforcementMode(getInput("enforcement-mode")),
    prComment: isTruthy(getInput("pr-comment"), false),
    commentMode: (getInput("comment-mode") as PullRequestCommentMode | undefined) ?? "review_and_block",
    githubToken: getInput("github-token") ?? process.env.GITHUB_TOKEN
  };
}

function buildPolicySource(config: ActionConfig): string {
  const sources = ["builtin:default"];

  if (config.baselinePolicyPath) {
    sources.push(config.baselinePolicyPath);
  }

  if (config.policyPath) {
    sources.push(config.policyPath);
  } else {
    sources.push(path.join(config.workspace, ".originfence", "policy.yaml"));
  }

  return sources.join(",");
}

async function syncCommentOutputs(report: DecisionReport, config: ActionConfig): Promise<void> {
  if (!config.prComment) {
    return;
  }

  try {
    const target = await resolvePullRequestTarget(config.githubToken);

    if (!target) {
      await writeOutput("comment-state", "skipped");
      return;
    }

    const runUrl = buildRunUrl();
    const commentBody = renderPullRequestComment(report, {
      mode: config.commentMode,
      runUrl
    });
    const syncResult = commentBody
      ? await syncStickyPullRequestComment(target, commentBody, { allowCreate: true })
      : await syncStickyPullRequestComment(
          target,
          renderResolvedPullRequestComment(report, {
            mode: config.commentMode,
            runUrl
          }),
          { allowCreate: false }
        );

    await writeOutput("comment-state", syncResult.action);
    if (typeof syncResult.commentId === "number") {
      await writeOutput("comment-id", String(syncResult.commentId));
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`OriginFence PR comment sync failed: ${message}\n`);
    await writeOutput("comment-state", "error");
  }
}

async function main(): Promise<number> {
  const config = await buildConfig();
  const basePath = await extractRevision(config.workspace, config.baseRev);

  try {
    try {
      const result = await evaluate({
        basePath,
        headPath: config.workspace,
        policyPath: config.policyPath,
        baselinePolicyPath: config.baselinePolicyPath,
        waiverPath: config.waiversPath,
        maliciousPackagesFilePath: config.maliciousPackagesFilePath,
        now: new Date().toISOString(),
        cacheDir: config.cacheDir,
        refreshCache: config.refreshCache,
        enforcementMode: config.enforcementMode
      });

      await writeEvaluationResultArtifacts(result, {
        jsonOut: config.jsonOut,
        summaryOut: config.summaryOut,
        githubStepSummaryOut: config.writeJobSummary ? process.env.GITHUB_STEP_SUMMARY : undefined
      });
      process.stdout.write(`${result.summaryText}\n`);

      await writeOutput("status", result.report.status);
      await writeOutput("decision", result.report.decision);
      await writeOutput("report-path", outputPathValue(config.workspace, config.jsonOut));
      await writeOutput("summary-path", outputPathValue(config.workspace, config.summaryOut));
      await writeOutput("changed-subjects", String(result.report.counts.changed_subjects));
      await syncCommentOutputs(result.report, config);

      return result.report.status === "failure" ? 1 : 0;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const report = buildFailureReport({
        basePath,
        headPath: config.workspace,
        summary: message,
        policySource: buildPolicySource(config),
        waiversFile: config.waiversPath ? path.relative(config.workspace, config.waiversPath) : ".originfence/waivers.yaml",
        enforcementMode: config.enforcementMode,
        diagnostics: [
          {
            level: "error",
            source: "config",
            code: "EVALUATION_FAILED",
            message
          }
        ]
      });
      await writeReportArtifacts(report, {
        jsonOut: config.jsonOut,
        summaryOut: config.summaryOut,
        githubStepSummaryOut: config.writeJobSummary ? process.env.GITHUB_STEP_SUMMARY : undefined
      });
      await writeOutput("status", report.status);
      await writeOutput("decision", report.decision);
      await writeOutput("report-path", outputPathValue(config.workspace, config.jsonOut));
      await writeOutput("summary-path", outputPathValue(config.workspace, config.summaryOut));
      await writeOutput("changed-subjects", String(report.counts.changed_subjects));
      await syncCommentOutputs(report, config);

      process.stderr.write(`${message}\n`);
      return 1;
    }
  } finally {
    await fs.rm(basePath, { recursive: true, force: true });
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch(async (error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    await writeOutput("status", "failure");
    await writeOutput("decision", "neutral");
    await writeOutput("changed-subjects", "0");
    process.stderr.write(`${message}\n`);
    process.exitCode = 2;
  });
