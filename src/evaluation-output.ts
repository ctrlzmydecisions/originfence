import type { DecisionReport, EvaluateCommandResult } from "./types";
import { renderGitHubJobSummary, renderReportSummary } from "./summary";
import { writeTextFile } from "./utils";

export interface EvaluationArtifactPaths {
  jsonOut?: string;
  summaryOut?: string;
  githubStepSummaryOut?: string;
}

export async function writeEvaluationResultArtifacts(
  result: Pick<EvaluateCommandResult, "report" | "summaryText" | "githubJobSummaryText">,
  paths: EvaluationArtifactPaths
): Promise<void> {
  if (paths.jsonOut) {
    await writeTextFile(paths.jsonOut, `${JSON.stringify(result.report, null, 2)}\n`);
  }

  if (paths.summaryOut) {
    await writeTextFile(paths.summaryOut, `${result.summaryText}\n`);
  }

  if (paths.githubStepSummaryOut) {
    await writeTextFile(paths.githubStepSummaryOut, `${result.githubJobSummaryText}\n`);
  }
}

export async function writeReportArtifacts(report: DecisionReport, paths: EvaluationArtifactPaths): Promise<void> {
  await writeEvaluationResultArtifacts({
    report,
    summaryText: renderReportSummary(report),
    githubJobSummaryText: renderGitHubJobSummary(report)
  }, paths);
}
