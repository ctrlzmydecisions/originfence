import type { DecisionReport, DiagnosticEntry } from "./types";
import { TOOL_VERSION } from "./tool-version";
import { sha256, stripUndefinedFields } from "./utils";

interface FailureReportInput {
  basePath: string;
  headPath: string;
  summary: string;
  policySource?: string;
  waiversFile?: string;
  diagnostics?: DiagnosticEntry[];
  generatedAt?: string;
  enforcementMode?: "enforce" | "observe";
}

export function buildFailureReport(input: FailureReportInput): DecisionReport {
  const diagnostics = input.diagnostics ?? [
    {
      level: "error",
      source: "originfence",
      code: "EVALUATION_FAILED",
      message: input.summary
    }
  ];

  return stripUndefinedFields({
    schema_version: "1",
    generated_at: input.generatedAt ?? new Date().toISOString(),
    tool_version: TOOL_VERSION,
    ...(input.enforcementMode === "observe" ? { enforcement_mode: "observe" as const } : {}),
    status: "failure",
    decision: "neutral",
    summary: input.summary,
    counts: {
      changed_subjects: 0,
      allow: 0,
      warn: 0,
      review: 0,
      block: 0
    },
    paths: {
      base: input.basePath,
      head: input.headPath
    },
    policy: {
      source: input.policySource ?? "builtin:default",
      checksum: sha256(input.policySource ?? "builtin:default"),
      waivers_file: input.waiversFile
    },
    diagnostics,
    results: []
  });
}
