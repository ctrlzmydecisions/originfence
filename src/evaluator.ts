import path from "node:path";

import { discoverRepoConfig } from "./config";
import { CompositeMetadataFetcher } from "./fetchers";
import { loadMaliciousPackageFeed } from "./malicious-intel";
import { findMatchingWaivers, loadWaivers } from "./waivers";
import { loadPolicy } from "./policy";
import { matchesAnyPattern } from "./patterns";
import { getReasonDefinition } from "./reason-codes";
import { resolveRepoDiff } from "./resolvers";
import { assertValidDecisionReport } from "./schema";
import { renderGitHubJobSummary, renderReportSummary } from "./summary";
import type {
  Decision,
  DecisionReport,
  DiagnosticEntry,
  EvaluateCommandResult,
  EvaluationInput,
  EvidenceRecord,
  EvaluationMeta,
  MaliciousPackageFeed,
  MetadataFetcher,
  Policy,
  Reason,
  RepoIssue,
  ResolvedDependency,
  Subject,
  SubjectResult,
  Waiver
} from "./types";
import { fileExists, stripUndefinedFields } from "./utils";
import { TOOL_VERSION } from "./tool-version";
import { formatSubjectDisplay } from "./display";

const DECISION_ORDER: Decision[] = ["allow", "warn", "review", "block"];

class EvidenceBuilder {
  private readonly records: EvidenceRecord[] = [];
  private nextIndex = 1;

  public add(record: Omit<EvidenceRecord, "id">): string {
    const id = `ev${this.nextIndex++}`;
    this.records.push({ id, ...record });
    return id;
  }

  public list(): EvidenceRecord[] {
    return this.records;
  }
}

function compareDecisions(left: Decision, right: Decision): number {
  return DECISION_ORDER.indexOf(left) - DECISION_ORDER.indexOf(right);
}

function maxDecision(decisions: Decision[]): Decision {
  return decisions.reduce((current, candidate) => (compareDecisions(current, candidate) >= 0 ? current : candidate), "allow" as Decision);
}

function downgradeDecision(decision: Decision, effect: Waiver["effect"]): Decision {
  if (effect === "downgrade_to_allow") {
    return "allow";
  }

  if (decision === "block" || decision === "review") {
    return "warn";
  }

  return decision;
}

function summarizeReportDecision(decision: DecisionReport["decision"], counts: DecisionReport["counts"]): string {
  if (decision === "neutral") {
    return "No supported dependency changes were detected.";
  }

  return `${counts.changed_subjects} changed subject(s): ${counts.block} blocked, ${counts.review} review, ${counts.warn} warn, ${counts.allow} allow.`;
}

function workflowStatusForDecision(
  decision: DecisionReport["decision"],
  counts: DecisionReport["counts"],
  enforcementMode: EvaluationInput["enforcementMode"]
): DecisionReport["status"] {
  if (decision === "neutral" || counts.changed_subjects === 0) {
    return "neutral";
  }

  if (enforcementMode === "observe") {
    return "success";
  }

  return counts.block > 0 || counts.review > 0 ? "failure" : "success";
}

function buildReasonMessage(code: string, subject: Subject, issueSummary?: string): string {
  switch (code) {
    case "KNOWN_MALICIOUS":
      return `${formatSubjectDisplay(subject)} matched a known malicious package entry.`;
    case "REGISTRY_QUARANTINED":
      return `${formatSubjectDisplay(subject)} is marked as quarantined or unsafe upstream.`;
    case "SOURCE_DENIED":
      return `${formatSubjectDisplay(subject)} resolves from a source outside the approved registry set.`;
    case "INVALID_PROVENANCE":
      return `${formatSubjectDisplay(subject)} has invalid or mismatched provenance.`;
    case "MANIFEST_LOCKFILE_OUT_OF_SYNC":
      return issueSummary ?? "The manifest changed without a matching lockfile update.";
    case "DIRECT_URL_SOURCE":
      return `${formatSubjectDisplay(subject)} is introduced from a direct URL instead of an approved registry.`;
    case "VCS_SOURCE":
      return `${formatSubjectDisplay(subject)} is introduced from a VCS source instead of an approved registry.`;
    case "MISSING_PROVENANCE":
      return `${formatSubjectDisplay(subject)} is missing required provenance for the active policy.`;
    case "PUBLISHER_IDENTITY_DRIFT":
      return `${formatSubjectDisplay(subject)} was published by a different identity than recent trusted history.`;
    case "MAINTAINER_SET_CHANGE":
      return `${formatSubjectDisplay(subject)} has a recent maintainer or owner set change.`;
    case "RECENT_PACKAGE_AGE":
      return `${formatSubjectDisplay(subject)} is newer than the configured recent-package threshold.`;
    case "SOFT_SIGNAL_SOURCE_UNAVAILABLE":
      return `A soft-signal source was unavailable while evaluating ${formatSubjectDisplay(subject)}.`;
    case "HARD_SIGNAL_SOURCE_UNAVAILABLE":
      return `A required hard-signal source was unavailable while evaluating ${formatSubjectDisplay(subject)}.`;
    case "UNSUPPORTED_PROJECT_FORMAT":
      return issueSummary ?? "The repository uses a dependency format that OriginFence does not support in v1.";
    default:
      return `${formatSubjectDisplay(subject)} triggered ${code}.`;
  }
}

function buildEvaluationMeta(
  evaluatedAt: string,
  evidence: EvidenceRecord[],
  availability: { hard_signal_source_available?: boolean; soft_signal_source_available?: boolean; fresh_cache_for_hard_signal?: boolean } | undefined
): EvaluationMeta {
  const staleEvidenceRefs = evidence.filter((record) => record.stale).map((record) => record.id);

  let hardSignalState: EvaluationMeta["hard_signal_state"] = "not_checked";
  let softSignalState: EvaluationMeta["soft_signal_state"] = "not_checked";

  if (availability?.hard_signal_source_available === false) {
    hardSignalState = availability.fresh_cache_for_hard_signal ? "stale" : "missing";
  } else if (staleEvidenceRefs.length > 0) {
    hardSignalState = "stale";
  } else if (evidence.length > 0) {
    hardSignalState = "fresh";
  }

  if (availability?.soft_signal_source_available === false) {
    softSignalState = "missing";
  } else if (staleEvidenceRefs.length > 0) {
    softSignalState = "stale";
  } else if (evidence.length > 0) {
    softSignalState = "fresh";
  }

  return {
    evaluated_at: evaluatedAt,
    tool_version: TOOL_VERSION,
    hard_signal_state: hardSignalState,
    soft_signal_state: softSignalState,
    stale_evidence_refs: staleEvidenceRefs
  };
}

function isHardBlockedRegistryStatus(status: string | undefined): boolean {
  const normalized = status?.trim().toLowerCase();

  if (!normalized) {
    return false;
  }

  return normalized === "quarantined";
}

function isRecentPackage(publishedAt: string | undefined, now: string, thresholdDays: number): boolean {
  if (!publishedAt) {
    return false;
  }

  const ageMs = Date.parse(now) - Date.parse(publishedAt);
  return ageMs >= 0 && ageMs <= thresholdDays * 24 * 60 * 60 * 1000;
}

function isSourceAllowed(subject: ResolvedDependency, policy: Policy): boolean {
  if (subject.source_type !== "registry") {
    return false;
  }

  const allowed = policy.sources?.allow ?? [];

  if (allowed.length === 0) {
    return true;
  }

  return allowed.includes(subject.registry_host ?? "");
}

function provenanceRequirement(subject: ResolvedDependency, policy: Policy): "review" | "block" | null {
  const rule = policy.provenance?.[subject.ecosystem];

  if (!rule || !matchesAnyPattern(subject.name, rule.require_for)) {
    return null;
  }

  return rule.missing_action ?? "review";
}

function summarizeSubjectResult(
  subject: Subject,
  effectiveDecision: Decision,
  reasons: Reason[],
  waiversApplied: Waiver[]
): string {
  const topReason = reasons[0];

  if (!topReason) {
    return `${formatSubjectDisplay(subject)} is allowed.`;
  }

  const firstWaiver = waiversApplied[0];

  if (firstWaiver && effectiveDecision !== topReason.decision) {
    return `${formatSubjectDisplay(subject)} is ${effectiveDecision} because waiver ${firstWaiver.id} applies.`;
  }

  return `${formatSubjectDisplay(subject)} is ${effectiveDecision} because ${topReason.message.charAt(0).toLowerCase()}${topReason.message.slice(1)}`;
}

function buildIssueSubject(issue: RepoIssue): Subject {
  return {
    ecosystem: issue.ecosystem,
    name: issue.name,
    version: null,
    source_type: issue.source_type,
    manifest_path: issue.manifest_path,
    lockfile_path: issue.lockfile_path,
    top_level: true
  };
}

function buildIssueResult(issue: RepoIssue, evaluatedAt: string): SubjectResult {
  const definition = getReasonDefinition(issue.code);
  const subject = buildIssueSubject(issue);
  const builder = new EvidenceBuilder();
  const evidenceRef = builder.add({
    source: "resolver",
    kind: "policy_rule",
    ref: `${issue.code}:${issue.manifest_path ?? issue.lockfile_path ?? issue.name}`
  });

  const reason: Reason = {
    code: issue.code,
    severity: definition.severity,
    decision: definition.default_decision,
    message: buildReasonMessage(issue.code, subject, issue.summary),
    evidence_refs: [evidenceRef],
    waivable: definition.waivable
  };

  return {
    schema_version: "1",
    subject,
    base_decision: definition.default_decision,
    effective_decision: definition.default_decision,
    waived: false,
    summary: issue.summary,
    reasons: [reason],
    evidence: builder.list(),
    waivers_applied: [],
    next_action: {
      kind: definition.next_action_kind,
      summary: definition.next_action_summary
    },
    evaluation_meta: buildEvaluationMeta(evaluatedAt, builder.list(), undefined)
  };
}

async function buildSubjectResult(
  subject: ResolvedDependency,
  policy: Policy,
  waivers: Waiver[],
  fetcher: MetadataFetcher,
  evaluatedAt: string
): Promise<{ result: SubjectResult; diagnostics: DiagnosticEntry[] }> {
  const provenanceAction = provenanceRequirement(subject, policy);
  const fetchResult = await fetcher.fetch(subject, {
    now: evaluatedAt,
    requireProvenance: provenanceAction !== null
  });
  const evidenceInput = fetchResult.evidence;
  const builder = new EvidenceBuilder();
  const reasons: Reason[] = [];

  const addReason = (code: string, decisionOverride?: Decision): void => {
    const definition = getReasonDefinition(code);
    const message = buildReasonMessage(code, subject);
    reasons.push({
      code,
      severity: definition.severity,
      decision: decisionOverride ?? definition.default_decision,
      message,
      evidence_refs: [],
      waivable: definition.waivable
    });
  };

  if (subject.source_type === "registry" && !isSourceAllowed(subject, policy)) {
    const ref = builder.add({
      source: "policy",
      kind: "policy_rule",
      ref: `allowed_sources:${subject.registry_host ?? "unknown"}`
    });
    addReason("SOURCE_DENIED");
    reasons.at(-1)?.evidence_refs.push(ref);
  }

  if (policy.sources?.deny_direct_urls !== false && subject.source_type === "direct_url") {
    const ref = builder.add({
      source: "resolver",
      kind: "policy_rule",
      ref: subject.source_ref ?? subject.name
    });
    addReason("DIRECT_URL_SOURCE");
    reasons.at(-1)?.evidence_refs.push(ref);
  }

  if (policy.sources?.deny_direct_urls !== false && subject.source_type === "vcs") {
    const ref = builder.add({
      source: "resolver",
      kind: "policy_rule",
      ref: subject.source_ref ?? subject.name
    });
    addReason("VCS_SOURCE");
    reasons.at(-1)?.evidence_refs.push(ref);
  }

  if (subject.source_type === "file" || subject.source_type === "unknown") {
    const ref = builder.add({
      source: "resolver",
      kind: "policy_rule",
      ref: subject.source_ref ?? subject.name
    });
    addReason("SOURCE_DENIED");
    reasons.at(-1)?.evidence_refs.push(ref);
  }

  if (evidenceInput.malicious?.matched) {
    const ref = builder.add({
      source: "malicious_packages_feed",
      kind: "feed_entry",
      ref: evidenceInput.malicious.ref,
      fetched_at: evaluatedAt
    });
    addReason("KNOWN_MALICIOUS", policy.malicious_packages?.action ?? "block");
    reasons.at(-1)?.evidence_refs.push(ref);
  }

  if (evidenceInput.registry) {
    const ref = builder.add({
      source: subject.ecosystem === "npm" ? "npm_registry" : "pypi_json_api",
      kind: "registry_metadata",
      ref: `${subject.name}@${subject.version ?? "unknown"}`,
      fetched_at: evaluatedAt,
      stale: evidenceInput.cache?.registry_stale
    });

    if (isHardBlockedRegistryStatus(evidenceInput.registry.status)) {
      addReason("REGISTRY_QUARANTINED");
      reasons.at(-1)?.evidence_refs.push(ref);
    }

    if (isRecentPackage(evidenceInput.registry.published_at, evaluatedAt, policy.soft_signals?.recent_package_age_days ?? 14)) {
      addReason("RECENT_PACKAGE_AGE");
      reasons.at(-1)?.evidence_refs.push(ref);
    }
  }

  if (
    evidenceInput.provenance?.present === true &&
    evidenceInput.provenance.checked !== false &&
    evidenceInput.provenance.verified === false
  ) {
    const ref = builder.add({
      source: subject.ecosystem === "npm" ? "npm_provenance" : "pypi_attestations",
      kind: "attestation",
      ref: evidenceInput.provenance.ref,
      fetched_at: evaluatedAt,
      verified: false,
      stale: evidenceInput.cache?.provenance_stale
    });
    addReason("INVALID_PROVENANCE");
    reasons.at(-1)?.evidence_refs.push(ref);
  } else if (provenanceAction && (!evidenceInput.provenance || evidenceInput.provenance.present === false)) {
    const evidenceRefs: string[] = [];

    if (evidenceInput.cache?.provenance_stale && evidenceInput.provenance?.ref) {
      evidenceRefs.push(builder.add({
        source: subject.ecosystem === "npm" ? "npm_provenance" : "pypi_attestations",
        kind: "attestation",
        ref: evidenceInput.provenance.ref,
        fetched_at: evaluatedAt,
        stale: true
      }));
    }

    evidenceRefs.push(builder.add({
      source: "policy",
      kind: "policy_rule",
      ref: `required_provenance:${subject.ecosystem}:${subject.name}`
    }));
    addReason("MISSING_PROVENANCE", provenanceAction);
    reasons.at(-1)?.evidence_refs.push(...evidenceRefs);
  }

  if (evidenceInput.signals?.publisher_identity_drift) {
    const ref = builder.add({
      source: "ptg_snapshot",
      kind: "cache_meta",
      ref: evidenceInput.registry?.publisher_identity ?? subject.name,
      fetched_at: evaluatedAt
    });
    addReason("PUBLISHER_IDENTITY_DRIFT", policy.soft_signals?.publisher_identity_drift ?? "review");
    reasons.at(-1)?.evidence_refs.push(ref);
  }

  if (evidenceInput.signals?.maintainer_set_change) {
    const ref = builder.add({
      source: "ptg_snapshot",
      kind: "cache_meta",
      ref: `maintainers:${subject.name}`,
      fetched_at: evaluatedAt
    });
    addReason("MAINTAINER_SET_CHANGE", policy.soft_signals?.maintainer_set_change ?? "warn");
    reasons.at(-1)?.evidence_refs.push(ref);
  }

  if (evidenceInput.availability?.soft_signal_source_available === false) {
    const ref = builder.add({
      source: "soft_signal_source",
      kind: "cache_meta",
      ref: subject.name
    });
    addReason("SOFT_SIGNAL_SOURCE_UNAVAILABLE");
    reasons.at(-1)?.evidence_refs.push(ref);
  }

  if (evidenceInput.availability?.hard_signal_source_available === false && !evidenceInput.availability.fresh_cache_for_hard_signal) {
    const ref = builder.add({
      source: "hard_signal_source",
      kind: "cache_meta",
      ref: subject.name
    });
    addReason("HARD_SIGNAL_SOURCE_UNAVAILABLE");
    reasons.at(-1)?.evidence_refs.push(ref);
  }

  reasons.sort((left, right) => {
    const decisionDelta = compareDecisions(right.decision, left.decision);
    if (decisionDelta !== 0) {
      return decisionDelta;
    }

    return left.code.localeCompare(right.code);
  });

  const baseDecision = maxDecision(reasons.map((reason) => reason.decision));
  const appliedWaivers: Waiver[] = [];

  const effectiveReasonDecisions = reasons.map((reason) => {
    const matches = reason.waivable ? findMatchingWaivers(waivers, subject, reason.code, evaluatedAt) : [];

    for (const waiver of matches) {
      if (!appliedWaivers.some((existing) => existing.id === waiver.id)) {
        appliedWaivers.push(waiver);
      }
    }

    if (matches.length === 0) {
      return reason.decision;
    }

    return matches.reduce((decision, waiver) => downgradeDecision(decision, waiver.effect), reason.decision);
  });

  const effectiveDecision = reasons.length === 0 ? "allow" : maxDecision(effectiveReasonDecisions);
  const topReason = reasons[0];
  const topReasonDefinition = topReason ? getReasonDefinition(topReason.code) : null;
  const firstAppliedWaiver = appliedWaivers[0];
  const waived = appliedWaivers.length > 0 && effectiveDecision !== baseDecision;

  const result: SubjectResult = {
    schema_version: "1",
    subject: {
      ecosystem: subject.ecosystem,
      name: subject.name,
      version: subject.version,
      source_type: subject.source_type,
      manifest_path: subject.manifest_path,
      lockfile_path: subject.lockfile_path,
      top_level: subject.top_level
    },
    base_decision: baseDecision,
    effective_decision: effectiveDecision,
    waived,
    waived_from: waived ? baseDecision : undefined,
    summary: summarizeSubjectResult(subject, effectiveDecision, reasons, appliedWaivers),
    reasons,
    evidence: builder.list(),
    waivers_applied: appliedWaivers,
    next_action:
      firstAppliedWaiver
        ? {
            kind: "track_waiver",
            summary: `Track waiver ${firstAppliedWaiver.id} until expiry or remove the dependency.`
          }
        : topReasonDefinition
          ? {
              kind: topReasonDefinition.next_action_kind,
              summary: topReasonDefinition.next_action_summary
            }
          : {
              kind: "none",
              summary: "No action required."
            },
    evaluation_meta: buildEvaluationMeta(evaluatedAt, builder.list(), evidenceInput.availability)
  };

  return {
    result,
    diagnostics: fetchResult.diagnostics
  };
}

function buildReport(
  results: SubjectResult[],
  basePath: string,
  headPath: string,
  now: string,
  policyMeta: Awaited<ReturnType<typeof loadPolicy>>,
  unsupportedFiles: string[],
  diagnostics: DiagnosticEntry[],
  enforcementMode: EvaluationInput["enforcementMode"]
): DecisionReport {
  const counts = {
    changed_subjects: results.length,
    allow: results.filter((result) => result.effective_decision === "allow").length,
    warn: results.filter((result) => result.effective_decision === "warn").length,
    review: results.filter((result) => result.effective_decision === "review").length,
    block: results.filter((result) => result.effective_decision === "block").length
  };

  const decision: DecisionReport["decision"] =
    results.length === 0 ? "neutral" : maxDecision(results.map((result) => result.effective_decision));

  const status = workflowStatusForDecision(decision, counts, enforcementMode);

  const report: DecisionReport = {
    schema_version: "1",
    generated_at: now,
    tool_version: TOOL_VERSION,
    ...(enforcementMode === "observe" ? { enforcement_mode: "observe" as const } : {}),
    status,
    decision,
    summary: summarizeReportDecision(decision, counts),
    counts,
    paths: {
      base: path.resolve(basePath),
      head: path.resolve(headPath)
    },
    policy: {
      source: policyMeta.source,
      checksum: policyMeta.checksum,
      ...(policyMeta.policy.waivers?.file ? { waivers_file: policyMeta.policy.waivers.file } : {})
    },
    unsupported_files: unsupportedFiles,
    ...(diagnostics.length > 0 ? { diagnostics } : {}),
    results
  };

  return assertValidDecisionReport(stripUndefinedFields(report));
}

export async function evaluate(input: EvaluationInput): Promise<EvaluateCommandResult> {
  const resolvedConfig = await discoverRepoConfig(input);
  const [policyMeta, maliciousFeed, repoDiff] = await Promise.all([
    loadPolicy(resolvedConfig.policyPath, resolvedConfig.baselinePolicyPath),
    loadMaliciousPackageFeed({
      cacheDir: resolvedConfig.cacheDir,
      refreshCache: Boolean(input.refreshCache),
      localOverrideFilePath: resolvedConfig.maliciousPackagesFilePath
    }),
    resolveRepoDiff(input.basePath, input.headPath)
  ]);

  let resolvedWaiverPath = resolvedConfig.waiverPath;

  if (!resolvedWaiverPath && input.discoverRepoConfig !== false) {
    const policyDefinedWaiverPath = policyMeta.policy.waivers?.file
      ? path.resolve(input.headPath, policyMeta.policy.waivers.file)
      : undefined;

    if (policyDefinedWaiverPath && await fileExists(policyDefinedWaiverPath)) {
      resolvedWaiverPath = policyDefinedWaiverPath;
    }
  }

  const waiversFile = await loadWaivers(resolvedWaiverPath);

  const fetcher =
    input.metadataFetcher ??
    new CompositeMetadataFetcher(maliciousFeed as MaliciousPackageFeed, {
      cacheDir: resolvedConfig.cacheDir,
      refreshCache: input.refreshCache === true
    });
  const issueResults = repoDiff.issues.map((issue) => buildIssueResult(issue, input.now));
  const subjectEvaluations = await Promise.all(
    repoDiff.subjects.map((subject) => buildSubjectResult(subject, policyMeta.policy, waiversFile.waivers, fetcher, input.now))
  );
  const subjectResults = subjectEvaluations.map((evaluation) => evaluation.result);
  const diagnostics = subjectEvaluations.flatMap((evaluation) => evaluation.diagnostics);

  const results = [...issueResults, ...subjectResults];
  const report = buildReport(
    results,
    input.basePath,
    input.headPath,
    input.now,
    policyMeta,
    repoDiff.unsupported_files,
    diagnostics,
    input.enforcementMode
  );

  return {
    report,
    summaryText: renderReportSummary(report),
    githubJobSummaryText: renderGitHubJobSummary(report),
    resolvedConfig: {
      policyPath: resolvedConfig.policyPath,
      baselinePolicyPath: resolvedConfig.baselinePolicyPath,
      waiverPath: resolvedWaiverPath,
      cacheDir: resolvedConfig.cacheDir
    }
  };
}
