export type Ecosystem = "npm" | "pypi";
export type Decision = "allow" | "warn" | "review" | "block";
export type ReportDecision = Decision | "neutral";
export type WorkflowStatus = "success" | "failure" | "neutral";
export type EnforcementMode = "enforce" | "observe";
export type SourceType = "registry" | "direct_url" | "vcs" | "file" | "unknown";
export type Severity = "low" | "medium" | "high" | "critical";
export type WaiverEffect = "downgrade_to_warn" | "downgrade_to_allow";
export type SignalState = "fresh" | "stale" | "missing" | "not_checked";
export type DiagnosticLevel = "info" | "warn" | "error";

export interface Subject {
  ecosystem: Ecosystem;
  name: string;
  version: string | null;
  source_type: SourceType;
  manifest_path?: string;
  lockfile_path?: string;
  top_level: boolean;
}

export interface Reason {
  code: string;
  severity: Severity;
  decision: Decision;
  message: string;
  evidence_refs: string[];
  waivable: boolean;
}

export interface EvidenceRecord {
  id: string;
  source: string;
  kind: string;
  ref: string;
  fetched_at?: string;
  verified?: boolean;
  stale?: boolean;
}

export interface DiagnosticEntry {
  level: DiagnosticLevel;
  source: string;
  code: string;
  message: string;
  subject_ref?: string;
}

export interface WaiverScope {
  ecosystem?: Ecosystem;
  package?: string;
  version?: string;
  path?: string;
}

export interface Waiver {
  id: string;
  owner: string;
  justification: string;
  created_at: string;
  expires_at: string;
  scope: WaiverScope;
  reason_codes: string[];
  effect: WaiverEffect;
}

export interface NextAction {
  kind: string;
  summary: string;
}

export interface EvaluationMeta {
  evaluated_at: string;
  tool_version: string;
  hard_signal_state: SignalState;
  soft_signal_state: SignalState;
  stale_evidence_refs: string[];
}

export interface SubjectResult {
  schema_version: "1";
  subject: Subject;
  base_decision: Decision;
  effective_decision: Decision;
  waived: boolean;
  waived_from?: Decision;
  summary: string;
  reasons: Reason[];
  evidence: EvidenceRecord[];
  waivers_applied: Waiver[];
  next_action: NextAction;
  evaluation_meta: EvaluationMeta;
}

export interface ReportCounts {
  changed_subjects: number;
  allow: number;
  warn: number;
  review: number;
  block: number;
}

export interface DecisionReport {
  schema_version: "1";
  generated_at: string;
  tool_version: string;
  enforcement_mode?: EnforcementMode;
  status: WorkflowStatus;
  decision: ReportDecision;
  summary: string;
  counts: ReportCounts;
  paths: {
    base: string;
    head: string;
  };
  policy: {
    source: string;
    checksum: string;
    waivers_file?: string;
  };
  unsupported_files?: string[];
  diagnostics?: DiagnosticEntry[];
  results: SubjectResult[];
}

export interface ProvenanceRule {
  require_for?: string[];
  missing_action?: "review" | "block";
}

export interface Policy {
  version: 1;
  sources?: {
    allow?: string[];
    deny_direct_urls?: boolean;
  };
  provenance?: {
    npm?: ProvenanceRule;
    pypi?: ProvenanceRule;
  };
  malicious_packages?: {
    action?: "warn" | "review" | "block";
  };
  soft_signals?: {
    recent_package_age_days?: number;
    maintainer_set_change?: "warn" | "review";
    publisher_identity_drift?: "warn" | "review";
  };
  waivers?: {
    file?: string;
  };
}

export interface WaiversFile {
  version: 1;
  waivers: Waiver[];
}

export interface CacheRecord {
  schema_version: "1";
  source_identifier: string;
  lookup_key: string;
  fetched_at: string;
  freshness_target: string;
  etag?: string;
  last_modified?: string;
  serial?: string;
  signal_class: "hard" | "soft";
}

export interface DriftSnapshot {
  schema_version: "1";
  captured_at: string;
  ecosystem: Ecosystem;
  package: string;
  version: string | null;
  registry_host?: string;
  repository?: string;
  publisher_identity?: string;
  maintainers: string[];
  serial?: string;
  source_refs: string[];
}

export interface RegistryMetadata {
  registry_host?: string;
  published_at?: string;
  repository?: string;
  status?: string;
  maintainers?: string[];
  publisher_identity?: string;
}

export interface SubjectEvidence {
  registry?: RegistryMetadata;
  malicious?: {
    matched: boolean;
    ref: string;
  };
  provenance?: {
    present: boolean;
    verified: boolean;
    ref: string;
  };
  cache?: {
    registry_stale?: boolean;
    provenance_stale?: boolean;
  };
  signals?: {
    publisher_identity_drift?: boolean;
    maintainer_set_change?: boolean;
  };
  availability?: {
    hard_signal_source_available?: boolean;
    soft_signal_source_available?: boolean;
    fresh_cache_for_hard_signal?: boolean;
  };
}

export interface ResolvedDependency extends Subject {
  source_ref?: string;
  registry_host?: string;
}

export interface RepoIssue {
  ecosystem: Ecosystem;
  code: string;
  name: string;
  manifest_path?: string;
  lockfile_path?: string;
  source_type: SourceType;
  summary: string;
}

export interface RepoScanResult {
  subjects: ResolvedDependency[];
  issues: RepoIssue[];
  unsupported_files: string[];
}

export interface EvaluationInput {
  basePath: string;
  headPath: string;
  policyPath?: string;
  baselinePolicyPath?: string;
  waiverPath?: string;
  maliciousPackagesFilePath?: string;
  now: string;
  discoverRepoConfig?: boolean;
  cacheDir?: string;
  refreshCache?: boolean;
  enforcementMode?: EnforcementMode;
  metadataFetcher?: MetadataFetcher;
}

export interface EvaluateCommandResult {
  report: DecisionReport;
  summaryText: string;
  githubJobSummaryText: string;
  resolvedConfig: {
    policyPath?: string;
    baselinePolicyPath?: string;
    waiverPath?: string;
    cacheDir?: string;
  };
}

export interface FetchSubjectOptions {
  now: string;
  requireProvenance?: boolean;
}

export interface FetchSubjectResult {
  evidence: SubjectEvidence;
  diagnostics: DiagnosticEntry[];
}

export interface MetadataFetcher {
  fetch(subject: ResolvedDependency, options: FetchSubjectOptions): Promise<FetchSubjectResult>;
}

export interface MaliciousFeedLookup {
  malicious?: SubjectEvidence["malicious"];
  diagnostics: DiagnosticEntry[];
  sourceAvailable: boolean;
  freshCacheForSignal: boolean;
}

export interface MaliciousPackageFeed {
  lookup(subject: ResolvedDependency, options: { now: string; skipRemote?: boolean }): Promise<MaliciousFeedLookup>;
}
