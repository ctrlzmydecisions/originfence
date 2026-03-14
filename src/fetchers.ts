import { fetchJsonWithCache, readDriftSnapshot, writeDriftSnapshot } from "./cache";
import type {
  DiagnosticEntry,
  DriftSnapshot,
  FetchSubjectOptions,
  FetchSubjectResult,
  MaliciousPackageFeed,
  MetadataFetcher,
  ResolvedDependency,
  SubjectEvidence
} from "./types";

interface NpmPackument {
  maintainers?: Array<{ name?: string; email?: string }>;
  repository?: string | { url?: string };
  time?: Record<string, string>;
  versions?: Record<
    string,
    {
      _npmUser?: { name?: string };
      repository?: string | { url?: string };
      dist?: {
        attestations?: {
          url?: string;
          provenance?: {
            predicateType?: string;
          };
        };
      };
    }
  >;
}

interface NpmAttestationResponse {
  attestations?: Array<{
    predicateType?: string;
    bundle?: {
      dsseEnvelope?: {
        payload?: string;
      };
      verificationMaterial?: {
        tlogEntries?: unknown[];
      };
    };
  }>;
}

interface PypiJsonResponse {
  info?: {
    project_urls?: Record<string, string>;
  };
  ownership?:
    | string[]
    | Array<{ username?: string }>
    | {
        organization?: string | null;
        roles?: Array<{ role?: string; user?: string }>;
      };
  releases?: Record<string, Array<{ upload_time_iso_8601?: string; filename?: string }>>;
  project_status?: {
    status?: string;
  };
  last_serial?: number;
}

interface PypiIntegrityResponse {
  attestation_bundles?: Array<{
    attestations?: Array<{
      envelope?: {
        statement?: string;
      };
    }>;
    verification_material?: {
      certificate?: string;
    };
  }>;
}

interface FetcherConfig {
  cacheDir: string;
  refreshCache: boolean;
}

interface DecodedStatement {
  subject?: Array<{ name?: string; digest?: Record<string, string> }>;
  predicateType?: string;
  predicate?: Record<string, unknown>;
}

function normalizeMaintainers(
  values:
    | Array<{ name?: string; email?: string }>
    | string[]
    | Array<{ username?: string }>
    | {
        organization?: string | null;
        roles?: Array<{ role?: string; user?: string }>;
      }
    | undefined
): string[] {
  if (!values) {
    return [];
  }

  if (!Array.isArray(values)) {
    return (values.roles ?? [])
      .map((entry) => entry.user ?? "")
      .filter(Boolean)
      .sort();
  }

  return values
    .map((value) => {
      if (typeof value === "string") {
        return value;
      }

      if ("username" in value && value.username) {
        return value.username;
      }

      if ("name" in value || "email" in value) {
        return value.name ?? value.email ?? "";
      }

      return "";
    })
    .filter(Boolean)
    .sort();
}

function extractRepository(repository: string | { url?: string } | undefined): string | undefined {
  if (!repository) {
    return undefined;
  }

  if (typeof repository === "string") {
    return repository;
  }

  return repository.url;
}

function decodeStatement(payload: string | undefined): DecodedStatement | null {
  if (!payload) {
    return null;
  }

  try {
    return JSON.parse(Buffer.from(payload, "base64").toString("utf8")) as DecodedStatement;
  } catch {
    return null;
  }
}

function setsDiffer(left: string[], right: string[]): boolean {
  if (left.length !== right.length) {
    return true;
  }

  return left.some((value, index) => value !== right[index]);
}

function verifyNpmAttestations(payload: NpmAttestationResponse | null, subject: ResolvedDependency): boolean {
  if (!payload?.attestations?.length || !subject.version) {
    return false;
  }

  return payload.attestations.some((attestation) => {
    const statement = decodeStatement(attestation.bundle?.dsseEnvelope?.payload);
    const subjectMatch = statement?.subject?.some((entry) => entry.name === `pkg:npm/${subject.name}@${subject.version}`);
    const predicateName = typeof statement?.predicate?.name === "string" ? statement.predicate.name : undefined;
    const predicateVersion = typeof statement?.predicate?.version === "string" ? statement.predicate.version : undefined;
    const registry = typeof statement?.predicate?.registry === "string" ? statement.predicate.registry : undefined;
    const hasVerificationMaterial = Array.isArray(attestation.bundle?.verificationMaterial?.tlogEntries);

    return Boolean(subjectMatch && predicateName === subject.name && predicateVersion === subject.version && registry?.includes("npmjs.org") && hasVerificationMaterial);
  });
}

function verifyPypiAttestations(payload: PypiIntegrityResponse | null, fileName: string): boolean {
  if (!payload?.attestation_bundles?.length) {
    return false;
  }

  return payload.attestation_bundles.every((bundle) => {
    if (!bundle.verification_material?.certificate || !bundle.attestations?.length) {
      return false;
    }

    return bundle.attestations.some((attestation) => {
      const statement = decodeStatement(attestation.envelope?.statement);
      const subjectMatch = statement?.subject?.some((entry) => entry.name === fileName);
      return Boolean(subjectMatch && statement?.predicateType === "https://docs.pypi.org/attestations/publish/v1");
    });
  });
}

function mergeEvidence(base: SubjectEvidence, overlay: SubjectEvidence): SubjectEvidence {
  return {
    registry: {
      ...base.registry,
      ...overlay.registry
    },
    malicious: overlay.malicious ?? base.malicious,
    provenance: overlay.provenance ?? base.provenance,
    cache: {
      ...base.cache,
      ...overlay.cache
    },
    signals: {
      ...base.signals,
      ...overlay.signals
    },
    availability: {
      ...base.availability,
      ...overlay.availability
    }
  };
}

function mergeAvailability(
  base: SubjectEvidence["availability"],
  overlay: { hardSignalSourceAvailable?: boolean; freshCacheForSignal?: boolean }
): SubjectEvidence["availability"] {
  const hardSignalSourceAvailable =
    (base?.hard_signal_source_available ?? true) && (overlay.hardSignalSourceAvailable ?? true);

  return {
    ...base,
    hard_signal_source_available: hardSignalSourceAvailable,
    fresh_cache_for_hard_signal: Boolean(base?.fresh_cache_for_hard_signal || overlay.freshCacheForSignal)
  };
}

function buildDriftSnapshot(
  subject: ResolvedDependency,
  registry: NonNullable<SubjectEvidence["registry"]>,
  capturedAt: string,
  serial?: string
): DriftSnapshot {
  return {
    schema_version: "1",
    captured_at: capturedAt,
    ecosystem: subject.ecosystem,
    package: subject.name,
    version: subject.version,
    registry_host: registry.registry_host,
    repository: registry.repository,
    publisher_identity: registry.publisher_identity,
    maintainers: [...(registry.maintainers ?? [])].sort(),
    serial,
    source_refs: [subject.name, subject.version ?? "unknown"]
  };
}

async function applyDriftSignals(
  cacheDir: string,
  subject: ResolvedDependency,
  evidence: SubjectEvidence,
  now: string,
  diagnostics: DiagnosticEntry[],
  serial?: string,
  allowSnapshotWrite = true
): Promise<void> {
  if (!evidence.registry) {
    return;
  }

  const current = buildDriftSnapshot(subject, evidence.registry, now, serial);
  const previous = await readDriftSnapshot(cacheDir, subject.ecosystem, subject.name);

  if (previous) {
    const currentMaintainers = current.maintainers;
    const previousMaintainers = [...previous.maintainers].sort();

    if (currentMaintainers.length > 0 && previousMaintainers.length > 0 && setsDiffer(previousMaintainers, currentMaintainers)) {
      evidence.signals = {
        ...evidence.signals,
        maintainer_set_change: true
      };
      diagnostics.push({
        level: "warn",
        source: "ptg_drift_snapshot",
        code: "MAINTAINER_DRIFT_DETECTED",
        message: `${subject.name} maintainer set differs from the last OriginFence snapshot.`,
        subject_ref: `${subject.ecosystem}:${subject.name}@${subject.version ?? "*"}`
      });
    }

    if (previous.publisher_identity && current.publisher_identity && previous.publisher_identity !== current.publisher_identity) {
      evidence.signals = {
        ...evidence.signals,
        publisher_identity_drift: true
      };
      diagnostics.push({
        level: "warn",
        source: "ptg_drift_snapshot",
        code: "PUBLISHER_DRIFT_DETECTED",
        message: `${subject.name} publisher identity differs from the last OriginFence snapshot.`,
        subject_ref: `${subject.ecosystem}:${subject.name}@${subject.version ?? "*"}`
      });
    }
  }

  if (allowSnapshotWrite) {
    await writeDriftSnapshot(cacheDir, current);
  }
}

async function fetchNpmEvidence(subject: ResolvedDependency, config: FetcherConfig, options: FetchSubjectOptions): Promise<FetchSubjectResult> {
  const diagnostics: DiagnosticEntry[] = [];
  const subjectRef = `${subject.ecosystem}:${subject.name}@${subject.version ?? "*"}`;
  const packumentResult = await fetchJsonWithCache<NpmPackument>({
    cacheDir: config.cacheDir,
    sourceIdentifier: "npm_packument",
    lookupKey: subject.name,
    url: `https://registry.npmjs.org/${encodeURIComponent(subject.name)}`,
    now: options.now,
    policy: {
      freshnessMs: 5 * 60 * 1000,
      maxStaleMs: 24 * 60 * 60 * 1000,
      freshnessTarget: "5m",
      signalClass: "hard"
    },
    refresh: config.refreshCache,
    subjectRef
  });

  diagnostics.push(...packumentResult.diagnostics);

  if (!packumentResult.payload) {
    return {
      evidence: {
        availability: {
          hard_signal_source_available: false,
          soft_signal_source_available: false,
          fresh_cache_for_hard_signal: packumentResult.freshCacheForSignal
        }
      },
      diagnostics
    };
  }

  const versionData = subject.version ? packumentResult.payload.versions?.[subject.version] : undefined;
  const evidence: SubjectEvidence = {
    registry: {
      registry_host: "registry.npmjs.org",
      published_at: subject.version ? packumentResult.payload.time?.[subject.version] : undefined,
      repository: extractRepository(versionData?.repository ?? packumentResult.payload.repository),
      maintainers: normalizeMaintainers(packumentResult.payload.maintainers),
      publisher_identity: versionData?._npmUser?.name
    },
    cache: {
      registry_stale: packumentResult.stale
    },
    availability: {
      hard_signal_source_available: packumentResult.sourceAvailable,
      soft_signal_source_available: packumentResult.sourceAvailable,
      fresh_cache_for_hard_signal: packumentResult.freshCacheForSignal
    }
  };

  if (options.requireProvenance && subject.version) {
    const attestationUrl = versionData?.dist?.attestations?.url;

    if (attestationUrl) {
      const attestationResult = await fetchJsonWithCache<NpmAttestationResponse>({
        cacheDir: config.cacheDir,
        sourceIdentifier: "npm_attestations",
        lookupKey: `${subject.name}@${subject.version}`,
        url: attestationUrl,
        now: options.now,
        policy: {
          freshnessMs: 0,
          maxStaleMs: 24 * 60 * 60 * 1000,
          freshnessTarget: "per_run",
          signalClass: "hard"
        },
        refresh: config.refreshCache,
        acceptStatuses: [200, 404],
        subjectRef
      });

      diagnostics.push(...attestationResult.diagnostics);
      evidence.provenance = {
        present: Boolean(attestationResult.payload?.attestations?.length),
        verified: verifyNpmAttestations(attestationResult.payload, subject),
        ref: attestationUrl
      };
      evidence.cache = {
        ...evidence.cache,
        provenance_stale: attestationResult.stale
      };

      if (!attestationResult.sourceAvailable) {
        evidence.availability = {
          ...evidence.availability,
          hard_signal_source_available: false,
          fresh_cache_for_hard_signal: attestationResult.freshCacheForSignal
        };
      }
    } else {
      evidence.provenance = {
        present: false,
        verified: false,
        ref: `npm_attestations:${subject.name}@${subject.version}`
      };
    }
  }

  await applyDriftSignals(config.cacheDir, subject, evidence, options.now, diagnostics, undefined, !packumentResult.stale);
  return { evidence, diagnostics };
}

async function fetchPypiEvidence(subject: ResolvedDependency, config: FetcherConfig, options: FetchSubjectOptions): Promise<FetchSubjectResult> {
  const diagnostics: DiagnosticEntry[] = [];
  const subjectRef = `${subject.ecosystem}:${subject.name}@${subject.version ?? "*"}`;
  const jsonResult = await fetchJsonWithCache<PypiJsonResponse>({
    cacheDir: config.cacheDir,
    sourceIdentifier: "pypi_json_api",
    lookupKey: subject.name,
    url: `https://pypi.org/pypi/${encodeURIComponent(subject.name)}/json`,
    now: options.now,
    policy: {
      freshnessMs: 15 * 60 * 1000,
      maxStaleMs: 24 * 60 * 60 * 1000,
      freshnessTarget: "15m",
      signalClass: "hard"
    },
    refresh: config.refreshCache,
    subjectRef
  });

  diagnostics.push(...jsonResult.diagnostics);

  if (!jsonResult.payload) {
    return {
      evidence: {
        availability: {
          hard_signal_source_available: false,
          soft_signal_source_available: false,
          fresh_cache_for_hard_signal: jsonResult.freshCacheForSignal
        }
      },
      diagnostics
    };
  }

  const releases = subject.version ? jsonResult.payload.releases?.[subject.version] ?? [] : [];
  const evidence: SubjectEvidence = {
    registry: {
      registry_host: "pypi.org",
      published_at: releases[0]?.upload_time_iso_8601,
      repository:
        jsonResult.payload.info?.project_urls?.Source ??
        jsonResult.payload.info?.project_urls?.["Source Code"] ??
        jsonResult.payload.info?.project_urls?.Homepage,
      maintainers: normalizeMaintainers(jsonResult.payload.ownership),
      status: jsonResult.payload.project_status?.status
    },
    cache: {
      registry_stale: jsonResult.stale
    },
    availability: {
      hard_signal_source_available: jsonResult.sourceAvailable,
      soft_signal_source_available: jsonResult.sourceAvailable,
      fresh_cache_for_hard_signal: jsonResult.freshCacheForSignal
    }
  };

  if (options.requireProvenance && subject.version) {
    const version = subject.version;

    if (releases.length === 0) {
      evidence.provenance = {
        present: false,
        verified: false,
        ref: `pypi_integrity:${subject.name}@${version}`
      };
    } else {
      const integrityChecks = await Promise.all(
        releases
          .filter((release): release is { upload_time_iso_8601?: string; filename: string } => Boolean(release.filename))
          .map(async (release) => {
            const provenanceUrl = `https://pypi.org/integrity/${encodeURIComponent(subject.name)}/${encodeURIComponent(version)}/${encodeURIComponent(release.filename)}/provenance`;
            const result = await fetchJsonWithCache<PypiIntegrityResponse>({
              cacheDir: config.cacheDir,
              sourceIdentifier: "pypi_integrity_api",
              lookupKey: `${subject.name}@${version}:${release.filename}`,
              url: provenanceUrl,
              now: options.now,
              policy: {
                freshnessMs: 0,
                maxStaleMs: 24 * 60 * 60 * 1000,
                freshnessTarget: "per_run",
                signalClass: "hard"
              },
              refresh: config.refreshCache,
              acceptStatuses: [200, 404],
              subjectRef
            });

            return {
              fileName: release.filename,
              provenanceUrl,
              result
            };
          })
      );

      for (const check of integrityChecks) {
        diagnostics.push(...check.result.diagnostics);
      }

      const allPresent = integrityChecks.length > 0 && integrityChecks.every((check) => Boolean(check.result.payload?.attestation_bundles?.length));
      const allVerified = allPresent && integrityChecks.every((check) => verifyPypiAttestations(check.result.payload, check.fileName));
      const anyUnavailable = integrityChecks.some((check) => !check.result.sourceAvailable);
      const anyFreshCache = integrityChecks.some((check) => check.result.freshCacheForSignal);
      const anyStale = integrityChecks.some((check) => check.result.stale);

      evidence.provenance = {
        present: allPresent,
        verified: allVerified,
        ref: `pypi_integrity:${subject.name}@${version}`
      };
      evidence.cache = {
        ...evidence.cache,
        provenance_stale: anyStale
      };

      if (anyUnavailable) {
        evidence.availability = {
          ...evidence.availability,
          hard_signal_source_available: false,
          fresh_cache_for_hard_signal: anyFreshCache
        };
      }
    }
  }

  await applyDriftSignals(config.cacheDir, subject, evidence, options.now, diagnostics, jsonResult.payload.last_serial ? String(jsonResult.payload.last_serial) : undefined, !jsonResult.stale);
  return { evidence, diagnostics };
}

export class CompositeMetadataFetcher implements MetadataFetcher {
  private readonly maliciousFeed: MaliciousPackageFeed;
  private readonly config: FetcherConfig;

  public constructor(maliciousFeed: MaliciousPackageFeed, config: FetcherConfig) {
    this.maliciousFeed = maliciousFeed;
    this.config = config;
  }

  public async fetch(subject: ResolvedDependency, options: FetchSubjectOptions): Promise<FetchSubjectResult> {
    const maliciousLookup = await this.maliciousFeed.lookup(subject, { now: options.now });

    let liveResult: FetchSubjectResult = {
      evidence: {},
      diagnostics: []
    };

    if (subject.source_type === "registry") {
      liveResult =
        subject.ecosystem === "npm"
          ? await fetchNpmEvidence(subject, this.config, options)
          : await fetchPypiEvidence(subject, this.config, options);
    }

    return {
      evidence: mergeEvidence(liveResult.evidence, {
        malicious: maliciousLookup.malicious,
        availability: mergeAvailability(liveResult.evidence.availability, {
          hardSignalSourceAvailable: maliciousLookup.sourceAvailable,
          freshCacheForSignal: maliciousLookup.freshCacheForSignal
        })
      }),
      diagnostics: [...liveResult.diagnostics, ...maliciousLookup.diagnostics]
    };
  }
}
