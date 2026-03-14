import { fetchJsonWithCache, readDriftSnapshot, writeDriftSnapshot } from "./cache";
import {
  npmDigestFromIntegrity,
  verifyNpmProvenance,
  verifyPypiProvenance,
  type NpmAttestationResponse,
  type NpmRegistryKeyResponse,
  type PypiAttestationResponse
} from "./provenance";
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
        integrity?: string;
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
  releases?: Record<string, Array<{ upload_time_iso_8601?: string; filename?: string; digests?: { sha256?: string } }>>;
  project_status?: {
    status?: string;
  };
  last_serial?: number;
}

interface FetcherConfig {
  cacheDir: string;
  refreshCache: boolean;
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

function setsDiffer(left: string[], right: string[]): boolean {
  if (left.length !== right.length) {
    return true;
  }

  return left.some((value, index) => value !== right[index]);
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
      const keyResult = await fetchJsonWithCache<NpmRegistryKeyResponse>({
        cacheDir: config.cacheDir,
        sourceIdentifier: "npm_registry_keys",
        lookupKey: "current",
        url: "https://registry.npmjs.org/-/npm/v1/keys",
        now: options.now,
        policy: {
          freshnessMs: 60 * 60 * 1000,
          maxStaleMs: 7 * 24 * 60 * 60 * 1000,
          freshnessTarget: "1h",
          signalClass: "hard"
        },
        refresh: config.refreshCache,
        subjectRef
      });
      diagnostics.push(...keyResult.diagnostics);
      const verification = await verifyNpmProvenance(
        attestationResult.payload,
        subject,
        keyResult.payload,
        npmDigestFromIntegrity(versionData?.dist?.integrity),
        config.cacheDir
      );

      evidence.provenance = {
        present: Boolean(attestationResult.payload?.attestations?.length),
        verified: verification.verified,
        checked: verification.checked,
        ref: attestationUrl
      };
      evidence.cache = {
        ...evidence.cache,
        provenance_stale: attestationResult.stale || keyResult.stale
      };

      if (!attestationResult.sourceAvailable || !keyResult.sourceAvailable || !verification.sourceAvailable) {
        evidence.availability = {
          ...evidence.availability,
          hard_signal_source_available: false,
          fresh_cache_for_hard_signal: Boolean(
            attestationResult.freshCacheForSignal ||
              keyResult.freshCacheForSignal
          )
        };
      }
    } else {
      evidence.provenance = {
        present: false,
        verified: false,
        checked: true,
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
          .filter((release): release is { upload_time_iso_8601?: string; filename: string; digests?: { sha256?: string } } => Boolean(release.filename))
          .map(async (release) => {
            const provenanceUrl = `https://pypi.org/integrity/${encodeURIComponent(subject.name)}/${encodeURIComponent(version)}/${encodeURIComponent(release.filename)}/provenance`;
            const result = await fetchJsonWithCache<PypiAttestationResponse>({
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
              digest: release.digests?.sha256 ?? null,
              provenanceUrl,
              result
            };
          })
      );

      for (const check of integrityChecks) {
        diagnostics.push(...check.result.diagnostics);
      }

      const allPresent = integrityChecks.length > 0 && integrityChecks.every((check) => Boolean(check.result.payload?.attestation_bundles?.length));
      const verificationChecks = await Promise.all(
        integrityChecks.map(async (check) => ({
          fileName: check.fileName,
          digest: check.digest,
          provenanceUrl: check.provenanceUrl,
          result: await verifyPypiProvenance(check.result.payload, check.fileName, check.digest, config.cacheDir)
        }))
      );
      const allVerified = allPresent && verificationChecks.every((check) => check.result.verified);
      const allChecked = verificationChecks.every((check) => check.result.checked);
      const anyUnavailable = integrityChecks.some((check) => !check.result.sourceAvailable);
      const anyVerificationUnavailable = verificationChecks.some((check) => !check.result.sourceAvailable);
      const anyFreshCache = integrityChecks.some((check) => check.result.freshCacheForSignal);
      const anyStale = integrityChecks.some((check) => check.result.stale);

      evidence.provenance = {
        present: allPresent,
        verified: allVerified,
        checked: allChecked,
        ref: `pypi_integrity:${subject.name}@${version}`
      };
      evidence.cache = {
        ...evidence.cache,
        provenance_stale: anyStale
      };

      if (anyUnavailable || anyVerificationUnavailable) {
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
