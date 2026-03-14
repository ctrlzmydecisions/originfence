import type { EvidenceRecord, Reason, SubjectResult } from "./types";

function truncateRef(ref: string, limit = 80): string {
  if (ref.length <= limit) {
    return ref;
  }

  return `${ref.slice(0, limit - 3)}...`;
}

function getReasonEvidence(result: SubjectResult, reason: Reason): EvidenceRecord[] {
  const refs = new Set(reason.evidence_refs);
  return result.evidence.filter((entry) => refs.has(entry.id));
}

function humanizeEvidenceSource(source: string): string {
  switch (source) {
    case "npm_registry":
      return "npm registry metadata";
    case "pypi_json_api":
      return "PyPI registry metadata";
    case "npm_provenance":
      return "npm provenance";
    case "pypi_attestations":
      return "PyPI attestations";
    case "ptg_snapshot":
      return "OriginFence drift history";
    case "registry_metadata":
      return "registry repository metadata";
    case "resolver":
      return "dependency resolver";
    case "policy":
      return "active policy";
    case "malicious_packages_feed":
      return "malicious-package intelligence";
    default:
      return source.replaceAll("_", " ");
  }
}

function maliciousSourceLabel(ref: string): string {
  if (ref.startsWith("local_override:")) {
    return "Local override";
  }

  if (ref.includes("github.com/advisories") || ref.startsWith("GHSA-") || ref.startsWith("github:")) {
    return "GitHub npm malware advisory";
  }

  return "OpenSSF malicious-packages via OSV";
}

function maliciousMatchScope(ref: string): string {
  if (ref.startsWith("local_override:")) {
    const versionSeparator = ref.lastIndexOf("@");
    const version = versionSeparator >= 0 ? ref.slice(versionSeparator + 1) : "";
    return version === "*" ? "package" : "exact version";
  }

  return "exact version";
}

function allowedSourceRef(ref: string): string {
  if (ref.startsWith("allowed_sources:")) {
    return ref.slice("allowed_sources:".length);
  }

  return ref;
}

function reasonEvidenceLines(result: SubjectResult, reason: Reason, evidence: EvidenceRecord): string[] {
  switch (reason.code) {
    case "KNOWN_MALICIOUS":
      return [
        `${maliciousSourceLabel(evidence.ref)} matched this ${maliciousMatchScope(evidence.ref)}.`,
        `Reference: \`${truncateRef(evidence.ref)}\`.`
      ];
    case "DIRECT_URL_SOURCE":
      return [
        "Dependency is pinned to a direct URL instead of a registry release.",
        `Source: \`${truncateRef(evidence.ref)}\`.`
      ];
    case "VCS_SOURCE":
      return [
        "Dependency is pinned to a VCS source instead of a registry release.",
        `Source: \`${truncateRef(evidence.ref)}\`.`
      ];
    case "SOURCE_DENIED":
      return [
        "Resolved source host is outside the approved registry set.",
        `Host: \`${truncateRef(allowedSourceRef(evidence.ref))}\`.`
      ];
    case "MISSING_PROVENANCE":
      return [
        "Policy requires provenance for this package before merge.",
        "No verified provenance record was available for this release."
      ];
    case "INVALID_PROVENANCE":
      return [
        "An attestation was found but did not verify cleanly.",
        `Reference: \`${truncateRef(evidence.ref)}\`.`
      ];
    case "REGISTRY_QUARANTINED":
      return [
        "The upstream registry marked this package as quarantined or unsafe.",
        `Source: ${humanizeEvidenceSource(evidence.source)}.`
      ];
    case "PUBLISHER_IDENTITY_DRIFT":
      return [
        "OriginFence drift history saw a publisher identity change.",
        `Observed publisher: \`${truncateRef(evidence.ref)}\`.`
      ];
    case "MAINTAINER_SET_CHANGE":
      return [
        "OriginFence drift history saw a maintainer or owner set change.",
        `Reference: \`${truncateRef(evidence.ref)}\`.`
      ];
    case "RECENT_PACKAGE_AGE":
      return [
        "Registry metadata shows this package is newer than the configured threshold.",
        `Source: ${humanizeEvidenceSource(evidence.source)}.`
      ];
    case "MANIFEST_LOCKFILE_OUT_OF_SYNC":
      return [
        "The manifest changed without a matching lockfile update.",
        `Paths: \`${truncateRef(evidence.ref)}\`.`
      ];
    case "UNSUPPORTED_PROJECT_FORMAT":
      return [
        "The repository changed a dependency format OriginFence does not support in v1.",
        `Path: \`${truncateRef(evidence.ref)}\`.`
      ];
    case "SOFT_SIGNAL_SOURCE_UNAVAILABLE":
      return [
        "A soft-signal source was unavailable during evaluation.",
        "OriginFence continued with available hard signals and partial soft evidence."
      ];
    case "HARD_SIGNAL_SOURCE_UNAVAILABLE":
      return [
        "A required hard-signal source was unavailable during evaluation.",
        "OriginFence blocked because no fresh trusted hard-signal evidence was available."
      ];
    default:
      return [
        reason.message,
        `Source: ${humanizeEvidenceSource(evidence.source)}.`
      ];
  }
}

function supportingEvidenceLines(evidence: EvidenceRecord): string[] {
  switch (evidence.source) {
    case "npm_registry":
    case "pypi_json_api":
      return [`Registry metadata was fetched from ${humanizeEvidenceSource(evidence.source)}.`];
    case "ptg_snapshot":
      return ["OriginFence compared this package against prior trusted snapshot history."];
    case "registry_metadata":
      return [`Registry metadata reference: \`${truncateRef(evidence.ref)}\`.`];
    case "policy":
      return [`Policy reference: \`${truncateRef(evidence.ref)}\`.`];
    case "resolver":
      return [`Resolved source reference: \`${truncateRef(evidence.ref)}\`.`];
    default:
      return [`Evidence source: ${humanizeEvidenceSource(evidence.source)}.`];
  }
}

export function describeEvidenceBullets(result: SubjectResult, limit = 3): string[] {
  const bullets: string[] = [];
  const seen = new Set<string>();
  const usedEvidence = new Set<string>();

  const addLine = (line: string | null | undefined): void => {
    if (!line || seen.has(line) || bullets.length >= limit) {
      return;
    }

    bullets.push(line);
    seen.add(line);
  };

  for (const reason of result.reasons) {
    const evidenceEntries = getReasonEvidence(result, reason);

    if (evidenceEntries.length === 0) {
      for (const line of reasonEvidenceLines(result, reason, {
        id: "synthetic",
        source: "policy",
        kind: "policy_rule",
        ref: reason.code
      })) {
        addLine(line);
      }
      continue;
    }

    for (const evidence of evidenceEntries) {
      usedEvidence.add(evidence.id);
      for (const line of reasonEvidenceLines(result, reason, evidence)) {
        addLine(line);
      }
    }
  }

  for (const evidence of result.evidence) {
    if (bullets.length >= limit || usedEvidence.has(evidence.id)) {
      continue;
    }

    for (const line of supportingEvidenceLines(evidence)) {
      addLine(line);
    }
  }

  if (bullets.length < limit && result.evaluation_meta.stale_evidence_refs.length > 0) {
    addLine("Some supporting evidence came from OriginFence cache while a live source was unavailable.");
  }

  return bullets.slice(0, limit);
}

export function describePrimaryEvidenceLine(result: SubjectResult): string | null {
  return describeEvidenceBullets(result, 1)[0] ?? null;
}

export function describeFalsePositiveGuidance(results: SubjectResult[]): string {
  const anyWaivable = results.some((result) => result.reasons.some((reason) => reason.waivable));

  if (anyWaivable) {
    return "If this looks wrong: open the workflow run to inspect evidence, then escalate or use a time-bounded waiver with justification if policy allows.";
  }

  return "If this looks wrong: open the workflow run to inspect evidence, then escalate to the policy owner. These reasons are not waivable.";
}
