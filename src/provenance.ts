import path from "node:path";
import { X509Certificate } from "node:crypto";
import { TUFError, type Bundle, verify as verifySigstoreBundle } from "sigstore";

import type { ResolvedDependency } from "./types";

export interface DecodedStatement {
  subject?: Array<{ name?: string; digest?: Record<string, string> }>;
  predicateType?: string;
  predicate?: Record<string, unknown>;
}

export interface NpmRegistryKey {
  keyid?: string;
  key?: string;
}

export interface NpmRegistryKeyResponse {
  keys?: NpmRegistryKey[];
}

export interface NpmAttestationResponse {
  attestations?: Array<{
    predicateType?: string;
    bundle?: Bundle;
  }>;
}

export interface PypiAttestationResponse {
  attestation_bundles?: Array<{
    attestations?: Array<{
      envelope?: {
        signature?: string;
        statement?: string;
      };
      verification_material?: {
        certificate?: string;
        transparency_entries?: Array<{
          canonicalizedBody?: string;
          inclusionPromise?: {
            signedEntryTimestamp?: string;
          };
          inclusionProof?: {
            checkpoint?: {
              envelope?: string;
            };
            hashes?: string[];
            logIndex?: number | string;
            rootHash?: string;
            treeSize?: number | string;
          };
          integratedTime?: number | string;
          kindVersion?: {
            kind?: string;
            version?: string;
          };
          logId?: {
            keyId?: string;
          };
          logIndex?: number | string;
        }>;
      };
    }>;
  }>;
}

export interface VerificationOutcome {
  checked: boolean;
  verified: boolean;
  sourceAvailable: boolean;
}

const PYPI_DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";
const PYPI_PUBLISH_PREDICATE = "https://docs.pypi.org/attestations/publish/v1";
const VERIFY_CACHE_SUBDIR = "sigstore-tuf";
const PYPI_KEY_HINT = "pypi-attestation-certificate";

let sigstoreVerifier: typeof verifySigstoreBundle = verifySigstoreBundle;

export function setSigstoreVerifierForTests(
  verifier: ((bundle: Bundle, options?: unknown) => Promise<unknown>) | null
): void {
  sigstoreVerifier = verifier ? (verifier as typeof verifySigstoreBundle) : verifySigstoreBundle;
}

export function decodeStatement(payload: string | undefined): DecodedStatement | null {
  if (!payload) {
    return null;
  }

  try {
    return JSON.parse(Buffer.from(payload, "base64").toString("utf8")) as DecodedStatement;
  } catch {
    return null;
  }
}

function base64FromBase64Url(value: string): string {
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const remainder = normalized.length % 4;

  if (remainder === 0) {
    return normalized;
  }

  return `${normalized}${"=".repeat(4 - remainder)}`;
}

function sha512HexFromIntegrity(integrity: string | undefined): string | null {
  if (!integrity || !integrity.startsWith("sha512-")) {
    return null;
  }

  const encoded = integrity.slice("sha512-".length);
  return Buffer.from(base64FromBase64Url(encoded), "base64").toString("hex");
}

function isTrustedNpmRegistryUrl(value: string | undefined): boolean {
  if (!value) {
    return false;
  }

  try {
    const host = new URL(value).host;
    return host === "registry.npmjs.org" || host === "npmjs.org";
  } catch {
    return false;
  }
}

function buildTufCachePath(cacheDir: string): string {
  return path.join(cacheDir, VERIFY_CACHE_SUBDIR);
}

function isTrustRootAvailabilityError(error: unknown): boolean {
  return error instanceof TUFError;
}

async function verifyBundleWithSigstore(
  bundle: Bundle,
  cacheDir: string,
  keySelector: (hint: string) => Buffer | undefined
): Promise<VerificationOutcome> {
  try {
    await sigstoreVerifier(bundle, {
      keySelector,
      tufCachePath: buildTufCachePath(cacheDir)
    });
    return {
      checked: true,
      verified: true,
      sourceAvailable: true
    };
  } catch (error) {
    if (isTrustRootAvailabilityError(error)) {
      return {
        checked: false,
        verified: false,
        sourceAvailable: false
      };
    }

    return {
      checked: true,
      verified: false,
      sourceAvailable: true
    };
  }
}

function parseCertificate(certificate: string | undefined): X509Certificate | null {
  if (!certificate) {
    return null;
  }

  try {
    return new X509Certificate(Buffer.from(certificate, "base64"));
  } catch {
    return null;
  }
}

function certificateValidAt(cert: X509Certificate, integratedTime: number | null): boolean {
  if (integratedTime === null) {
    return true;
  }

  const validFrom = Date.parse(cert.validFrom);
  const validTo = Date.parse(cert.validTo);
  return Number.isFinite(validFrom) && Number.isFinite(validTo) && integratedTime >= validFrom && integratedTime <= validTo;
}

function parseIntegratedTime(value: number | string | undefined): number | null {
  if (typeof value === "number") {
    return value * 1000;
  }

  if (typeof value === "string" && value.length > 0) {
    const seconds = Number(value);
    return Number.isFinite(seconds) ? seconds * 1000 : null;
  }

  return null;
}

function buildPypiSigstoreBundle(
  attestation: NonNullable<NonNullable<PypiAttestationResponse["attestation_bundles"]>[number]["attestations"]>[number]
): Bundle | null {
  const entry = attestation.verification_material?.transparency_entries?.[0];
  const signature = attestation.envelope?.signature;
  const statement = attestation.envelope?.statement;

  if (!entry?.kindVersion?.kind || !entry.logId?.keyId || !signature || !statement) {
    return null;
  }

  return {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: {
      publicKey: {
        hint: PYPI_KEY_HINT
      },
      x509CertificateChain: undefined,
      certificate: undefined,
      tlogEntries: [
        {
          canonicalizedBody: entry.canonicalizedBody ?? "",
          inclusionPromise: entry.inclusionPromise?.signedEntryTimestamp
            ? {
                signedEntryTimestamp: entry.inclusionPromise.signedEntryTimestamp
              }
            : undefined,
          inclusionProof: entry.inclusionProof
            ? {
                logIndex: String(entry.inclusionProof.logIndex ?? ""),
                rootHash: entry.inclusionProof.rootHash ?? "",
                treeSize: String(entry.inclusionProof.treeSize ?? ""),
                hashes: entry.inclusionProof.hashes ?? [],
                checkpoint: {
                  envelope: entry.inclusionProof.checkpoint?.envelope ?? ""
                }
              }
            : undefined,
          integratedTime: String(entry.integratedTime ?? ""),
          kindVersion: {
            kind: entry.kindVersion.kind,
            version: entry.kindVersion.version ?? ""
          },
          logId: {
            keyId: entry.logId.keyId
          },
          logIndex: String(entry.logIndex ?? "")
        }
      ],
      timestampVerificationData: undefined
    },
    dsseEnvelope: {
      payload: statement,
      payloadType: PYPI_DSSE_PAYLOAD_TYPE,
      signatures: [
        {
          keyid: PYPI_KEY_HINT,
          sig: signature
        }
      ]
    },
    messageSignature: undefined
  };
}

export async function verifyNpmProvenance(
  payload: NpmAttestationResponse | null,
  subject: ResolvedDependency,
  registryKeys: NpmRegistryKeyResponse | null,
  expectedDigest: string | null,
  cacheDir: string
): Promise<VerificationOutcome> {
  if (!payload?.attestations?.length || !subject.version || !expectedDigest || !registryKeys?.keys?.length) {
    return {
      checked: true,
      verified: false,
      sourceAvailable: Boolean(registryKeys?.keys?.length)
    };
  }

  for (const attestation of payload.attestations) {
    if (!attestation.bundle?.dsseEnvelope) {
      continue;
    }

    const statement = decodeStatement(attestation.bundle.dsseEnvelope.payload);
    const subjectEntry = statement?.subject?.find((entry) => entry.name === `pkg:npm/${subject.name}@${subject.version}`);
    const predicateName = typeof statement?.predicate?.name === "string" ? statement.predicate.name : undefined;
    const predicateVersion = typeof statement?.predicate?.version === "string" ? statement.predicate.version : undefined;
    const predicateRegistry = typeof statement?.predicate?.registry === "string" ? statement.predicate.registry : undefined;
    const digestMatch = subjectEntry?.digest?.sha512 === expectedDigest;

    if (!subjectEntry || !digestMatch || predicateName !== subject.name || predicateVersion !== subject.version || !isTrustedNpmRegistryUrl(predicateRegistry)) {
      continue;
    }

    const verification = await verifyBundleWithSigstore(
      attestation.bundle,
      cacheDir,
      (hint) => {
        const matchedKey = registryKeys.keys?.find((key) => key.keyid === hint)?.key;
        return matchedKey ? Buffer.from(matchedKey, "base64") : undefined;
      }
    );

    if (!verification.checked || verification.verified) {
      return verification;
    }
  }

  return {
    checked: true,
    verified: false,
    sourceAvailable: true
  };
}

export async function verifyPypiProvenance(
  payload: PypiAttestationResponse | null,
  fileName: string,
  expectedDigest: string | null,
  cacheDir: string
): Promise<VerificationOutcome> {
  if (!payload?.attestation_bundles?.length || !expectedDigest) {
    return {
      checked: true,
      verified: false,
      sourceAvailable: true
    };
  }

  let matchedAttestation = false;

  for (const bundle of payload.attestation_bundles) {
    for (const attestation of bundle.attestations ?? []) {
      const statement = decodeStatement(attestation.envelope?.statement);
      const subjectEntry = statement?.subject?.find((entry) => entry.name === fileName);
      const certificate = parseCertificate(attestation.verification_material?.certificate);
      const integratedTime = parseIntegratedTime(attestation.verification_material?.transparency_entries?.[0]?.integratedTime);

      if (!statement || !subjectEntry || statement.predicateType !== PYPI_PUBLISH_PREDICATE || subjectEntry.digest?.sha256 !== expectedDigest || !certificate) {
        continue;
      }

      matchedAttestation = true;

      if (!certificateValidAt(certificate, integratedTime)) {
        return {
          checked: true,
          verified: false,
          sourceAvailable: true
        };
      }

      const publicKey = certificate.publicKey.export({
        format: "der",
        type: "spki"
      }) as Buffer;
      const sigstoreBundle = buildPypiSigstoreBundle(attestation);

      if (!sigstoreBundle) {
        continue;
      }

      const verification = await verifyBundleWithSigstore(
        sigstoreBundle,
        cacheDir,
        (hint) => hint === PYPI_KEY_HINT ? publicKey : undefined
      );

      if (!verification.checked || !verification.verified) {
        return verification;
      }
    }
  }

  return {
    checked: true,
    verified: matchedAttestation,
    sourceAvailable: true
  };
}

export function npmDigestFromIntegrity(integrity: string | undefined): string | null {
  return sha512HexFromIntegrity(integrity);
}
