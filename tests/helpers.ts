import fs from "node:fs/promises";
import path from "node:path";

import type { MetadataFetcher, ResolvedDependency, SubjectEvidence } from "../src/types";

export const FIXTURES_ROOT = path.resolve(process.cwd(), "fixtures");
export const CASES_ROOT = path.join(FIXTURES_ROOT, "cases");
export const FIXED_NOW = "2026-03-13T12:00:00Z";
export const TEST_TMP_ROOT = path.resolve(process.cwd(), "..", ".tmp", "originfence-tests");

export interface FixtureCase {
  name: string;
  path: string;
}

export async function listFixtureCases(): Promise<FixtureCase[]> {
  const entries = await fs.readdir(CASES_ROOT, { withFileTypes: true });

  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({
      name: entry.name,
      path: path.join(CASES_ROOT, entry.name)
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

export async function readJsonFile<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as T;
}

export async function readTextFile(filePath: string): Promise<string> {
  return fs.readFile(filePath, "utf8");
}

export async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function makeTempDir(prefix: string): Promise<string> {
  await fs.mkdir(TEST_TMP_ROOT, { recursive: true });
  return fs.mkdtemp(path.join(TEST_TMP_ROOT, prefix));
}

export async function writeFiles(root: string, files: Record<string, string>): Promise<void> {
  for (const [relativePath, content] of Object.entries(files)) {
    const absolutePath = path.join(root, relativePath);
    await fs.mkdir(path.dirname(absolutePath), { recursive: true });
    await fs.writeFile(absolutePath, content, "utf8");
  }
}

interface TestEvidenceOverrideEntry extends SubjectEvidence {
  match: {
    ecosystem: ResolvedDependency["ecosystem"];
    name: string;
    version?: string | null;
  };
}

interface TestEvidenceOverrideFile {
  subjects: TestEvidenceOverrideEntry[];
}

export async function loadFixtureMetadataFetcher(fixturePath: string): Promise<MetadataFetcher | undefined> {
  const filePath = path.join(fixturePath, "evidence.json");

  if (!await fileExists(filePath)) {
    return undefined;
  }

  const content = await fs.readFile(filePath, "utf8");
  const overrides = JSON.parse(content) as TestEvidenceOverrideFile;

  return {
    async fetch(subject) {
      const match = overrides.subjects.find((entry) => {
        if (entry.match.ecosystem !== subject.ecosystem || entry.match.name !== subject.name) {
          return false;
        }

        if (typeof entry.match.version === "undefined") {
          return true;
        }

        return entry.match.version === subject.version;
      });

      if (!match) {
        return {
          evidence: {},
          diagnostics: []
        };
      }

      return {
        evidence: {
          registry: match.registry,
          malicious: match.malicious,
          provenance: match.provenance,
          cache: match.cache,
          signals: match.signals,
          availability: match.availability
        },
        diagnostics: []
      };
    }
  };
}
