import fs from "node:fs/promises";
import path from "node:path";
import TOML from "toml";

import type {
  RepoIssue,
  ResolvedDependency,
  RepoScanResult,
  SourceType
} from "./types";
import { readFileIfExists } from "./utils";

const DEFERRED_FILES = ["pnpm-lock.yaml", "yarn.lock", "poetry.lock"] as const;

interface PackageJsonShape {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  repository?: string | { type?: string; url?: string };
}

interface PackageLockShape {
  name?: string;
  lockfileVersion?: number;
  packages?: Record<string, { name?: string; version?: string; resolved?: string } & Record<string, unknown>>;
  dependencies?: Record<string, PackageLockDependencyNode>;
}

interface PackageLockDependencyNode {
  version?: string;
  resolved?: string;
  dependencies?: Record<string, PackageLockDependencyNode>;
}

function collectTopLevelSpecs(packageJson: PackageJsonShape | null): Map<string, string> {
  const specs = new Map<string, string>();

  for (const dependencyGroup of [
    packageJson?.dependencies,
    packageJson?.devDependencies,
    packageJson?.optionalDependencies,
    packageJson?.peerDependencies
  ]) {
    for (const [name, spec] of Object.entries(dependencyGroup ?? {})) {
      specs.set(name, spec);
    }
  }

  return specs;
}

function classifySource(spec: string | undefined | null): SourceType {
  if (!spec) {
    return "registry";
  }

  if (spec.startsWith("git+") || spec.startsWith("github:") || spec.startsWith("git@")) {
    return "vcs";
  }

  if (spec.startsWith("file:") || spec.startsWith("./") || spec.startsWith("../") || spec.startsWith("/")) {
    return "file";
  }

  if (spec.startsWith("http://") || spec.startsWith("https://")) {
    if (spec.includes(".git") || spec.includes("github.com")) {
      return "vcs";
    }

    return "direct_url";
  }

  return "registry";
}

function extractRegistryHost(spec: string | undefined | null): string | undefined {
  if (!spec) {
    return undefined;
  }

  try {
    const url = new URL(spec);
    return url.host;
  } catch {
    return undefined;
  }
}

function derivePackageNameFromLockPath(packagePath: string): string | null {
  if (!packagePath.includes("node_modules/")) {
    return null;
  }

  const segments = packagePath.split("node_modules/").filter(Boolean);
  const last = segments.at(-1);

  if (!last) {
    return null;
  }

  return last;
}

function parsePackageJson(content: string | null): PackageJsonShape | null {
  if (!content) {
    return null;
  }

  return JSON.parse(content) as PackageJsonShape;
}

function parsePackageLock(content: string | null): PackageLockShape | null {
  if (!content) {
    return null;
  }

  return JSON.parse(content) as PackageLockShape;
}

function parseNpmLockSubjects(
  lockfile: PackageLockShape | null,
  packageJson: PackageJsonShape | null
): ResolvedDependency[] {
  if (!lockfile) {
    return [];
  }

  const topLevelSpecs = collectTopLevelSpecs(packageJson);
  const subjects: ResolvedDependency[] = [];

  if (lockfile.packages) {
    for (const [packagePath, metadata] of Object.entries(lockfile.packages)) {
      if (packagePath === "") {
        continue;
      }

      const name = metadata.name ?? derivePackageNameFromLockPath(packagePath);

      if (!name) {
        continue;
      }

      const topLevelSpec = topLevelSpecs.get(name);
      const sourceRef = topLevelSpec ?? metadata.resolved;
      const sourceType = classifySource(sourceRef);

      subjects.push({
        ecosystem: "npm",
        name,
        version: metadata.version ?? null,
        source_type: sourceType,
        manifest_path: "package.json",
        lockfile_path: "package-lock.json",
        top_level: topLevelSpecs.has(name),
        source_ref: sourceRef,
        registry_host: sourceType === "registry" ? extractRegistryHost(metadata.resolved) ?? "registry.npmjs.org" : extractRegistryHost(sourceRef)
      });
    }

    return subjects;
  }

  const walk = (dependencies: Record<string, PackageLockDependencyNode>, topLevel = false): void => {
    for (const [name, dependency] of Object.entries(dependencies)) {
      const topLevelSpec = topLevelSpecs.get(name);
      const sourceRef = topLevelSpec ?? dependency.resolved;
      const sourceType = classifySource(sourceRef);

      subjects.push({
        ecosystem: "npm",
        name,
        version: dependency.version ?? null,
        source_type: sourceType,
        manifest_path: "package.json",
        lockfile_path: "package-lock.json",
        top_level: topLevel || topLevelSpecs.has(name),
        source_ref: sourceRef,
        registry_host: sourceType === "registry" ? extractRegistryHost(dependency.resolved) ?? "registry.npmjs.org" : extractRegistryHost(sourceRef)
      });

      if (dependency.dependencies) {
        walk(dependency.dependencies, false);
      }
    }
  };

  walk(lockfile.dependencies ?? {}, true);
  return subjects;
}

function parseRequirementLine(line: string): ResolvedDependency | null {
  const trimmed = line.trim();

  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) {
    return null;
  }

  if (trimmed.includes(" @ ")) {
    const [namePart = "", refPart = ""] = trimmed.split(" @ ", 2);
    const sourceType = classifySource(refPart);

    return {
      ecosystem: "pypi",
      name: namePart.trim(),
      version: refPart.trim(),
      source_type: sourceType,
      manifest_path: "requirements.txt",
      lockfile_path: "requirements.txt",
      top_level: true,
      source_ref: refPart.trim(),
      registry_host: sourceType === "registry" ? "pypi.org" : extractRegistryHost(refPart.trim())
    };
  }

  if (trimmed.includes("==")) {
    const [namePart = "", versionPart = ""] = trimmed.split("==", 2);

    return {
      ecosystem: "pypi",
      name: namePart.trim(),
      version: versionPart.trim(),
      source_type: "registry",
      manifest_path: "requirements.txt",
      lockfile_path: "requirements.txt",
      top_level: true,
      source_ref: undefined,
      registry_host: "pypi.org"
    };
  }

  return {
    ecosystem: "pypi",
    name: trimmed,
    version: null,
    source_type: "unknown",
    manifest_path: "requirements.txt",
    lockfile_path: "requirements.txt",
    top_level: true,
    source_ref: trimmed
  };
}

function parseRequirements(content: string | null): ResolvedDependency[] {
  if (!content) {
    return [];
  }

  return content
    .split(/\r?\n/u)
    .map((line) => parseRequirementLine(line))
    .filter((entry): entry is ResolvedDependency => entry !== null);
}

function parsePyprojectDependencyNames(pyprojectContent: string | null): Set<string> {
  if (!pyprojectContent) {
    return new Set<string>();
  }

  const document = TOML.parse(pyprojectContent) as {
    project?: {
      dependencies?: string[];
    };
  };

  const names = new Set<string>();

  for (const dependency of document.project?.dependencies ?? []) {
    const [namePart] = dependency.split(/[ <>=@]/u, 1);
    if (namePart) {
      names.add(namePart.trim());
    }
  }

  return names;
}

function parseUvLock(content: string | null, pyprojectContent: string | null): ResolvedDependency[] {
  if (!content) {
    return [];
  }

  const document = TOML.parse(content) as {
    package?: Array<{
      name?: string;
      version?: string;
      source?: { registry?: string; url?: string; path?: string };
    }>;
  };

  const topLevelNames = parsePyprojectDependencyNames(pyprojectContent);

  return (document.package ?? [])
    .filter((entry): entry is { name: string; version?: string; source?: { registry?: string; url?: string; path?: string } } => Boolean(entry.name))
    .map((entry) => {
      const sourceRef = entry.source?.url ?? entry.source?.path ?? entry.source?.registry;
      const sourceType = entry.source?.registry ? "registry" : classifySource(sourceRef);

      return {
        ecosystem: "pypi" as const,
        name: entry.name,
        version: entry.version ?? null,
        source_type: sourceType,
        manifest_path: "pyproject.toml",
        lockfile_path: "uv.lock",
        top_level: topLevelNames.has(entry.name),
        source_ref: sourceRef,
        registry_host: sourceType === "registry" ? extractRegistryHost(entry.source?.registry ?? "https://pypi.org/simple") ?? "pypi.org" : extractRegistryHost(sourceRef)
      };
    });
}

function makeSubjectKey(subject: ResolvedDependency): string {
  return [
    subject.ecosystem,
    subject.name,
    subject.version ?? "",
    subject.source_type,
    subject.top_level ? "top" : "transitive"
  ].join(":");
}

function diffSubjects(baseSubjects: ResolvedDependency[], headSubjects: ResolvedDependency[]): ResolvedDependency[] {
  const baseKeys = new Set(baseSubjects.map((subject) => makeSubjectKey(subject)));
  return headSubjects.filter((subject) => !baseKeys.has(makeSubjectKey(subject)));
}

async function readRepoFile(repoPath: string, relativePath: string): Promise<string | null> {
  return readFileIfExists(path.join(repoPath, relativePath));
}

function issueFromCode(code: string, ecosystem: "npm" | "pypi", fields: Partial<RepoIssue>): RepoIssue {
  const fallbackName =
    fields.manifest_path && fields.lockfile_path && fields.manifest_path !== fields.lockfile_path
      ? `${fields.manifest_path} -> ${fields.lockfile_path}`
      : fields.manifest_path ?? fields.lockfile_path ?? "<repo>";

  return {
    ecosystem,
    code,
    name: fields.name ?? fallbackName,
    source_type: fields.source_type ?? "unknown",
    summary: fields.summary ?? code,
    manifest_path: fields.manifest_path,
    lockfile_path: fields.lockfile_path
  };
}

export async function resolveRepoDiff(basePath: string, headPath: string): Promise<RepoScanResult> {
  const issues: RepoIssue[] = [];
  const unsupportedFiles: string[] = [];

  const packageJsonBase = await readRepoFile(basePath, "package.json");
  const packageJsonHead = await readRepoFile(headPath, "package.json");
  const packageLockBase = await readRepoFile(basePath, "package-lock.json");
  const packageLockHead = await readRepoFile(headPath, "package-lock.json");

  const requirementsBase = await readRepoFile(basePath, "requirements.txt");
  const requirementsHead = await readRepoFile(headPath, "requirements.txt");
  const uvLockBase = await readRepoFile(basePath, "uv.lock");
  const uvLockHead = await readRepoFile(headPath, "uv.lock");
  const pyprojectBase = await readRepoFile(basePath, "pyproject.toml");
  const pyprojectHead = await readRepoFile(headPath, "pyproject.toml");

  for (const deferredFile of DEFERRED_FILES) {
    const baseContent = await readRepoFile(basePath, deferredFile);
    const headContent = await readRepoFile(headPath, deferredFile);

    if ((baseContent !== null || headContent !== null) && !packageLockBase && !packageLockHead && !requirementsBase && !requirementsHead && !uvLockBase && !uvLockHead) {
      unsupportedFiles.push(deferredFile);
      issues.push(
        issueFromCode("UNSUPPORTED_PROJECT_FORMAT", deferredFile === "poetry.lock" ? "pypi" : "npm", {
          name: deferredFile,
          lockfile_path: deferredFile,
          summary: `OriginFence does not support ${deferredFile} in v1.`
        })
      );
    }
  }

  let npmSubjects: ResolvedDependency[] = [];

  if (packageJsonBase !== null || packageJsonHead !== null || packageLockBase !== null || packageLockHead !== null) {
    const packageJsonChanged = packageJsonBase !== packageJsonHead;
    const packageLockChanged = packageLockBase !== packageLockHead;

    if (packageJsonChanged && !packageLockChanged) {
      issues.push(
        issueFromCode("MANIFEST_LOCKFILE_OUT_OF_SYNC", "npm", {
          manifest_path: "package.json",
          lockfile_path: "package-lock.json",
          summary: "package.json changed without a matching package-lock.json update."
        })
      );
    } else if (packageLockBase !== null || packageLockHead !== null) {
      npmSubjects = diffSubjects(
        parseNpmLockSubjects(parsePackageLock(packageLockBase), parsePackageJson(packageJsonBase)),
        parseNpmLockSubjects(parsePackageLock(packageLockHead), parsePackageJson(packageJsonHead))
      );
    } else if (packageJsonHead !== null || packageJsonBase !== null) {
      unsupportedFiles.push("package.json");
      issues.push(
        issueFromCode("UNSUPPORTED_PROJECT_FORMAT", "npm", {
          name: "package.json",
          manifest_path: "package.json",
          summary: "package.json is present without package-lock.json, so OriginFence cannot evaluate exact npm resolutions."
        })
      );
    }
  }

  let pythonSubjects: ResolvedDependency[] = [];

  if (uvLockBase !== null || uvLockHead !== null) {
    const pyprojectChanged = pyprojectBase !== pyprojectHead;
    const uvLockChanged = uvLockBase !== uvLockHead;

    if (pyprojectChanged && !uvLockChanged) {
      issues.push(
        issueFromCode("MANIFEST_LOCKFILE_OUT_OF_SYNC", "pypi", {
          manifest_path: "pyproject.toml",
          lockfile_path: "uv.lock",
          summary: "pyproject.toml changed without a matching uv.lock update."
        })
      );
    } else {
      pythonSubjects = diffSubjects(parseUvLock(uvLockBase, pyprojectBase), parseUvLock(uvLockHead, pyprojectHead));
    }
  } else if (requirementsBase !== null || requirementsHead !== null) {
    pythonSubjects = diffSubjects(parseRequirements(requirementsBase), parseRequirements(requirementsHead));
  } else if (pyprojectBase !== null || pyprojectHead !== null) {
    unsupportedFiles.push("pyproject.toml");
    issues.push(
      issueFromCode("UNSUPPORTED_PROJECT_FORMAT", "pypi", {
        name: "pyproject.toml",
        manifest_path: "pyproject.toml",
        summary: "pyproject.toml is present without uv.lock or requirements.txt, so OriginFence cannot evaluate exact Python resolutions."
      })
    );
  }

  return {
    subjects: [...npmSubjects, ...pythonSubjects],
    issues,
    unsupported_files: unsupportedFiles
  };
}
