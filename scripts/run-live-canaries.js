#!/usr/bin/env node

const fs = require("node:fs/promises");
const path = require("node:path");

const { CompositeMetadataFetcher } = require("../dist/src/fetchers.js");
const { loadMaliciousPackageFeed } = require("../dist/src/malicious-intel.js");

async function writeGitHubStepSummary(lines) {
  if (!process.env.GITHUB_STEP_SUMMARY) {
    return;
  }

  await fs.appendFile(process.env.GITHUB_STEP_SUMMARY, `${lines.join("\n")}\n`, "utf8");
}

function subjectRef(subject) {
  return `${subject.ecosystem}:${subject.name}@${subject.version}`;
}

async function main() {
  const tempRoot = path.resolve(process.cwd(), ".tmp", "live-canaries");
  await fs.mkdir(tempRoot, { recursive: true });
  const cacheDir = await fs.mkdtemp(path.join(tempRoot, "run-"));
  const now = new Date().toISOString();

  try {
    const maliciousFeed = await loadMaliciousPackageFeed({
      cacheDir,
      refreshCache: true
    });

    const fetcher = new CompositeMetadataFetcher(maliciousFeed, {
      cacheDir,
      refreshCache: true
    });

    const subjects = [
      {
        ecosystem: "npm",
        name: "lodash",
        version: "4.17.21",
        source_type: "registry",
        top_level: true,
        manifest_path: "package.json",
        lockfile_path: "package-lock.json",
        registry_host: "registry.npmjs.org"
      },
      {
        ecosystem: "pypi",
        name: "requests",
        version: "2.32.3",
        source_type: "registry",
        top_level: true,
        manifest_path: "requirements.txt",
        lockfile_path: "requirements.txt",
        registry_host: "pypi.org"
      }
    ];

    const summaryLines = ["## OriginFence Live Canaries", ""];

    for (const subject of subjects) {
      const result = await fetcher.fetch(subject, { now });
      const diagnostics = result.diagnostics.filter((entry) => entry.level === "error");
      const registryHost = result.evidence.registry?.registry_host;
      const publishedAt = result.evidence.registry?.published_at;
      const hardSignalAvailable = result.evidence.availability?.hard_signal_source_available !== false;
      const maliciousMatch = result.evidence.malicious?.matched === true;

      if (diagnostics.length > 0) {
        throw new Error(`${subjectRef(subject)} returned error diagnostics: ${diagnostics.map((entry) => entry.code).join(", ")}`);
      }

      if (!registryHost || !publishedAt) {
        throw new Error(`${subjectRef(subject)} is missing required registry metadata`);
      }

      if (!hardSignalAvailable) {
        throw new Error(`${subjectRef(subject)} could not obtain fresh hard-signal evidence`);
      }

      if (maliciousMatch) {
        throw new Error(`${subjectRef(subject)} unexpectedly matched malicious-package intelligence`);
      }

      summaryLines.push(`- \`${subjectRef(subject)}\`: registry metadata ok, malicious-intel adapters reachable, no malicious match`);
    }

    await writeGitHubStepSummary(summaryLines);
    process.stdout.write(`${summaryLines.join("\n")}\n`);
  } finally {
    await fs.rm(cacheDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
