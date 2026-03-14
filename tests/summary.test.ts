import assert from "node:assert/strict";
import test from "node:test";

import { renderGitHubJobSummary } from "../src/summary";
import type { DecisionReport } from "../src/types";

test("github job summary renders fuller evidence bullets for malicious hits", () => {
  const report: DecisionReport = {
    schema_version: "1",
    generated_at: "2026-03-14T18:00:00Z",
    tool_version: "0.1.0",
    status: "failure",
    decision: "block",
    summary: "fixture",
    counts: {
      changed_subjects: 1,
      allow: 0,
      warn: 0,
      review: 0,
      block: 1
    },
    paths: {
      base: "/tmp/base",
      head: "/tmp/head"
    },
    policy: {
      source: "builtin:default",
      checksum: "abc123"
    },
    results: [
      {
        schema_version: "1",
        subject: {
          ecosystem: "npm",
          name: "evil-pkg",
          version: "1.4.2",
          source_type: "registry",
          top_level: true,
          manifest_path: "package.json",
          lockfile_path: "package-lock.json"
        },
        base_decision: "block",
        effective_decision: "block",
        waived: false,
        summary: "fixture",
        reasons: [
          {
            code: "KNOWN_MALICIOUS",
            severity: "critical",
            decision: "block",
            message: "evil-pkg@1.4.2 matched a known malicious package entry.",
            evidence_refs: ["ev1"],
            waivable: false
          }
        ],
        evidence: [
          {
            id: "ev1",
            source: "malicious_packages_feed",
            kind: "feed_entry",
            ref: "local_override:npm:evil-pkg@*"
          },
          {
            id: "ev2",
            source: "npm_registry",
            kind: "registry_metadata",
            ref: "evil-pkg@1.4.2"
          }
        ],
        waivers_applied: [],
        next_action: {
          kind: "remove_dependency",
          summary: "Remove the dependency immediately."
        },
        evaluation_meta: {
          evaluated_at: "2026-03-14T18:00:00Z",
          tool_version: "0.1.0",
          hard_signal_state: "fresh",
          soft_signal_state: "fresh",
          stale_evidence_refs: []
        }
      }
    ]
  };

  const summary = renderGitHubJobSummary(report);

  assert.match(summary, /Evidence: Local override matched this package/);
  assert.match(summary, /Evidence: Reference: `local_override:npm:evil-pkg@\*`/);
  assert.match(summary, /Evidence: Registry metadata was fetched from npm registry metadata/);
});

test("github job summary surfaces observe-mode status and decision separately", () => {
  const report: DecisionReport = {
    schema_version: "1",
    generated_at: "2026-03-14T18:00:00Z",
    tool_version: "0.1.0",
    enforcement_mode: "observe",
    status: "success",
    decision: "review",
    summary: "fixture",
    counts: {
      changed_subjects: 1,
      allow: 0,
      warn: 0,
      review: 1,
      block: 0
    },
    paths: {
      base: "/tmp/base",
      head: "/tmp/head"
    },
    policy: {
      source: "builtin:default",
      checksum: "abc123"
    },
    results: []
  };

  const summary = renderGitHubJobSummary(report);

  assert.match(summary, /Status: `success`/);
  assert.match(summary, /Decision: `review`/);
  assert.match(summary, /Enforcement mode: observe/);
});
