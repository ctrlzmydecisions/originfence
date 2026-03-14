import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { renderPullRequestComment, renderResolvedPullRequestComment, syncStickyPullRequestComment } from "../src/pr-comment";
import type { DecisionReport } from "../src/types";

function makeReport(status: DecisionReport["status"], decision: DecisionReport["decision"]): DecisionReport {
  const isAllow = decision === "allow";
  const effectiveDecision = decision === "warn" ? "warn" : "review";

  return {
    schema_version: "1",
    generated_at: "2026-03-13T12:00:00Z",
    tool_version: "0.1.0",
    status,
    decision,
    summary: "fixture",
    counts: {
      changed_subjects: 1,
      allow: isAllow ? 1 : 0,
      warn: decision === "warn" ? 1 : 0,
      review: decision === "review" ? 1 : 0,
      block: decision === "block" ? 1 : 0
    },
    paths: {
      base: "/tmp/base",
      head: "/tmp/head"
    },
    policy: {
      source: "builtin:default",
      checksum: "abc123"
    },
    results: isAllow ? [] : [
      {
        schema_version: "1",
        subject: {
          ecosystem: "pypi",
          name: "internal-tooling-lib",
          version: "1.0.0",
          source_type: "direct_url",
          top_level: true,
          manifest_path: "requirements.txt",
          lockfile_path: "requirements.txt"
        },
        base_decision: effectiveDecision,
        effective_decision: effectiveDecision,
        waived: false,
        summary: "fixture",
        reasons: [
          {
            code: "DIRECT_URL_SOURCE",
            severity: "high",
            decision: "review",
            message: "Dependency is introduced from a direct URL instead of an approved registry.",
            evidence_refs: ["ev1"],
            waivable: true
          }
        ],
        evidence: [
          {
            id: "ev1",
            source: "resolver",
            kind: "policy_rule",
            ref: "requirements.txt"
          }
        ],
        waivers_applied: [],
        next_action: {
          kind: "move_to_registry",
          summary: "Move the dependency to an approved registry or justify the exception."
        },
        evaluation_meta: {
          evaluated_at: "2026-03-13T12:00:00Z",
          tool_version: "0.1.0",
          hard_signal_state: "fresh",
          soft_signal_state: "fresh",
          stale_evidence_refs: []
        }
      }
    ]
  };
}

async function startCommentServer(): Promise<{ apiUrl: string; comments: Array<{ id: number; body: string }>; close(): Promise<void> }> {
  const comments: Array<{ id: number; body: string }> = [];
  let nextId = 1;

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const chunks: Buffer[] = [];

    for await (const chunk of request) {
      chunks.push(Buffer.from(chunk));
    }

    const payload = chunks.length > 0 ? (JSON.parse(Buffer.concat(chunks).toString("utf8")) as { body?: string }) : {};

    if (request.method === "GET" && url.pathname === "/repos/test-owner/test-repo/issues/123/comments") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(comments));
      return;
    }

    if (request.method === "POST" && url.pathname === "/repos/test-owner/test-repo/issues/123/comments") {
      const created = {
        id: nextId++,
        body: payload.body ?? ""
      };
      comments.push(created);
      response.writeHead(201, { "content-type": "application/json" });
      response.end(JSON.stringify(created));
      return;
    }

    const patchMatch = url.pathname.match(/^\/repos\/test-owner\/test-repo\/issues\/comments\/(?<id>\d+)$/u);
    const patchId = patchMatch?.groups?.id;
    if (request.method === "PATCH" && patchId) {
      const existing = comments.find((comment) => comment.id === Number(patchId));

      if (!existing) {
        response.writeHead(404, { "content-type": "application/json" });
        response.end(JSON.stringify({ message: "not found" }));
        return;
      }

      existing.body = payload.body ?? existing.body;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(existing));
      return;
    }

    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ message: "not found" }));
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();

  if (!address || typeof address === "string") {
    throw new Error("Unable to resolve comment server address");
  }

  return {
    apiUrl: `http://127.0.0.1:${address.port}`,
    comments,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    }
  };
}

test("sticky PR comments create once and then update in place", async () => {
  const server = await startCommentServer();

  try {
    const failingReport = makeReport("failure", "review");
    const failingBody = renderPullRequestComment(failingReport, {
      mode: "review_and_block",
      runUrl: "https://github.com/test-owner/test-repo/actions/runs/101"
    });

    assert.ok(failingBody);

    const created = await syncStickyPullRequestComment({
      apiUrl: server.apiUrl,
      owner: "test-owner",
      repo: "test-repo",
      issueNumber: 123,
      token: "test-token"
    }, failingBody ?? "");

    assert.equal(created.action, "created");
    assert.equal(server.comments.length, 1);
    assert.match(server.comments[0]?.body ?? "", /DIRECT_URL_SOURCE/);

    const resolved = await syncStickyPullRequestComment({
      apiUrl: server.apiUrl,
      owner: "test-owner",
      repo: "test-repo",
      issueNumber: 123,
      token: "test-token"
    }, renderResolvedPullRequestComment(makeReport("neutral", "neutral"), {
      mode: "review_and_block",
      runUrl: "https://github.com/test-owner/test-repo/actions/runs/102"
    }), { allowCreate: false });

    assert.equal(resolved.action, "updated");
    assert.equal(server.comments.length, 1);
    assert.match(server.comments[0]?.body ?? "", /No review-required or blocked dependency trust outcomes remain/);
  } finally {
    await server.close();
  }
});

test("pull request comments render operator-facing evaluation failures without subject results", () => {
  const report: DecisionReport = {
    schema_version: "1",
    generated_at: "2026-03-14T13:00:00Z",
    tool_version: "0.1.0",
    status: "failure",
    decision: "neutral",
    summary: "Policy validation failed: /version must be equal to constant",
    counts: {
      changed_subjects: 0,
      allow: 0,
      warn: 0,
      review: 0,
      block: 0
    },
    paths: {
      base: "/tmp/base",
      head: "/tmp/head"
    },
    policy: {
      source: "builtin:default,/tmp/head/.originfence/policy.yaml",
      checksum: "abc123"
    },
    diagnostics: [
      {
        level: "error",
        source: "config",
        code: "EVALUATION_FAILED",
        message: "Policy validation failed: /version must be equal to constant"
      }
    ],
    results: []
  };

  const body = renderPullRequestComment(report, {
    mode: "review_and_block",
    runUrl: "https://github.com/test-owner/test-repo/actions/runs/103"
  });

  assert.ok(body);
  assert.match(body ?? "", /Evaluation failure/);
  assert.match(body ?? "", /Policy validation failed/);
});

test("pull request comments add evidence context and a false-positive path", () => {
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
          ecosystem: "pypi",
          name: "requests",
          version: "2.32.5",
          source_type: "registry",
          top_level: true,
          manifest_path: "requirements.txt",
          lockfile_path: "requirements.txt"
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
            message: "requests@2.32.5 matched a known malicious package entry.",
            evidence_refs: ["ev1"],
            waivable: false
          }
        ],
        evidence: [
          {
            id: "ev1",
            source: "malicious_packages_feed",
            kind: "feed_entry",
            ref: "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/pypi/requests/MAL-2026-1111.json"
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

  const body = renderPullRequestComment(report, {
    mode: "review_and_block",
    runUrl: "https://github.com/test-owner/test-repo/actions/runs/104"
  });

  assert.ok(body);
  assert.match(body ?? "", /Evidence: OpenSSF malicious-packages via OSV matched this exact version/);
  assert.match(body ?? "", /If this looks wrong:/);
  assert.match(body ?? "", /These reasons are not waivable/);
});

test("pull request comments show observe-mode status without hiding the underlying decision", () => {
  const body = renderPullRequestComment({
    ...makeReport("success", "review"),
    enforcement_mode: "observe"
  }, {
    mode: "review_and_block",
    runUrl: "https://github.com/test-owner/test-repo/actions/runs/104"
  });

  assert.ok(body);
  assert.match(body ?? "", /Status: `success`/);
  assert.match(body ?? "", /Decision: `review`/);
  assert.match(body ?? "", /Enforcement mode: `observe`/);
});
