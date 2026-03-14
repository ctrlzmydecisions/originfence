import fs from "node:fs/promises";
import YAML from "yaml";

import { assertValidPolicy } from "./schema";
import type { Decision, Policy, ProvenanceRule } from "./types";
import { sha256 } from "./utils";

export const DEFAULT_POLICY: Policy = {
  version: 1,
  sources: {
    allow: ["registry.npmjs.org", "npmjs.org", "pypi.org", "files.pythonhosted.org"],
    deny_direct_urls: true
  },
  provenance: {
    npm: {
      require_for: [],
      missing_action: "review"
    },
    pypi: {
      require_for: [],
      missing_action: "review"
    }
  },
  malicious_packages: {
    action: "block"
  },
  soft_signals: {
    recent_package_age_days: 14,
    maintainer_set_change: "warn",
    publisher_identity_drift: "review"
  },
  waivers: {
    file: ".originfence/waivers.yaml"
  }
};

export interface LoadedPolicy {
  policy: Policy;
  source: string;
  checksum: string;
}

const decisionOrder: Decision[] = ["allow", "warn", "review", "block"];

function stricterDecision(left: Decision | undefined, right: Decision | undefined): Decision | undefined {
  if (!left) {
    return right;
  }

  if (!right) {
    return left;
  }

  return decisionOrder[Math.max(decisionOrder.indexOf(left), decisionOrder.indexOf(right))];
}

function stricterReviewOrBlock(
  left: "review" | "block" | undefined,
  right: "review" | "block" | undefined
): "review" | "block" {
  return stricterDecision(left, right) === "block" ? "block" : "review";
}

function stricterWarnReviewOrBlock(
  left: "warn" | "review" | "block" | undefined,
  right: "warn" | "review" | "block" | undefined,
  fallback: "warn" | "review" | "block"
): "warn" | "review" | "block" {
  const merged = stricterDecision(left, right);
  if (merged === "warn" || merged === "review" || merged === "block") {
    return merged;
  }

  return fallback;
}

function stricterWarnOrReview(
  left: "warn" | "review" | undefined,
  right: "warn" | "review" | undefined,
  fallback: "warn" | "review"
): "warn" | "review" {
  const merged = stricterDecision(left as Decision | undefined, right as Decision | undefined);
  if (merged === "warn" || merged === "review") {
    return merged;
  }

  return fallback;
}

function mergeStringArrays(left: string[] | undefined, right: string[] | undefined, mode: "intersection" | "union"): string[] | undefined {
  if (!left && !right) {
    return undefined;
  }

  if (!left) {
    return right;
  }

  if (!right) {
    return left;
  }

  if (mode === "intersection") {
    const set = new Set(right);
    return left.filter((item) => set.has(item));
  }

  return Array.from(new Set([...left, ...right]));
}

function mergeProvenanceRule(left: ProvenanceRule | undefined, right: ProvenanceRule | undefined): ProvenanceRule | undefined {
  if (!left && !right) {
    return undefined;
  }

  return {
    require_for: mergeStringArrays(left?.require_for, right?.require_for, "union") ?? [],
    missing_action: stricterReviewOrBlock(left?.missing_action, right?.missing_action)
  };
}

function mergePolicy(base: Policy, overlay: Policy): Policy {
  return {
    version: 1,
    sources: {
      allow: mergeStringArrays(base.sources?.allow, overlay.sources?.allow, "intersection") ?? [],
      deny_direct_urls: Boolean(base.sources?.deny_direct_urls) || Boolean(overlay.sources?.deny_direct_urls)
    },
    provenance: {
      npm: mergeProvenanceRule(base.provenance?.npm, overlay.provenance?.npm),
      pypi: mergeProvenanceRule(base.provenance?.pypi, overlay.provenance?.pypi)
    },
    malicious_packages: {
      action: stricterWarnReviewOrBlock(base.malicious_packages?.action, overlay.malicious_packages?.action, "block")
    },
    soft_signals: {
      recent_package_age_days: Math.min(
        base.soft_signals?.recent_package_age_days ?? Number.POSITIVE_INFINITY,
        overlay.soft_signals?.recent_package_age_days ?? Number.POSITIVE_INFINITY
      ),
      maintainer_set_change: stricterWarnOrReview(base.soft_signals?.maintainer_set_change, overlay.soft_signals?.maintainer_set_change, "warn"),
      publisher_identity_drift: stricterWarnOrReview(
        base.soft_signals?.publisher_identity_drift,
        overlay.soft_signals?.publisher_identity_drift,
        "review"
      )
    },
    waivers: {
      file: overlay.waivers?.file ?? base.waivers?.file
    }
  };
}

export async function loadPolicy(policyPath?: string, baselinePolicyPath?: string): Promise<LoadedPolicy> {
  let combinedPolicy = DEFAULT_POLICY;
  const sources = ["builtin:default"];

  if (baselinePolicyPath) {
    const baselineContent = await fs.readFile(baselinePolicyPath, "utf8");
    combinedPolicy = mergePolicy(combinedPolicy, assertValidPolicy(YAML.parse(baselineContent)));
    sources.push(baselinePolicyPath);
  }

  if (policyPath) {
    const policyContent = await fs.readFile(policyPath, "utf8");
    combinedPolicy = mergePolicy(combinedPolicy, assertValidPolicy(YAML.parse(policyContent)));
    sources.push(policyPath);
  }

  const normalized = JSON.stringify(combinedPolicy, null, 2);

  return {
    policy: combinedPolicy,
    source: sources.join(","),
    checksum: sha256(normalized)
  };
}
