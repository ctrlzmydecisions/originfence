import YAML from "yaml";

import type { Policy } from "./types";

export type PolicyPresetName = "balanced" | "strict" | "observe";

const presetDescriptions: Record<PolicyPresetName, string> = {
  balanced: "Recommended starting point for most repositories.",
  strict: "Stricter rollout with provenance required for all supported registry packages and stronger soft-signal review.",
  observe: "Safe initial rollout preset. Pair this with enforcement-mode: observe in the workflow until the repo is tuned."
};

const presetPolicies: Record<PolicyPresetName, Policy> = {
  balanced: {
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
  },
  strict: {
    version: 1,
    sources: {
      allow: ["registry.npmjs.org", "npmjs.org", "pypi.org", "files.pythonhosted.org"],
      deny_direct_urls: true
    },
    provenance: {
      npm: {
        require_for: ["*"],
        missing_action: "block"
      },
      pypi: {
        require_for: ["*"],
        missing_action: "block"
      }
    },
    malicious_packages: {
      action: "block"
    },
    soft_signals: {
      recent_package_age_days: 7,
      maintainer_set_change: "review",
      publisher_identity_drift: "review"
    },
    waivers: {
      file: ".originfence/waivers.yaml"
    }
  },
  observe: {
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
  }
};

export function listPolicyPresetNames(): PolicyPresetName[] {
  return ["balanced", "strict", "observe"];
}

export function getPolicyPresetDescription(name: PolicyPresetName): string {
  return presetDescriptions[name];
}

export function getPolicyPreset(name: PolicyPresetName): Policy {
  return presetPolicies[name];
}

export function renderPolicyPreset(name: PolicyPresetName): string {
  const description = getPolicyPresetDescription(name);
  const lines = [
    `# OriginFence preset: ${name}`,
    `# ${description}`
  ];

  if (name === "observe") {
    lines.push("# Recommended workflow input during initial rollout: enforcement-mode: observe");
  }

  lines.push("");
  lines.push(YAML.stringify(getPolicyPreset(name)).trimEnd());
  lines.push("");
  return lines.join("\n");
}

export function renderWaiversTemplate(): string {
  return [
    "# OriginFence waivers template",
    "# Add explicit, time-bounded exceptions here when policy allows.",
    "",
    "version: 1",
    "waivers: []",
    ""
  ].join("\n");
}
