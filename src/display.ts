import type { Subject, SubjectResult } from "./types";

const DECISION_RANK: Record<SubjectResult["effective_decision"], number> = {
  block: 0,
  review: 1,
  warn: 2,
  allow: 3
};

export function formatSubjectDisplay(subject: Pick<Subject, "name" | "version" | "manifest_path" | "lockfile_path">): string {
  if (subject.name === "<repo>") {
    if (subject.manifest_path && subject.lockfile_path && subject.manifest_path !== subject.lockfile_path) {
      return `${subject.manifest_path} -> ${subject.lockfile_path}`;
    }

    return subject.manifest_path ?? subject.lockfile_path ?? subject.name;
  }

  return subject.version ? `${subject.name}@${subject.version}` : subject.name;
}

export function sortSubjectResults(results: SubjectResult[]): SubjectResult[] {
  return [...results].sort((left, right) => {
    const leftRank = DECISION_RANK[left.effective_decision] ?? 99;
    const rightRank = DECISION_RANK[right.effective_decision] ?? 99;

    if (leftRank !== rightRank) {
      return leftRank - rightRank;
    }

    return formatSubjectDisplay(left.subject).localeCompare(formatSubjectDisplay(right.subject));
  });
}

export function formatAppliedWaiverDisplay(result: Pick<SubjectResult, "waivers_applied" | "waived_from">): string | null {
  const waiver = result.waivers_applied[0];

  if (!waiver) {
    return null;
  }

  const fromDecision = result.waived_from ? ` from ${result.waived_from}` : "";
  return `${waiver.id} (${waiver.owner}) until ${waiver.expires_at}${fromDecision}`;
}
