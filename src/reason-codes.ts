import reasonCodesJson from "../schemas/reason-codes.v1.json";
import type { Decision, Severity } from "./types";

export interface ReasonDefinition {
  code: string;
  default_decision: Decision;
  severity: Severity;
  waivable: boolean;
  next_action_kind: string;
  next_action_summary: string;
}

export const reasonDefinitions: ReasonDefinition[] = reasonCodesJson as ReasonDefinition[];

const definitionsByCode = new Map(reasonDefinitions.map((definition) => [definition.code, definition]));

export function getReasonDefinition(code: string): ReasonDefinition {
  const definition = definitionsByCode.get(code);

  if (!definition) {
    throw new Error(`Unknown reason code: ${code}`);
  }

  return definition;
}
