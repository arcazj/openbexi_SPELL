import type { ExecutionSnapshot } from "../types";

export interface LineObservation { item: string; value: string; result: string }

/** Display only explicit, line-correlated notifications; traversal is not success. */
export function lineObservations(execution: ExecutionSnapshot): Map<number, LineObservation> {
  const result = new Map<number, LineObservation>();
  const requests = new Map<string, Record<string, unknown>>();
  const text = (value: unknown) => value == null ? "" : typeof value === "object" ? JSON.stringify(value) : String(value);
  for (const event of [...execution.events].sort((a, b) => a.sequence - b.sequence)) {
    if (event.execution_id !== execution.id) continue;
    if (event.event_type === "procedure.observation_requested" && typeof event.payload.request_id === "string") {
      requests.set(event.payload.request_id, event.payload);
      continue;
    }
    if (event.event_type === "procedure.observation_result") {
      const data = event.payload;
      const request = typeof data.request_id === "string" ? requests.get(data.request_id) : undefined;
      const index = data.step_index;
      if (!request || request.step_index !== index || request.operation !== data.operation
        || typeof index !== "number" || !Number.isInteger(index) || index < 0) continue;
      const line = execution.steps[index]?.line;
      if (!line || !Number.isInteger(line) || line < 1) continue;
      const parameters = request.parameters as Record<string, unknown> | undefined;
      const value = data.value && typeof data.value === "object" && "value" in data.value
        ? (data.value as Record<string, unknown>).value : data.value;
      result.set(line, { item: text(parameters?.item_id ?? data.operation), value: text(value), result: text(data.outcome) });
      continue;
    }
    const line = event.payload.line;
    if (event.execution_id !== execution.id || typeof line !== "number" || !Number.isInteger(line) || line < 1) continue;
    const data = event.payload;
    const item = text(data.parameter ?? data.item_id ?? data.command_name);
    const value = text(data.value);
    const outcome = text(data.outcome ?? data.quality ?? data.status);
    if (!item && !value && !outcome) continue;
    result.set(line, { item, value, result: outcome });
  }
  return result;
}

/** Cosmetic tokenization only: source remains escaped React text, never evaluated. */
export function HighlightedSource({ text }: { text: string }) {
  const tokens = text.split(/(#.*$|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|\b(?:if|else|elif|for|in|while|def|return|True|False|None|and|or|not|break|continue)\b)/g);
  return <>{tokens.map((token, index) => <span key={index} className={token.startsWith("#") ? "syntax-comment"
    : /^["']/.test(token) ? "syntax-string" : /^(if|else|elif|for|in|while|def|return|True|False|None|and|or|not|break|continue)$/.test(token) ? "syntax-keyword" : undefined}>{token}</span>)}</>;
}
