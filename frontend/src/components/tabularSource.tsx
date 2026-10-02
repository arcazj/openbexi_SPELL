import type { ExecutionSnapshot } from "../types";

export interface LineObservation { item: string; value: string; result: string }

/** Display only explicit, line-correlated notifications; traversal is not success. */
export function lineObservations(execution: ExecutionSnapshot): Map<number, LineObservation> {
  const result = new Map<number, LineObservation>();
  const text = (value: unknown) => value == null ? "" : typeof value === "object" ? JSON.stringify(value) : String(value);
  for (const event of [...execution.events].sort((a, b) => a.sequence - b.sequence)) {
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
