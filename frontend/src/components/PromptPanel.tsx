import { AlertTriangle, Check, RotateCcw, Timer, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { currentControlProof } from "../api";
import { useAppDispatch, useAppSelector } from "../hooks";
import { answerPrompt, resyncExecution } from "../store";
import type { ActivePrompt } from "../types";
import { useActiveControlLease } from "../useControlLease";

function displayValue(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function sameValue(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (typeof left !== "object" || left === null || typeof right !== "object" || right === null) return false;
  return JSON.stringify(left) === JSON.stringify(right);
}

function initialOptionIndex(prompt: ActivePrompt): number {
  if (!prompt.options?.length) return -1;
  if (prompt.default_value !== undefined && prompt.option_values) {
    const match = prompt.option_values.findIndex((candidate) => sameValue(candidate, prompt.default_value));
    if (match >= 0) return match;
  }
  if (prompt.default_value !== undefined) {
    const match = prompt.options.indexOf(displayValue(prompt.default_value));
    if (match >= 0) return match;
  }
  return 0;
}

export function PromptPanel({ prompt }: { prompt: ActivePrompt }) {
  const dispatch = useAppDispatch();
  const pending = useAppSelector((state) => state.console.pendingAction);
  const connection = useAppSelector((state) => state.console.connection.phase);
  const execution = useAppSelector((state) => state.console.execution);
  const executionRevision = execution?.revision;
  const executionState = useAppSelector((state) => state.console.execution?.state);
  const [value, setValue] = useState(displayValue(prompt.default_value));
  const [selectedOption, setSelectedOption] = useState(() => initialOptionIndex(prompt));
  const [optionQuery, setOptionQuery] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);
  const [nowMs, setNowMs] = useState(Date.now);
  const refreshedBoundaries = useRef(new Set<string>());

  useEffect(() => {
    setValue(displayValue(prompt.default_value));
    setSelectedOption(initialOptionIndex(prompt));
    setOptionQuery("");
    setValidationError(null);
  }, [prompt.id, prompt.revision]);

  useEffect(() => {
    const boundaries = [
      ["warning", prompt.warning_at],
      ["deadline", prompt.deadline],
    ] as const;
    let nextBoundary = Number.POSITIVE_INFINITY;

    for (const [kind, timestamp] of boundaries) {
      if (!timestamp) continue;
      const boundaryMs = Date.parse(timestamp);
      if (!Number.isFinite(boundaryMs)) continue;
      if (boundaryMs > nowMs) {
        nextBoundary = Math.min(nextBoundary, boundaryMs);
        continue;
      }

      const key = `${prompt.id}:${prompt.revision}:${kind}:${timestamp}`;
      if (execution?.id && !refreshedBoundaries.current.has(key)) {
        refreshedBoundaries.current.add(key);
        void dispatch(resyncExecution(execution.id));
      }
    }

    if (!Number.isFinite(nextBoundary)) return;
    const delay = Math.min(Math.max(nextBoundary - Date.now() + 25, 25), 60_000);
    const timer = window.setTimeout(() => setNowMs(Date.now()), delay);
    return () => window.clearTimeout(timer);
  }, [dispatch, execution?.id, nowMs, prompt.deadline, prompt.id, prompt.revision, prompt.warning_at]);

  const validate = (): string | null => {
    if (prompt.options?.length) return selectedOption >= 0 ? null : "Select a response.";
    if (prompt.type === "number") {
      if (!/^[+-]?(?:\d+(?:\.\d+)?|\.\d+)$/.test(value) || !Number.isFinite(Number(value))) return "Enter a finite base-10 number.";
    } else if (prompt.type === "date") {
      const parsed = new Date(`${value}T00:00:00Z`);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value) return "Enter an unambiguous date in YYYY-MM-DD format.";
    } else if (!value.trim() || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) {
      return "Enter a nonempty value without control characters.";
    }
    return null;
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (executionRevision === undefined || !execution) return;
    const error = validate();
    setValidationError(error);
    if (error) return;
    const committedValue = selectedOption >= 0
      ? prompt.option_values && selectedOption < prompt.option_values.length
        ? prompt.option_values[selectedOption]
        : prompt.options?.[selectedOption]
      : value;
    void dispatch(answerPrompt({ promptId: prompt.id, action: "COMMIT", value: committedValue, revision: prompt.revision, proof: currentControlProof(execution.controller_lease) }));
  };

  const abort = () => {
    if (!execution) return;
    void dispatch(answerPrompt({ promptId: prompt.id, action: "ABORT", revision: prompt.revision, proof: currentControlProof(execution.controller_lease) }));
  };

  const canControl = useActiveControlLease(execution);
  const warningAtMs = prompt.warning_at ? Date.parse(prompt.warning_at) : Number.NaN;
  const deadlineMs = prompt.deadline ? Date.parse(prompt.deadline) : Number.NaN;
  const warningActive = prompt.warning_active || (Number.isFinite(warningAtMs) && nowMs >= warningAtMs);
  const deadlineReached = Number.isFinite(deadlineMs) && nowMs >= deadlineMs;

  const disabled =
    connection !== "CONNECTED" ||
    !["PROMPT", "PROMPTING"].includes(executionState ?? "") ||
    !canControl ||
    deadlineReached ||
    pending !== null ||
    executionRevision === undefined;
  const visibleOptions = (prompt.options ?? [])
    .map((option, index) => ({ option, index }))
    .filter(({ option }) => option.toLocaleLowerCase().includes(optionQuery.trim().toLocaleLowerCase()));
  const selectedOptionVisible = visibleOptions.some(({ index }) => index === selectedOption);
  const optionCountId = `prompt-${prompt.id}-option-count`;
  return (
    <section className="prompt-panel" aria-labelledby="prompt-title">
      <div className="prompt-icon"><AlertTriangle aria-hidden="true" size={20} /></div>
      <form onSubmit={submit}>
        <div className="prompt-heading">
          <div>
            <span className="eyebrow">Durable prompt - {prompt.prompt_type ?? prompt.type.toUpperCase()}</span>
            <h3 id="prompt-title">{prompt.message}</h3>
          </div>
          {prompt.deadline && (
            <span className="prompt-deadline">
              <Timer aria-hidden="true" size={14} /> {new Date(prompt.deadline).toLocaleTimeString()}
            </span>
          )}
        </div>
        <div className="prompt-metadata"><code>{prompt.id}</code><span>Revision {prompt.revision}</span>{prompt.default_value !== undefined && <span>Default: {displayValue(prompt.default_value)}</span>}</div>
        {prompt.options?.length ? (
          <>
          {prompt.options.length > 20 && (
            <label className="prompt-input">
              <span>Filter {prompt.options.length} examples</span>
              <input
                type="search"
                value={optionQuery}
                onChange={(event) => {
                  const query = event.target.value;
                  setOptionQuery(query);
                  const normalized = query.trim().toLocaleLowerCase();
                  if (normalized && selectedOption >= 0 && !prompt.options?.[selectedOption]?.toLocaleLowerCase().includes(normalized)) {
                    setSelectedOption(-1);
                  }
                }}
                placeholder="Example number or title"
                aria-describedby={optionCountId}
                disabled={disabled}
              />
            </label>
          )}
          {prompt.options.length > 20 && (
            <p className="prompt-option-count" id={optionCountId} role="status" aria-live="polite">
              Showing {visibleOptions.length} of {prompt.options.length} examples
            </p>
          )}
          <div className="prompt-options" role="radiogroup" aria-label="Prompt response" aria-describedby={prompt.options.length > 20 ? optionCountId : undefined}>
            {visibleOptions.map(({ option, index }) => (
              <label key={`${index}-${option}`}>
                <input
                  type="radio"
                  name={`prompt-${prompt.id}`}
                  value={index}
                  checked={selectedOption === index}
                  onChange={() => setSelectedOption(index)}
                  disabled={disabled}
                />
                <span>{option}</span>
              </label>
            ))}
            {visibleOptions.length === 0 && <p role="status">No matching examples.</p>}
          </div>
          </>
        ) : (
          <label className="prompt-input">
            <span>Response</span>
            <input
              type="text"
              inputMode={prompt.type === "number" ? "decimal" : prompt.type === "date" ? "numeric" : undefined}
              placeholder={prompt.type === "date" ? "YYYY-MM-DD" : undefined}
              value={value}
              onChange={(event) => setValue(event.target.value)}
              autoFocus
              disabled={disabled}
            />
          </label>
        )}
        {deadlineReached ? (
          <div className="prompt-warning" role="status"><Timer aria-hidden="true" size={14} /> Response deadline reached.</div>
        ) : warningActive ? (
          <div className="prompt-warning" role="status"><AlertTriangle aria-hidden="true" size={14} /> Response warning threshold reached.</div>
        ) : null}
        {validationError && <p className="prompt-validation" role="alert">{validationError}</p>}
        {!canControl && <p className="prompt-monitor-notice">Monitor mode is read-only. Acquire control to settle this prompt.</p>}
        <div className="prompt-actions">
          <button className="toolbar-command" type="button" onClick={() => { setValue(displayValue(prompt.default_value)); setSelectedOption(initialOptionIndex(prompt)); setOptionQuery(""); setValidationError(null); }} disabled={pending !== null}><RotateCcw aria-hidden="true" size={15} /> Reset draft</button>
          <button className="danger-command" type="button" onClick={abort} disabled={disabled}><X aria-hidden="true" size={15} /> Abort prompt</button>
          <button className="prompt-submit" type="submit" disabled={disabled || (prompt.options?.length ? !selectedOptionVisible : !value)}><Check aria-hidden="true" size={17} /> Commit response</button>
        </div>
      </form>
    </section>
  );
}
