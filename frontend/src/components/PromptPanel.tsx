import { AlertTriangle, Check, Timer } from "lucide-react";
import { useEffect, useState } from "react";
import { useAppDispatch, useAppSelector } from "../hooks";
import { answerPrompt } from "../store";
import type { ActivePrompt } from "../types";

export function PromptPanel({ prompt }: { prompt: ActivePrompt }) {
  const dispatch = useAppDispatch();
  const pending = useAppSelector((state) => state.console.pendingAction);
  const connection = useAppSelector((state) => state.console.connection.phase);
  const executionRevision = useAppSelector((state) => state.console.execution?.revision);
  const executionState = useAppSelector((state) => state.console.execution?.state);
  const [value, setValue] = useState(prompt.default_value ?? prompt.options?.[0] ?? "");

  useEffect(() => {
    setValue(prompt.default_value ?? prompt.options?.[0] ?? "");
  }, [prompt]);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!value && prompt.type !== "confirm") return;
    if (executionRevision === undefined) return;
    void dispatch(answerPrompt({ promptId: prompt.id, value, revision: executionRevision }));
  };

  const disabled =
    connection !== "CONNECTED" ||
    executionState !== "PROMPTING" ||
    pending !== null ||
    executionRevision === undefined;
  return (
    <section className="prompt-panel" aria-labelledby="prompt-title">
      <div className="prompt-icon"><AlertTriangle aria-hidden="true" size={20} /></div>
      <form onSubmit={submit}>
        <div className="prompt-heading">
          <div>
            <span className="eyebrow">Operator action required</span>
            <h3 id="prompt-title">{prompt.message}</h3>
          </div>
          {prompt.deadline && (
            <span className="prompt-deadline">
              <Timer aria-hidden="true" size={14} /> {new Date(prompt.deadline).toLocaleTimeString()}
            </span>
          )}
        </div>
        {prompt.options?.length ? (
          <div className="prompt-options" role="radiogroup" aria-label="Prompt response">
            {prompt.options.map((option) => (
              <label key={option}>
                <input
                  type="radio"
                  name={`prompt-${prompt.id}`}
                  value={option}
                  checked={value === option}
                  onChange={(event) => setValue(event.target.value)}
                  disabled={disabled}
                />
                <span>{option}</span>
              </label>
            ))}
          </div>
        ) : (
          <label className="prompt-input">
            <span>Response</span>
            <input
              type={prompt.type === "number" ? "number" : "text"}
              value={value}
              onChange={(event) => setValue(event.target.value)}
              autoFocus
              disabled={disabled}
            />
          </label>
        )}
        <button className="prompt-submit" type="submit" disabled={disabled || !value}>
          <Check aria-hidden="true" size={17} /> Commit response
        </button>
      </form>
    </section>
  );
}
