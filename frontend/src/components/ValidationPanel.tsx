import {
  AlertCircle,
  CheckCircle2,
  FileSearch,
  LoaderCircle,
  X,
  XCircle,
} from "lucide-react";
import { useAppDispatch, useAppSelector } from "../hooks";
import { clearValidation } from "../store";
import type { ValidationStep } from "../types";

function stepArguments(step: ValidationStep): string {
  const entries = Object.entries(step).filter(
    ([key]) => !["index", "line", "type"].includes(key),
  );
  return entries.length ? JSON.stringify(Object.fromEntries(entries)) : "None";
}

function variableEntries(value: unknown[] | Record<string, unknown>): Array<[string, string]> {
  if (Array.isArray(value)) {
    return value.map((item, index) => {
      if (typeof item === "string") return [item, "Declared"];
      if (typeof item === "object" && item !== null) {
        const record = item as Record<string, unknown>;
        return [String(record.name ?? index + 1), JSON.stringify(record)];
      }
      return [String(index + 1), String(item)];
    });
  }
  return Object.entries(value).map(([name, detail]) => [
    name,
    typeof detail === "string" ? detail : JSON.stringify(detail),
  ]);
}

export function ValidationPanel() {
  const dispatch = useAppDispatch();
  const { validation, procedures } = useAppSelector((state) => state.console);
  if (validation.status === "idle") return null;

  const procedure = procedures.find((item) => item.id === validation.procedureId);
  const result = validation.result;
  const variables = result ? variableEntries(result.variables) : [];
  const status =
    validation.status === "pending"
      ? "VALIDATING"
      : validation.status === "failed"
        ? "FAILED"
        : result?.valid
          ? "VALID"
          : "INVALID";

  return (
    <section
      id="validation-panel"
      className="validation-panel"
      aria-labelledby="validation-title"
      tabIndex={-1}
    >
      <header className="validation-header">
        <div className="validation-title">
          <FileSearch aria-hidden="true" size={20} />
          <div>
            <span className="eyebrow">Restricted source analysis</span>
            <h2 id="validation-title">{procedure?.name ?? "Procedure"} validation</h2>
          </div>
        </div>
        <div className="validation-header-actions">
          <span className={`validation-status ${status.toLowerCase()}`} role="status" aria-live="polite">
            {validation.status === "pending" ? (
              <LoaderCircle className="spin" aria-hidden="true" size={14} />
            ) : result?.valid ? (
              <CheckCircle2 aria-hidden="true" size={14} />
            ) : (
              <XCircle aria-hidden="true" size={14} />
            )}
            {status}
          </span>
          <button
            type="button"
            className="icon-command"
            aria-label="Close validation result"
            title="Close validation result"
            onClick={() => dispatch(clearValidation())}
          >
            <X aria-hidden="true" size={16} />
          </button>
        </div>
      </header>

      {validation.status === "pending" && (
        <div className="validation-progress">
          <LoaderCircle className="spin" aria-hidden="true" size={18} />
          <span>Validating selected source without creating an execution.</span>
        </div>
      )}

      {validation.status === "failed" && (
        <div className="validation-failure" role="alert">
          <AlertCircle aria-hidden="true" size={18} />
          <div>
            <strong>Validation request failed</strong>
            <span>{validation.error}</span>
          </div>
        </div>
      )}

      {validation.status === "complete" && result && (
        <div className="validation-results">
          <dl className="validation-summary">
            <div><dt>Subset</dt><dd>{result.subset_version}</dd></div>
            <div>
              <dt>Source hash</dt>
              <dd>
                <code title={result.sha256 ?? "No canonical UTF-8 source hash"}>
                  {result.sha256 ?? "Unavailable"}
                </code>
              </dd>
            </div>
            <div><dt>IR steps</dt><dd>{result.steps.length}</dd></div>
            <div><dt>Variables</dt><dd>{variables.length}</dd></div>
          </dl>

          <div className="validation-detail-grid">
            <section aria-labelledby="diagnostics-title">
              <div className="validation-section-title">
                <h3 id="diagnostics-title">Diagnostics</h3>
                <span>{result.diagnostics.length}</span>
              </div>
              {result.diagnostics.length ? (
                <ul className="diagnostic-list">
                  {result.diagnostics.map((diagnostic, index) => (
                    <li key={`${diagnostic.code ?? "diagnostic"}-${index}`}>
                      <div>
                        <strong>{(diagnostic.severity ?? "error").toUpperCase()}</strong>
                        {diagnostic.code && <code>{diagnostic.code}</code>}
                        {(diagnostic.line != null || diagnostic.column != null) && (
                          <span>Line {diagnostic.line ?? "?"}, column {diagnostic.column ?? "?"}</span>
                        )}
                      </div>
                      <p>{diagnostic.message}</p>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="validation-empty">No diagnostics returned.</p>
              )}
            </section>

            <section aria-labelledby="variables-title">
              <div className="validation-section-title">
                <h3 id="variables-title">Variables</h3>
                <span>{variables.length}</span>
              </div>
              {variables.length ? (
                <dl
                  className="validation-variables"
                  tabIndex={0}
                  aria-label="Scrollable validated variables"
                >
                  {variables.map(([name, detail]) => (
                    <div key={name}><dt>{name}</dt><dd>{detail}</dd></div>
                  ))}
                </dl>
              ) : (
                <p className="validation-empty">No variables declared.</p>
              )}
            </section>
          </div>

          <section className="validation-ir" aria-labelledby="ir-title">
            <div className="validation-section-title">
              <h3 id="ir-title">Validated IR</h3>
              <span>Read-only</span>
            </div>
            <div className="table-scroll" tabIndex={0} aria-label="Scrollable validated IR">
              <table>
                <caption className="sr-only">Validated intermediate representation steps</caption>
                <thead><tr><th>#</th><th>Line</th><th>Operation</th><th>Arguments</th></tr></thead>
                <tbody>
                  {result.steps.map((step, index) => (
                    <tr key={`${step.index ?? index}-${step.line ?? "line"}`}>
                      <td>{Number(step.index ?? index) + 1}</td>
                      <td>{String(step.line ?? "-")}</td>
                      <td><code>{String(step.type ?? "step")}</code></td>
                      <td className="validation-arguments"><code>{stepArguments(step)}</code></td>
                    </tr>
                  ))}
                  {!result.steps.length && (
                    <tr><td colSpan={4}>No IR steps were produced.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
