import {
  AlertOctagon,
  FileClock,
  LoaderCircle,
  Pause,
  Play,
  RefreshCcw,
  RotateCcw,
  Skull,
  Square,
} from "lucide-react";
import { useState } from "react";
import { createPortal } from "react-dom";
import { useAppDispatch, useAppSelector } from "../hooks";
import { loadReport, resyncExecution, sendExecutionCommand } from "../store";
import type { ExecutionSnapshot } from "../types";
import { ProcedureFlow } from "./ProcedureFlow";
import { PromptPanel } from "./PromptPanel";
import { ValidationPanel } from "./ValidationPanel";

const TERMINAL_STATES = new Set(["ABORTED", "FAILED", "COMPLETED"]);

function stateTone(state: ExecutionSnapshot["state"]): string {
  if (state === "RUNNING") return "running";
  if (state === "PAUSED" || state === "WAITING" || state === "PROMPTING") return "attention";
  if (state === "FAILED" || state === "ABORTED" || state === "RECOVERY_REQUIRED") return "danger";
  if (state === "COMPLETED") return "complete";
  return "neutral";
}

function CommandButton({
  icon,
  label,
  command,
  disabled,
  dangerous = false,
}: {
  icon: React.ReactNode;
  label: string;
  command: string;
  disabled: boolean;
  dangerous?: boolean;
}) {
  const dispatch = useAppDispatch();
  const execution = useAppSelector((state) => state.console.execution);
  const send = () => {
    if (!execution) return;
    void dispatch(
      sendExecutionCommand({
        executionId: execution.id,
        command,
        revision: execution.revision,
        reason: `${label} requested by console operator`,
      }),
    );
  };
  return (
    <button
      type="button"
      className={dangerous ? "danger-command" : "toolbar-command"}
      onClick={send}
      disabled={disabled}
      title={label}
    >
      {icon}<span>{label}</span>
    </button>
  );
}

function AbortDialog({ execution }: { execution: ExecutionSnapshot }) {
  const dispatch = useAppDispatch();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const pending = useAppSelector((state) => state.console.pendingAction !== null);
  const connected = useAppSelector((state) => state.console.connection.phase === "CONNECTED");

  const abort = (event: React.FormEvent) => {
    event.preventDefault();
    if (!reason.trim() || !connected) return;
    void dispatch(
      sendExecutionCommand({
        executionId: execution.id,
        command: "ABORT",
        revision: execution.revision,
        reason: reason.trim(),
      }),
    ).then(() => setOpen(false));
  };

  return (
    <>
      <button
        type="button"
        className="danger-command"
        aria-label="Abort"
        title="Abort execution"
        onClick={() => setOpen(true)}
        disabled={!connected || pending || TERMINAL_STATES.has(execution.state)}
      >
        <Square aria-hidden="true" size={15} fill="currentColor" /> <span>Abort</span>
      </button>
      {open && createPortal(
        <div className="abort-backdrop" onKeyDown={(event) => event.key === "Escape" && setOpen(false)}>
          <section
            className="abort-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="abort-dialog-title"
          >
            <form onSubmit={abort}>
              <div className="dialog-title">
                <AlertOctagon aria-hidden="true" size={24} />
                <div>
                  <span className="eyebrow">Irreversible control</span>
                  <h2 id="abort-dialog-title">Abort execution?</h2>
                </div>
              </div>
              <p>Execution <strong>{execution.id}</strong> will enter its abort sequence. State changes remain auditable.</p>
              <label>
                Operational reason
                <textarea
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  rows={3}
                  required
                  autoFocus
                />
              </label>
              <div className="dialog-actions">
                <button type="button" onClick={() => setOpen(false)}>Cancel</button>
                <button type="submit" className="confirm-abort" disabled={!connected || !reason.trim() || pending}>
                  Confirm abort
                </button>
              </div>
            </form>
          </section>
        </div>,
        document.body,
      )}
    </>
  );
}

export function ExecutionWorkspace() {
  const dispatch = useAppDispatch();
  const { execution, connection, pendingAction, validation } = useAppSelector((state) => state.console);

  if (!execution) {
    if (validation.status !== "idle") {
      return (
        <main className="empty-workspace validation-workspace">
          <ValidationPanel />
        </main>
      );
    }
    return (
      <main className="empty-workspace">
        <div className="empty-mark"><FileClock aria-hidden="true" size={32} /></div>
        <h1>No active execution</h1>
        <p>Select a simulator procedure from the catalog to create an auditable execution.</p>
        <dl>
          <div><dt>Control channel</dt><dd>{connection.phase}</dd></div>
          <div><dt>Environment</dt><dd>Simulator only</dd></div>
        </dl>
      </main>
    );
  }

  const stale = connection.phase !== "CONNECTED";
  const pending = pendingAction !== null;
  const currentStep = execution.steps.find((step) => step.id === execution.current_step_id);
  const sourceLines = execution.source?.split("\n") ?? execution.steps.map((step) => step.source ?? step.label);

  return (
    <main className="execution-workspace">
      <div className="execution-titlebar">
        <div>
          <span className="eyebrow">Execution {execution.id}</span>
          <h1>{execution.procedure_name}</h1>
        </div>
        <div className="execution-metadata">
          <span className={`state-pill ${stateTone(execution.state)}`}>{execution.state}</span>
          <span>Rev {execution.revision}</span>
          <span>Seq {execution.last_sequence}</span>
        </div>
      </div>

      <div className="command-toolbar" aria-label="Execution controls">
        <CommandButton
          icon={<Pause aria-hidden="true" size={15} fill="currentColor" />}
          label="Pause"
          command="PAUSE"
          disabled={stale || pending || execution.state !== "RUNNING"}
        />
        <CommandButton
          icon={<Play aria-hidden="true" size={15} fill="currentColor" />}
          label="Resume"
          command="RESUME"
          disabled={stale || pending || execution.state !== "PAUSED"}
        />
        <CommandButton
          icon={<RotateCcw aria-hidden="true" size={15} />}
          label="Recover"
          command="RECOVER"
          disabled={stale || pending || !["FAILED", "RECOVERY_REQUIRED"].includes(execution.state)}
        />
        <CommandButton
          icon={<Skull aria-hidden="true" size={15} />}
          label="Simulate crash"
          command="SIMULATE_CRASH"
          disabled={stale || pending || TERMINAL_STATES.has(execution.state)}
        />
        <AbortDialog execution={execution} />
        <span className="toolbar-spacer" />
        <button
          className="icon-command"
          type="button"
          title="Refresh authoritative snapshot"
          aria-label="Refresh authoritative snapshot"
          onClick={() => void dispatch(resyncExecution(execution.id))}
          disabled={pending}
        >
          <RefreshCcw aria-hidden="true" size={16} />
        </button>
        <button
          className="toolbar-command"
          type="button"
          onClick={() => void dispatch(loadReport(execution.id))}
          disabled={pending || !TERMINAL_STATES.has(execution.state)}
        >
          {pendingAction === "LOAD_REPORT" ? <LoaderCircle className="spin" size={15} /> : <FileClock size={15} />}
          <span>As-run report</span>
        </button>
      </div>

      <ValidationPanel />

      {stale && (
        <div className="stale-interlock" role="alert">
          <AlertOctagon aria-hidden="true" size={17} />
          <strong>{connection.phase}</strong>
          <span>Operational controls are interlocked until authoritative state is restored.</span>
        </div>
      )}

      {execution.active_prompt && <PromptPanel prompt={execution.active_prompt} />}

      <ProcedureFlow steps={execution.steps} currentStepId={execution.current_step_id} />

      <section className="source-section" aria-labelledby="source-title">
        <div className="section-heading">
          <h3 id="source-title">Procedure source</h3>
          <span>{currentStep ? `Line ${currentStep.line} - ${currentStep.label}` : "Awaiting source position"}</span>
        </div>
        <ol
          className="source-list"
          tabIndex={0}
          aria-label="Scrollable procedure source with current execution line"
        >
          {sourceLines.map((line, index) => {
            const lineNumber = index + 1;
            const active = lineNumber === execution.current_line || execution.steps[index]?.id === execution.current_step_id;
            return (
              <li key={`${lineNumber}-${line}`} className={active ? "current-line" : undefined}>
                <span className="line-number">{lineNumber}</span>
                <code>{line || " "}</code>
              </li>
            );
          })}
        </ol>
      </section>
    </main>
  );
}
