import {
  AlertOctagon,
  ArrowRightLeft,
  Check,
  ChevronRight,
  ChevronsRight,
  CircleStop,
  FileClock,
  Gauge,
  LogOut,
  LoaderCircle,
  MapPin,
  Pause,
  Play,
  RefreshCcw,
  RotateCcw,
  Settings2,
  SkipForward,
  Square,
  StepForward,
  Users,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { api, currentControlProof } from "../api";
import { useAppDispatch, useAppSelector } from "../hooks";
import { loadReport, openExecution, refreshMaster, resyncExecution, sendExecutionCommand } from "../store";
import type { ControllerHandover, ExecutionSnapshot, MonitorSubscription, PromptSettings } from "../types";
import { useActiveControlLease, useControlLeaseStatus } from "../useControlLease";
import { ProcedureFlow } from "./ProcedureFlow";
import { PromptPanel } from "./PromptPanel";
import { SourceWorkspace } from "./SourceWorkspace";
import { ValidationPanel } from "./ValidationPanel";

const TERMINAL_STATES = new Set(["ABORTED", "FAILED", "COMPLETED", "FINISHED", "ERROR"]);
const ABORT_ALLOWED_STATES = new Set(["REQUESTED", "VALIDATING", "ADMISSION_PENDING", "LOADING", "PAUSED", "RUNNING", "WAITING", "PROMPT", "PROMPTING", "INTERRUPTED", "SUSPENDED", "RECOVERING"]);
const BACKGROUND_ALLOWED_STATES = new Set(["PAUSED", "RUNNING", "WAITING", "INTERRUPTED"]);

function stateTone(state: ExecutionSnapshot["state"]): string {
  if (state === "RUNNING") return "running";
  if (["PAUSED", "WAITING", "PROMPT", "PROMPTING", "INTERRUPTED"].includes(state)) return "attention";
  if (["FAILED", "ERROR", "ABORTED", "SUSPENDED", "RECOVERY_REQUIRED"].includes(state)) return "danger";
  if (state === "COMPLETED" || state === "FINISHED") return "complete";
  return "neutral";
}

function CommandButton({
  icon,
  label,
  command,
  disabled,
  dangerous = false,
  target,
}: {
  icon: React.ReactNode;
  label: string;
  command: string;
  disabled: boolean;
  dangerous?: boolean;
  target?: Record<string, unknown>;
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
        proof: currentControlProof(execution.controller_lease),
        target,
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

export function OwnershipControls({ execution }: { execution: ExecutionSnapshot }) {
  const dispatch = useAppDispatch();
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [monitor, setMonitor] = useState<MonitorSubscription | null>(null);
  const [handovers, setHandovers] = useState<ControllerHandover[]>([]);
  const [handoverDialog, setHandoverDialog] = useState<"REQUEST" | ControllerHandover | null>(null);
  const [handoverAcknowledged, setHandoverAcknowledged] = useState(false);
  const [handoverReason, setHandoverReason] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsReason, setSettingsReason] = useState("");
  const [settingsDraft, setSettingsDraft] = useState({ warning: "", timeout: "", grace: "" });
  const monitorRef = useRef<{ executionId: string; subscription: MonitorSubscription } | null>(null);
  const handledHandoversRef = useRef<Set<string>>(new Set());
  const activeExecutionIdRef = useRef<string | null>(execution.id);
  activeExecutionIdRef.current = execution.id;
  const lease = execution.controller_lease;
  const { hasActiveLease, ownsControl } = useControlLeaseStatus(execution);
  const displayedLeaseState = lease?.state === "ACTIVE" && !hasActiveLease ? "EXPIRED" : lease?.state;

  useEffect(() => {
    const executionId = execution.id;
    handledHandoversRef.current.clear();
    const tracked = monitorRef.current;
    setMonitor(tracked?.executionId === executionId ? tracked.subscription : null);
    return () => {
      if (activeExecutionIdRef.current === executionId) activeExecutionIdRef.current = null;
      const active = monitorRef.current;
      if (!active || active.executionId !== executionId) return;
      monitorRef.current = null;
      void api.stopMonitor(executionId, active.subscription.id)
        .catch(() => undefined)
        .finally(() => { void dispatch(refreshMaster()); });
    };
  }, [dispatch, execution.id]);

  useEffect(() => {
    let active = true;
    const executionId = execution.id;
    const load = async () => {
      try {
        const items = await api.handovers(executionId, true);
        if (!active || activeExecutionIdRef.current !== executionId) return;
        setHandovers(items.filter((item) => item.state === "REQUESTED"));

        const identity = currentControlProof();
        const completed = items.find((item) => item.state === "COMPLETED"
          && item.requester_session_id === identity.session_id
          && item.requester_client_instance_key_id === identity.client_instance_key_id
          && Boolean(item.successor_lease_id)
          && !handledHandoversRef.current.has(item.id));
        if (!completed) return;

        handledHandoversRef.current.add(completed.id);
        const tracked = monitorRef.current;
        if (tracked?.executionId === executionId && tracked.subscription.id === completed.requester_monitor_id) {
          monitorRef.current = null;
          setMonitor(null);
        }
        try {
          await dispatch(openExecution(executionId)).unwrap();
          if (active && activeExecutionIdRef.current === executionId) setError(null);
          void dispatch(refreshMaster());
        } catch (reason) {
          handledHandoversRef.current.delete(completed.id);
          if (active && activeExecutionIdRef.current === executionId) {
            setError(reason instanceof Error ? reason.message : "Control transferred, but the authoritative snapshot could not be refreshed");
          }
        }
      } catch {
        if (active && activeExecutionIdRef.current === executionId) setHandovers([]);
      }
    };
    void load();
    const timer = window.setInterval(() => void load(), 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [dispatch, execution.id]);

  const refreshHandovers = async () => {
    const items = await api.handovers(execution.id);
    setHandovers(items.filter((item) => item.state === "REQUESTED"));
  };

  const request = async (action: "ACQUIRE" | "RENEW" | "RELEASE_TO_BACKGROUND") => {
    setPending(action);
    setError(null);
    try {
      await api.control(
        execution.id,
        action,
        execution.revision,
        currentControlProof(lease),
        execution.ownership_mode === "CONTROL_LOST" || execution.hold_reason || (lease && lease.state !== "ACTIVE")
          ? "I acknowledge the recovered execution state and retained effect certainty."
          : undefined,
      );
      await dispatch(openExecution(execution.id));
      void dispatch(refreshMaster());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Control request failed");
    } finally {
      setPending(null);
    }
  };

  const releaseToBackground = async () => {
    setPending("BACKGROUND");
    setError(null);
    try {
      await dispatch(sendExecutionCommand({
        executionId: execution.id,
        command: "BACKGROUND",
        revision: execution.revision,
        reason: "Release controller ownership to background at the next safe point",
        proof: currentControlProof(lease),
      })).unwrap();
      void dispatch(refreshMaster());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Background release failed");
    } finally {
      setPending(null);
    }
  };

  const toggleMonitor = async () => {
    setPending(monitor ? "STOP_MONITOR" : "START_MONITOR");
    setError(null);
    try {
      if (monitor) {
        const tracked = monitorRef.current;
        monitorRef.current = null;
        try {
          await api.stopMonitor(execution.id, monitor.id);
          setMonitor(null);
        } catch (reason) {
          if (tracked && activeExecutionIdRef.current === tracked.executionId) monitorRef.current = tracked;
          throw reason;
        }
      } else {
        const executionId = execution.id;
        const next = await api.startMonitor(executionId, currentControlProof(lease));
        if (next.state === "ACTIVE" && activeExecutionIdRef.current === executionId) {
          monitorRef.current = { executionId, subscription: next };
          setMonitor(next);
        } else if (next.state === "ACTIVE") {
          await api.stopMonitor(executionId, next.id).catch(() => undefined);
        }
      }
      void dispatch(refreshMaster());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Monitor subscription request failed");
    } finally {
      setPending(null);
    }
  };

  const submitHandover = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!handoverDialog || !handoverReason.trim()) return;
    setPending(handoverDialog === "REQUEST" ? "REQUEST_HANDOVER" : "APPROVE_HANDOVER");
    setError(null);
    try {
      if (handoverDialog === "REQUEST") {
        if (!monitor || !handoverAcknowledged) return;
        await api.requestHandover(
          execution.id,
          monitor.id,
          execution.revision,
          "I accept responsibility for control of this execution and its subsequent effects.",
          handoverReason.trim(),
          currentControlProof(lease),
        );
      } else {
        const result = await api.approveHandover(
          execution.id,
          handoverDialog,
          execution.revision,
          handoverReason.trim(),
          currentControlProof(lease),
        );
        const formerMonitor = result.former_monitor;
        if (formerMonitor?.state === "ACTIVE" && activeExecutionIdRef.current === execution.id) {
          monitorRef.current = { executionId: execution.id, subscription: formerMonitor };
          setMonitor(formerMonitor);
        }
        await dispatch(openExecution(execution.id));
      }
      await refreshHandovers();
      void dispatch(refreshMaster());
      setHandoverDialog(null);
      setHandoverAcknowledged(false);
      setHandoverReason("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Control handover failed");
    } finally {
      setPending(null);
    }
  };

  const openSettings = () => {
    const settings = execution.settings ?? {};
    setSettingsDraft({
      warning: settings.PROMPT_WARNING_DELAY == null ? "" : String(settings.PROMPT_WARNING_DELAY),
      timeout: settings.PROMPT_RESPONSE_TIMEOUT == null ? "" : String(settings.PROMPT_RESPONSE_TIMEOUT),
      grace: settings.NO_CONTROLLER_GRACE == null ? "" : String(settings.NO_CONTROLLER_GRACE),
    });
    setSettingsReason("");
    setSettingsOpen(true);
  };

  const submitSettings = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!settingsReason.trim() || !ownsControl) return;
    const duration = (value: string): number | null => value.trim() ? Number(value) : null;
    const settings: PromptSettings = {
      PROMPT_WARNING_DELAY: duration(settingsDraft.warning),
      PROMPT_RESPONSE_TIMEOUT: duration(settingsDraft.timeout),
      NO_CONTROLLER_GRACE: duration(settingsDraft.grace),
    };
    setPending("UPDATE_SETTINGS");
    setError(null);
    try {
      await api.updateExecutionSettings(execution.id, settings, execution.revision, currentControlProof(lease), settingsReason.trim());
      await dispatch(openExecution(execution.id));
      setSettingsOpen(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Prompt settings update failed");
    } finally {
      setPending(null);
    }
  };

  const requesterHandover = monitor
    ? handovers.find((handover) => handover.requester_monitor_id === monitor.id)
    : undefined;

  return (
    <>
      <div className="ownership-row">
        <div className="mode-control" aria-label="Ownership mode">
          <button type="button" aria-pressed={ownsControl} disabled={pending !== null || (hasActiveLease && !ownsControl)} onClick={() => void request(ownsControl ? "RENEW" : "ACQUIRE")} title={ownsControl ? "Renew control lease" : "Acquire exclusive control"}><Gauge aria-hidden="true" size={14} /><b>C</b><span>{ownsControl ? "Renew" : "Acquire"}</span></button>
          <button type="button" aria-pressed={Boolean(monitor)} disabled={pending !== null} onClick={() => void toggleMonitor()} title={monitor ? "Stop read-only monitor" : "Start read-only monitor"}><Users aria-hidden="true" size={14} /><b>M</b><span>{monitor ? "Stop" : "Monitor"}</span></button>
          <button type="button" aria-pressed={execution.ownership_mode === "B"} disabled={!ownsControl || pending !== null || Boolean(execution.active_prompt) || !execution.background_allowed || !BACKGROUND_ALLOWED_STATES.has(execution.state)} onClick={() => void releaseToBackground()} title={execution.background_allowed ? "Release control at a safe point" : "Procedure does not allow background execution"}><LogOut aria-hidden="true" size={14} /><b>B</b><span>Background</span></button>
        </div>
        <div className="ownership-actions">
          <button type="button" onClick={() => setHandoverDialog("REQUEST")} disabled={!monitor || ownsControl || pending !== null || Boolean(requesterHandover)} title={!monitor ? "Start a named monitor before requesting control" : requesterHandover ? "Control handover requested" : "Request control from the current holder"} aria-label="Request control handover"><ArrowRightLeft aria-hidden="true" size={14} /></button>
          <button type="button" onClick={openSettings} disabled={!ownsControl || pending !== null} title="Execution prompt settings" aria-label="Execution prompt settings"><Settings2 aria-hidden="true" size={14} /></button>
        </div>
        {ownsControl && handovers.length > 0 && <div className="handover-requests" aria-label="Pending control handovers">
          {handovers.map((handover) => <button key={handover.id} type="button" onClick={() => { setHandoverReason(""); setHandoverDialog(handover); }} disabled={pending !== null} title={`Approve control handover from ${handover.requester_subject_id}`}><Check aria-hidden="true" size={13} /><span>{handover.requester_subject_id}</span></button>)}
        </div>}
        <div className="lease-readout">
          <span className={`lease-state ${displayedLeaseState?.toLowerCase() ?? "none"}`}>{displayedLeaseState ?? "NO LEASE"}</span>
          {lease && <><code title={lease.id}>{lease.id.slice(0, 10)}</code><span>Fence {lease.fencing_token}</span><span>Rev {lease.revision}</span><span>Expires {new Date(lease.expires_at).toLocaleTimeString()}</span></>}
          {requesterHandover && <span className="handover-state">Handover requested</span>}
        </div>
        {error && <span className="control-error" role="alert">{error}</span>}
      </div>
      {handoverDialog && createPortal(
        <div className="abort-backdrop" onKeyDown={(event) => event.key === "Escape" && setHandoverDialog(null)}>
          <section className="operator-dialog" role="dialog" aria-modal="true" aria-labelledby="handover-dialog-title">
            <form onSubmit={(event) => void submitHandover(event)}>
              <div className="dialog-title neutral"><ArrowRightLeft aria-hidden="true" size={22} /><h2 id="handover-dialog-title">{handoverDialog === "REQUEST" ? "Request control handover" : "Approve control handover"}</h2></div>
              {handoverDialog === "REQUEST" ? <label className="acknowledgement"><input type="checkbox" checked={handoverAcknowledged} onChange={(event) => setHandoverAcknowledged(event.target.checked)} /><span>I accept responsibility for control of this execution and its subsequent effects.</span></label> : <p>Requester <strong>{handoverDialog.requester_subject_id}</strong><br /><code title={handoverDialog.requester_monitor_id}>{handoverDialog.requester_monitor_id}</code></p>}
              <label>Operational reason<textarea value={handoverReason} onChange={(event) => setHandoverReason(event.target.value)} rows={3} required autoFocus={handoverDialog !== "REQUEST"} /></label>
              <div className="dialog-actions"><button type="button" onClick={() => setHandoverDialog(null)}>Cancel</button><button type="submit" className="confirm-control" disabled={pending !== null || !handoverReason.trim() || (handoverDialog === "REQUEST" && !handoverAcknowledged)}>{handoverDialog === "REQUEST" ? "Request" : "Approve"}</button></div>
            </form>
          </section>
        </div>,
        document.body,
      )}
      {settingsOpen && createPortal(
        <div className="abort-backdrop" onKeyDown={(event) => event.key === "Escape" && setSettingsOpen(false)}>
          <section className="operator-dialog" role="dialog" aria-modal="true" aria-labelledby="settings-dialog-title">
            <form onSubmit={(event) => void submitSettings(event)}>
              <div className="dialog-title neutral"><Settings2 aria-hidden="true" size={22} /><h2 id="settings-dialog-title">Execution prompt settings</h2></div>
              <div className="settings-grid">
                <label>Warning delay <span>seconds</span><input type="number" min={0} max={86400} step="any" placeholder="Inherited" value={settingsDraft.warning} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, warning: event.target.value }))} /></label>
                <label>Response timeout <span>seconds</span><input type="number" min={0} max={604800} step="any" placeholder="Inherited" value={settingsDraft.timeout} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, timeout: event.target.value }))} /></label>
                <label>No-controller grace <span>seconds</span><input type="number" min={0} max={604800} step="any" placeholder="Inherited" value={settingsDraft.grace} onChange={(event) => setSettingsDraft((draft) => ({ ...draft, grace: event.target.value }))} /></label>
              </div>
              <label>Operational reason<textarea value={settingsReason} onChange={(event) => setSettingsReason(event.target.value)} rows={2} required /></label>
              <div className="dialog-actions"><button type="button" onClick={() => setSettingsOpen(false)}>Cancel</button><button type="submit" className="confirm-control" disabled={pending !== null || !ownsControl || !settingsReason.trim()}>Apply</button></div>
            </form>
          </section>
        </div>,
        document.body,
      )}
    </>
  );
}

function AbortDialog({ execution }: { execution: ExecutionSnapshot }) {
  const dispatch = useAppDispatch();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const pending = useAppSelector((state) => state.console.pendingAction !== null);
  const connected = useAppSelector((state) => state.console.connection.phase === "CONNECTED");
  const canControl = useActiveControlLease(execution);

  const abort = (event: React.FormEvent) => {
    event.preventDefault();
    if (!reason.trim() || !connected) return;
    void dispatch(
      sendExecutionCommand({
        executionId: execution.id,
        command: "ABORT",
        revision: execution.revision,
        reason: reason.trim(),
        proof: currentControlProof(execution.controller_lease),
      }),
    ).unwrap().then(() => setOpen(false)).catch(() => undefined);
  };

  return (
    <>
      <button
        type="button"
        className="danger-command"
        aria-label="Abort"
        title="Abort execution"
        onClick={() => setOpen(true)}
        disabled={!connected || pending || !canControl || !ABORT_ALLOWED_STATES.has(execution.state)}
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
                <button type="submit" className="confirm-abort" disabled={!connected || !reason.trim() || pending || !canControl}>
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
  const [gotoLine, setGotoLine] = useState(1);
  const canControl = useActiveControlLease(execution);

  useEffect(() => {
    const lease = execution?.controller_lease;
    if (!execution || lease?.state !== "ACTIVE") return;
    const expiresAt = Date.parse(lease.expires_at);
    if (!Number.isFinite(expiresAt)) return;
    let cancelled = false;
    let timer = 0;
    const refreshExpiredProjection = async (attempt: number) => {
      if (cancelled) return;
      await Promise.all([dispatch(resyncExecution(execution.id)), dispatch(refreshMaster())]);
      if (!cancelled && attempt < 3) {
        timer = window.setTimeout(() => void refreshExpiredProjection(attempt + 1), 2_000);
      }
    };
    const armExpiry = () => {
      const remaining = expiresAt - Date.now();
      if (remaining <= 0) {
        void refreshExpiredProjection(1);
        return;
      }
      timer = window.setTimeout(armExpiry, Math.min(remaining + 50, 2_147_000_000));
    };
    armExpiry();
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [dispatch, execution?.controller_lease?.expires_at, execution?.controller_lease?.id, execution?.controller_lease?.revision, execution?.controller_lease?.state, execution?.id]);

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
  const commandDisabled = stale || pending || !canControl;

  return (
    <main className="execution-workspace">
      <div className="execution-titlebar">
        <div>
          <span className="eyebrow execution-id" title={execution.id}>Execution {execution.id}</span>
          <h1>{execution.procedure_name}</h1>
          {execution.parent_execution_id && <button type="button" className="parent-link" onClick={() => void dispatch(openExecution(execution.parent_execution_id!))}>Parent <code>{execution.parent_execution_id}</code><ChevronRight aria-hidden="true" size={13} /></button>}
        </div>
        <div className="execution-metadata">
          <span className={`state-pill ${stateTone(execution.state)}`}>{execution.state}</span>
          <span>Rev {execution.revision}</span>
          <span>Seq {execution.last_sequence}</span>
        </div>
      </div>

      <OwnershipControls execution={execution} />

      <div className="command-toolbar" aria-label="Execution controls">
        <CommandButton
          icon={<Play aria-hidden="true" size={15} fill="currentColor" />}
          label="Run"
          command="RUN"
          disabled={commandDisabled || !["PAUSED", "INTERRUPTED"].includes(execution.state)}
        />
        <CommandButton
          icon={<StepForward aria-hidden="true" size={15} />}
          label="Step"
          command="STEP"
          disabled={commandDisabled || !["PAUSED", "INTERRUPTED"].includes(execution.state)}
        />
        <CommandButton
          icon={<ChevronsRight aria-hidden="true" size={15} />}
          label="Step over"
          command="STEP_OVER"
          disabled={commandDisabled || !["PAUSED", "INTERRUPTED"].includes(execution.state)}
        />
        <CommandButton
          icon={<Pause aria-hidden="true" size={15} fill="currentColor" />}
          label="Pause"
          command="PAUSE"
          disabled={commandDisabled || !["RUNNING", "WAITING", "PROMPT", "PROMPTING"].includes(execution.state)}
        />
        <CommandButton
          icon={<SkipForward aria-hidden="true" size={15} />}
          label="Skip"
          command="SKIP"
          disabled={commandDisabled || !["PAUSED", "INTERRUPTED"].includes(execution.state)}
        />
        <label className="goto-control" title="Static line in the current procedure"><span className="sr-only">Goto line</span><input type="number" min={1} value={gotoLine} onChange={(event) => setGotoLine(Math.max(1, Number(event.target.value) || 1))} disabled={commandDisabled || execution.state !== "PAUSED"} /></label>
        <CommandButton
          icon={<MapPin aria-hidden="true" size={15} />}
          label="Goto"
          command="GOTO"
          target={{ line: gotoLine }}
          disabled={commandDisabled || execution.state !== "PAUSED"}
        />
        <CommandButton
          icon={<CircleStop aria-hidden="true" size={15} />}
          label="Stop"
          command="STOP"
          disabled={commandDisabled || TERMINAL_STATES.has(execution.state) || execution.state === "STOPPING"}
        />
        <CommandButton
          icon={<RotateCcw aria-hidden="true" size={15} />}
          label="Recover"
          command="RECOVER"
          disabled={commandDisabled || !["ERROR", "FAILED", "RECOVERY_REQUIRED"].includes(execution.state)}
        />
        <CommandButton
          icon={<RotateCcw aria-hidden="true" size={15} />}
          label="Reload"
          command="RELOAD"
          disabled={commandDisabled || !["FINISHED", "COMPLETED", "ABORTED", "ERROR", "FAILED"].includes(execution.state)}
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
      <SourceWorkspace execution={execution} canMutate={!commandDisabled} />
    </main>
  );
}
