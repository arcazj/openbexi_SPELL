import { useEffect, useRef } from "react";
import {
  accessTokenExpiresAtMs,
  clearAccessToken,
  websocketProtocols,
  websocketUrl,
} from "./api";
import { useAppDispatch, useAppSelector } from "./hooks";
import {
  forceResyncExecution,
  ingestEvent,
  markReconnect,
  resyncExecution,
  setConnectionPhase,
} from "./store";
import type { ExecutionEvent } from "./types";

const STALE_AFTER_MS = 8_000;
const MAX_RECONNECT_MS = 10_000;

export function eventRequiresProjectionResync(eventType: string): boolean {
  return ["control.", "schedule.", "startproc.", "relationship."].some((prefix) => eventType.startsWith(prefix))
    || eventType === "execution.child_created"
    || eventType === "operator.control_loss_requested";
}

export function useExecutionStream(authenticated: boolean): void {
  const dispatch = useAppDispatch();
  const executionId = useAppSelector((state) => state.console.execution?.id ?? null);
  const lastSequence = useAppSelector(
    (state) => state.console.execution?.last_sequence ?? 0,
  );
  const sequenceRef = useRef(lastSequence);
  const socketRef = useRef<WebSocket | null>(null);
  const authenticationInvalidatedRef = useRef(!authenticated);

  useEffect(() => {
    sequenceRef.current = lastSequence;
  }, [lastSequence]);

  useEffect(() => {
    if (!authenticated) {
      authenticationInvalidatedRef.current = true;
      return;
    }
    authenticationInvalidatedRef.current = false;
    const expiresAtMs = accessTokenExpiresAtMs();
    if (expiresAtMs === null) return;
    const expireSession = () => {
      authenticationInvalidatedRef.current = true;
      const activeSocket = socketRef.current;
      socketRef.current = null;
      activeSocket?.close();
      dispatch(setConnectionPhase("STALE"));
      clearAccessToken();
    };
    const remainingMs = expiresAtMs - Date.now();
    if (remainingMs <= 0) {
      expireSession();
      return;
    }
    const expiryTimer = window.setTimeout(expireSession, remainingMs);
    return () => window.clearTimeout(expiryTimer);
  }, [authenticated, dispatch]);

  useEffect(() => {
    if (!authenticated || !executionId) return;
    const activeExecutionId = executionId;

    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let staleTimer: number | null = null;
    let cancelled = false;
    let attempt = 0;
    let resyncing = false;
    let forceResyncPending = false;
    let bufferedEvents: ExecutionEvent[] = [];

    const clearTimers = () => {
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      if (staleTimer !== null) window.clearTimeout(staleTimer);
    };

    const expireSession = () => {
      cancelled = true;
      authenticationInvalidatedRef.current = true;
      clearTimers();
      socket?.close();
      socket = null;
      socketRef.current = null;
      dispatch(setConnectionPhase("STALE"));
      clearAccessToken();
    };

    const armStaleTimer = () => {
      if (staleTimer !== null) window.clearTimeout(staleTimer);
      staleTimer = window.setTimeout(() => {
        dispatch(setConnectionPhase("STALE"));
        scheduleReconnect();
        socket?.close();
      }, STALE_AFTER_MS);
    };

    const applyBufferedEvents = (snapshotSequence: number) => {
      sequenceRef.current = Math.max(sequenceRef.current, snapshotSequence);
      const replay = bufferedEvents.sort((left, right) => left.sequence - right.sequence);
      bufferedEvents = [];
      for (const event of replay) {
        if (event.sequence <= sequenceRef.current) continue;
        if (event.sequence > sequenceRef.current + 1) {
          bufferedEvents.push(event);
          dispatch(setConnectionPhase("STALE"));
          return false;
        }
        sequenceRef.current = event.sequence;
        dispatch(ingestEvent(event));
      }
      return true;
    };

    const performResync = async (force = false) => {
      if (cancelled) return;
      if (resyncing) {
        forceResyncPending ||= force;
        return;
      }
      resyncing = true;
      dispatch(setConnectionPhase("RESYNCING"));
      try {
        const snapshot = await dispatch(
          force
            ? forceResyncExecution(activeExecutionId)
            : resyncExecution(activeExecutionId),
        ).unwrap();
        const complete = applyBufferedEvents(snapshot.last_sequence);
        if (!cancelled && complete && socket?.readyState === WebSocket.OPEN) {
          dispatch(setConnectionPhase("CONNECTED"));
          armStaleTimer();
        }
      } catch {
        if (!cancelled) dispatch(setConnectionPhase("STALE"));
        socket?.close();
      } finally {
        resyncing = false;
        if (forceResyncPending && !cancelled) {
          forceResyncPending = false;
          void performResync(true);
        }
      }
    };

    const scheduleReconnect = () => {
      if (cancelled || authenticationInvalidatedRef.current || reconnectTimer !== null) return;
      dispatch(markReconnect());
      attempt += 1;
      const delay = Math.min(500 * 2 ** attempt, MAX_RECONNECT_MS);
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, delay);
    };

    function connect() {
      if (cancelled || authenticationInvalidatedRef.current) return;
      const candidate = new WebSocket(
        websocketUrl(activeExecutionId, sequenceRef.current),
        websocketProtocols(),
      );
      socket = candidate;
      socketRef.current = candidate;

      candidate.addEventListener("open", () => {
        if (socket !== candidate) return;
        attempt = 0;
        void performResync();
      });

      candidate.addEventListener("message", (message) => {
        if (socket !== candidate) return;
        armStaleTimer();
        try {
          const event = JSON.parse(String(message.data)) as ExecutionEvent;
          if (event.event_type === "stream.resync_required") {
            bufferedEvents = [];
            sequenceRef.current = 0;
            void performResync(true);
            return;
          }
          if (typeof event.sequence !== "number" || !event.event_type) return;
          if (resyncing) {
            bufferedEvents.push(event);
            return;
          }
          if (event.sequence <= sequenceRef.current) return;
          if (event.sequence > sequenceRef.current + 1) {
            bufferedEvents.push(event);
            void performResync();
            return;
          }
          sequenceRef.current = Math.max(sequenceRef.current, event.sequence);
          dispatch(ingestEvent(event));
          if (eventRequiresProjectionResync(event.event_type)) void performResync();
          dispatch(setConnectionPhase("CONNECTED"));
        } catch {
          dispatch(setConnectionPhase("STALE"));
        }
      });

      candidate.addEventListener("close", (event) => {
        if (socket !== candidate) return;
        if (event.code === 4401) {
          expireSession();
          return;
        }
        scheduleReconnect();
      });

      candidate.addEventListener("error", () => {
        if (socket !== candidate) return;
        scheduleReconnect();
        if (candidate.readyState === WebSocket.OPEN) candidate.close();
      });
    }

    connect();
    return () => {
      cancelled = true;
      clearTimers();
      socket?.close();
      if (socketRef.current === socket) socketRef.current = null;
    };
  }, [authenticated, dispatch, executionId]);
}
