import { useEffect } from "react";
import {
  clearAccessToken,
  telemetryWebsocketUrl,
  websocketProtocols,
} from "./api";
import type {
  TelemetryObservationEvent,
  TelemetryObservationSnapshot,
} from "./types";

const MAX_RECONNECT_MS = 10_000;
const OBSERVATION_SEQUENCE = /^(?:0|[1-9][0-9]*)$/;

type SnapshotCursor = Pick<
  TelemetryObservationSnapshot,
  "stream_epoch" | "through_sequence"
>;

export function useTelemetryObservationStream(
  contextId: string | null,
  refreshSnapshot: () => Promise<SnapshotCursor | null>,
): void {
  useEffect(() => {
    if (!contextId) return;
    const resolvedContextId: string = contextId;

    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let cancelled = false;
    let authenticationInvalidated = false;
    let reconnectAttempt = 0;
    let lastSequence = "0";
    let streamEpoch: string | undefined;
    let refreshInFlight = false;
    let refreshPending = false;
    let reconnectAfterRefresh = false;

    const scheduleReconnect = (immediate = false) => {
      if (cancelled || authenticationInvalidated || reconnectTimer !== null) return;
      reconnectAttempt += 1;
      const delay = immediate
        ? 0
        : Math.min(500 * 2 ** reconnectAttempt, MAX_RECONNECT_MS);
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        if (streamEpoch) connect();
        else void synchronize(true);
      }, delay);
    };

    const synchronize = async (reconnect: boolean) => {
      if (cancelled) return;
      if (reconnect) reconnectAfterRefresh = true;
      if (refreshInFlight) {
        refreshPending = true;
        return;
      }
      refreshInFlight = true;
      try {
        do {
          refreshPending = false;
          const snapshot = await refreshSnapshot();
          if (snapshot && OBSERVATION_SEQUENCE.test(snapshot.through_sequence)) {
            streamEpoch = snapshot.stream_epoch;
            lastSequence = snapshot.through_sequence;
          }
        } while (!cancelled && refreshPending);
      } catch {
        if (reconnectAfterRefresh) {
          streamEpoch = undefined;
          lastSequence = "0";
        }
      } finally {
        refreshInFlight = false;
        if (reconnectAfterRefresh && !cancelled) {
          reconnectAfterRefresh = false;
          if (streamEpoch) connect();
          else scheduleReconnect();
        }
      }
    };

    function connect() {
      if (cancelled || authenticationInvalidated) return;
      const candidate = new WebSocket(
        telemetryWebsocketUrl(resolvedContextId, lastSequence, streamEpoch),
        websocketProtocols(),
      );
      socket = candidate;

      candidate.addEventListener("open", () => {
        if (socket === candidate) reconnectAttempt = 0;
      });

      candidate.addEventListener("message", (message) => {
        if (socket !== candidate) return;
        try {
          const event = JSON.parse(String(message.data)) as TelemetryObservationEvent;
          const resync = event.event_type === "stream.resync_required";
          if (event.event_type === "stream.keepalive") return;
          const sequence = event.projection_sequence;
          const invalidSequence =
            sequence === undefined ||
            !OBSERVATION_SEQUENCE.test(sequence) ||
            BigInt(sequence) !== BigInt(lastSequence) + 1n;
          const wrongEpoch = Boolean(
            streamEpoch && event.stream_epoch && event.stream_epoch !== streamEpoch,
          );
          if (resync || invalidSequence || wrongEpoch) {
            candidate.close(4409, "observation resynchronization required");
            return;
          }
          streamEpoch = event.stream_epoch;
          lastSequence = sequence;
          void synchronize(false);
        } catch {
          candidate.close(4409, "invalid observation event");
        }
      });

      candidate.addEventListener("close", (event) => {
        if (socket !== candidate) return;
        if (event.code === 4401) {
          authenticationInvalidated = true;
          clearAccessToken();
          return;
        }
        if (event.code === 4409) {
          streamEpoch = undefined;
          lastSequence = "0";
          void synchronize(true);
          return;
        }
        scheduleReconnect();
      });

      candidate.addEventListener("error", () => {
        if (socket === candidate && candidate.readyState === WebSocket.OPEN) {
          candidate.close();
        }
      });
    }

    void synchronize(true);
    return () => {
      cancelled = true;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [contextId, refreshSnapshot]);
}
