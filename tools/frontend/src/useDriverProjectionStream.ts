import { useEffect } from "react";
import {
  clearAccessToken,
  driverWebsocketUrl,
  websocketProtocols,
} from "./api";
import type { DriverLifecycleEvent } from "./types";

const MAX_RECONNECT_MS = 10_000;

export function useDriverProjectionStream(
  refreshProjection: () => Promise<void>,
): void {
  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let cancelled = false;
    let authenticationInvalidated = false;
    let reconnectAttempt = 0;
    let lastSequence = 0;
    let resyncSequence: number | null = null;
    let resyncInFlight = false;

    const scheduleReconnect = (immediate = false) => {
      if (cancelled || authenticationInvalidated || reconnectTimer !== null) return;
      reconnectAttempt += 1;
      const delay = immediate
        ? 0
        : Math.min(500 * 2 ** reconnectAttempt, MAX_RECONNECT_MS);
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, delay);
    };

    const resynchronize = async () => {
      if (cancelled || resyncInFlight) return;
      resyncInFlight = true;
      try {
        await refreshProjection();
      } finally {
        resyncInFlight = false;
        if (!cancelled && socket?.readyState === WebSocket.CLOSED) {
          if (resyncSequence !== null) lastSequence = resyncSequence;
          resyncSequence = null;
          scheduleReconnect(true);
        }
      }
    };

    function connect() {
      if (cancelled || authenticationInvalidated) return;
      const candidate = new WebSocket(
        driverWebsocketUrl(lastSequence),
        websocketProtocols(),
      );
      socket = candidate;

      candidate.addEventListener("open", () => {
        if (socket === candidate) reconnectAttempt = 0;
      });

      candidate.addEventListener("message", (message) => {
        if (socket !== candidate) return;
        try {
          const event = JSON.parse(String(message.data)) as DriverLifecycleEvent;
          if (event.event_type === "stream.resync_required") {
            const authority = event.payload?.authoritative_sequence;
            resyncSequence =
              typeof authority === "number" && Number.isSafeInteger(authority) && authority >= 0
                ? authority
                : 0;
            void resynchronize();
            return;
          }
          if (
            typeof event.sequence !== "number" ||
            !Number.isSafeInteger(event.sequence) ||
            event.sequence <= lastSequence ||
            !event.event_type
          ) {
            return;
          }
          lastSequence = event.sequence;
          void refreshProjection();
        } catch {
          candidate.close();
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
          if (resyncSequence === null) resyncSequence = 0;
          void resynchronize();
          return;
        }
        scheduleReconnect();
      });

      candidate.addEventListener("error", () => {
        if (socket !== candidate) return;
        if (candidate.readyState === WebSocket.OPEN) candidate.close();
      });
    }

    connect();
    return () => {
      cancelled = true;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [refreshProjection]);
}
