import { useEffect, useState } from "react";
import { hasActiveControlLease, hasUnexpiredControlLease } from "./api";
import type { ControllerLease } from "./types";

type LeaseExecution = { ownership_mode?: string; controller_lease?: ControllerLease | null } | null | undefined;

export function useControlLeaseStatus(execution: LeaseExecution): {
  hasActiveLease: boolean;
  ownsControl: boolean;
} {
  const [nowMs, setNowMs] = useState(() => Date.now());
  const lease = execution?.controller_lease;

  useEffect(() => {
    setNowMs(Date.now());
    if (lease?.state !== "ACTIVE") return;
    const expiresAt = Date.parse(lease.expires_at);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return;

    let timer = 0;
    const updateAtExpiry = () => {
      const remaining = expiresAt - Date.now();
      if (remaining <= 0) {
        setNowMs(Date.now());
        return;
      }
      timer = window.setTimeout(updateAtExpiry, Math.min(remaining + 1, 2_147_000_000));
    };
    updateAtExpiry();
    return () => window.clearTimeout(timer);
  }, [lease?.expires_at, lease?.id, lease?.revision, lease?.state]);

  return {
    hasActiveLease: hasUnexpiredControlLease(lease, nowMs),
    ownsControl: hasActiveControlLease(execution, nowMs),
  };
}

export function useActiveControlLease(execution: LeaseExecution): boolean {
  return useControlLeaseStatus(execution).ownsControl;
}
