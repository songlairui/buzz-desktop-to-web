import type { RelayEvent } from "@/shared/api/types";
import { invokeTauri } from "./tauri";

export async function decryptObserverEvent(
  event: RelayEvent,
): Promise<unknown> {
  return invokeTauri<unknown>("decrypt_observer_event", {
    eventJson: JSON.stringify(event),
  });
}

export async function buildObserverControlEvent(input: {
  agentPubkey: string;
  payload: unknown;
}): Promise<RelayEvent> {
  const eventJson = await invokeTauri<string>("build_observer_control_event", {
    agentPubkey: input.agentPubkey,
    payload: input.payload,
  });
  return JSON.parse(eventJson) as RelayEvent;
}

/**
 * Host-side ring buffer of recent kind:24200 frames (web only).
 * Desktop archive covers history; web has no SQLite save-subscription path,
 * so mid-turn Activity opens would otherwise see an empty transcript.
 */
export async function listBufferedObserverEvents(options?: {
  since?: number;
  agentPubkey?: string | null;
  limit?: number;
}): Promise<RelayEvent[]> {
  try {
    const response = await invokeTauri<{ events?: RelayEvent[] }>(
      "list_buffered_observer_events",
      {
        since: options?.since ?? null,
        agentPubkey: options?.agentPubkey ?? null,
        limit: options?.limit ?? 500,
      },
    );
    return Array.isArray(response?.events) ? response.events : [];
  } catch {
    // Desktop / older host: command missing — treat as empty.
    return [];
  }
}
