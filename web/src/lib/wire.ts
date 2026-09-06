/**
 * A small in-memory recorder for every HTTP exchange the app makes.
 *
 * The dashboard renders this as the "Wire" panel, which is the deliverable's
 * "example authenticated request" shown live rather than pasted into a README:
 * you can watch the Authorization header go out and the status code come back.
 * Nothing here is persisted, and tokens are never recorded — only their presence.
 */

export type WireEntry = {
  id: number;
  method: string;
  path: string;
  status: number;
  code: string | null;
  ms: number;
  requestId: string | null;
  authenticated: boolean;
  at: number;
};

const CAPACITY = 40;

let sequence = 0;
let entries: WireEntry[] = [];
const listeners = new Set<(entries: WireEntry[]) => void>();

/** Records one completed exchange, evicting the oldest once the buffer is full. */
export function record(entry: Omit<WireEntry, "id" | "at">): void {
  sequence += 1;
  const next: WireEntry = { ...entry, id: sequence, at: Date.now() };
  entries = [next, ...entries].slice(0, CAPACITY);
  for (const listener of listeners) listener(entries);
}

/** Current buffer, newest first. */
export function snapshot(): WireEntry[] {
  return entries;
}

/** Subscribes to buffer changes; returns an unsubscribe function. */
export function subscribe(listener: (entries: WireEntry[]) => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Clears the buffer. Used when a session ends so one user's traffic is not shown to the next. */
export function clear(): void {
  entries = [];
  sequence = 0;
  for (const listener of listeners) listener(entries);
}
