// SPDX-License-Identifier: Apache-2.0
/**
 * Polling with exponential backoff + jitter, deadline and abort support.
 * A timeout ends the wait and reports the latest status — it is never an approval.
 */
import { randomUnit } from "./encoding.js";
import { AbortedError, AIPassError } from "./errors.js";
import { msg } from "./messages.js";
import type { Locale } from "./types.js";

export interface BackoffOptions {
  /** First delay between polls (ms). Default 1000. */
  intervalMs?: number;
  /** Upper bound for the delay (ms). Default 10000. */
  maxIntervalMs?: number;
  /** Multiplier applied after each poll. Default 1.5. */
  backoff?: number;
  /** Relative jitter in [0, 1]: each delay is scaled by a CSPRNG factor in [1 - j, 1 + j]. Default 0.2. */
  jitter?: number;
}

export interface ResolvedBackoff {
  intervalMs: number;
  maxIntervalMs: number;
  backoff: number;
  jitter: number;
}

export function resolveBackoff(options: BackoffOptions = {}, defaults: Partial<ResolvedBackoff> = {}): ResolvedBackoff {
  const intervalMs = finiteOr(options.intervalMs, defaults.intervalMs ?? 1000, 1);
  const maxIntervalMs = Math.max(intervalMs, finiteOr(options.maxIntervalMs, defaults.maxIntervalMs ?? 10_000, 1));
  const backoff = Math.max(1, finiteOr(options.backoff, defaults.backoff ?? 1.5, 1));
  const jitter = Math.min(1, Math.max(0, finiteOr(options.jitter, defaults.jitter ?? 0.2, 0)));
  return { intervalMs, maxIntervalMs, backoff, jitter };
}

function finiteOr(value: number | undefined, fallback: number, min: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= min ? value : fallback;
}

/** Apply jitter to a base delay. `rand` returns a uniform value in [0, 1). */
export function jittered(baseMs: number, jitter: number, rand: () => number = randomUnit): number {
  if (jitter <= 0) return baseMs;
  const factor = 1 - jitter + 2 * jitter * rand();
  return Math.max(0, Math.round(baseMs * factor));
}

/** Delay before poll number `attempt` (0-based), before jitter. */
export function backoffDelay(attempt: number, b: ResolvedBackoff): number {
  return Math.min(b.maxIntervalMs, b.intervalMs * Math.pow(b.backoff, Math.max(0, attempt)));
}

/** Sleep that rejects with {@link AbortedError} as soon as `signal` aborts. */
export function sleep(ms: number, signal?: AbortSignal, locale?: Locale): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(new AbortedError("ABORTED", msg(locale, "aborted")));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(new AbortedError("ABORTED", msg(locale, "aborted")));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, Math.max(0, ms));
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export function throwIfAborted(signal: AbortSignal | undefined, locale?: Locale): void {
  if (signal?.aborted) throw new AbortedError("ABORTED", msg(locale, "aborted"));
}

/** Errors worth another poll before the deadline (the broker or network blipped). */
export function isTransientPollError(err: unknown): boolean {
  if (!(err instanceof AIPassError)) return false;
  if (["NETWORK_ERROR", "TIMEOUT", "RATE_LIMITED", "INTERNAL"].includes(err.code)) return true;
  return err.code === "INVALID_RESPONSE" && (err.httpStatus ?? 0) >= 500;
}

export interface PollOptions<T> extends BackoffOptions {
  timeoutMs: number;
  signal?: AbortSignal;
  locale?: Locale;
  isTerminal: (value: T) => boolean;
  onUpdate?: (value: T) => void;
  /** Injected for tests. */
  now?: () => number;
}

export interface PollOutcome<T> {
  value: T;
  /** True when the deadline passed before a terminal state was reached. */
  timedOut: boolean;
  polls: number;
}

/**
 * Poll `fetch` until `isTerminal`, the deadline, or abort. Transient errors are retried until
 * the deadline; if the final attempt failed, that error is thrown (a stale status is never
 * silently reported as current). Non-transient errors are thrown immediately.
 */
export async function poll<T>(fetch: (remainingMs: number) => Promise<T>, options: PollOptions<T>): Promise<PollOutcome<T>> {
  const now = options.now ?? Date.now;
  const b = resolveBackoff(options);
  const timeoutMs = Math.max(0, options.timeoutMs);
  const deadline = now() + timeoutMs;
  let attempt = 0;
  let last: { value: T } | undefined;
  let lastError: unknown;
  for (;;) {
    throwIfAborted(options.signal, options.locale);
    let extraDelay = 0;
    try {
      const value = await fetch(Math.max(0, deadline - now()));
      last = { value };
      lastError = undefined;
      options.onUpdate?.(value);
      if (options.isTerminal(value)) return { value, timedOut: false, polls: attempt + 1 };
    } catch (err) {
      if (err instanceof AbortedError || !isTransientPollError(err)) throw err;
      lastError = err;
      const retryAfter = (err as { retryAfterSeconds?: number }).retryAfterSeconds;
      if (typeof retryAfter === "number" && retryAfter > 0) extraDelay = retryAfter * 1000;
    }
    const remaining = deadline - now();
    if (remaining <= 0) break;
    const delay = Math.max(jittered(backoffDelay(attempt, b), b.jitter), extraDelay);
    await sleep(Math.min(delay, remaining), options.signal, options.locale);
    attempt += 1;
  }
  if (lastError !== undefined || last === undefined) throw lastError;
  return { value: last.value, timedOut: true, polls: attempt + 1 };
}
