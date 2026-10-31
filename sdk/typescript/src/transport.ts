// SPDX-License-Identifier: Apache-2.0
/**
 * Minimal HTTP transport over `node:http` / `node:https`, including unix domain sockets
 * (`socketPath`). No runtime dependencies. The transport never logs headers or bodies.
 */
import http from "node:http";
import https from "node:https";
import { AbortedError, AIPassTimeoutError, InvalidResponseError, NetworkError } from "./errors.js";
import { msg } from "./messages.js";
import type { Locale } from "./types.js";
import type { BrokerEndpoint } from "./url.js";

export interface TransportRequest {
  method: string;
  /** Full path + query exactly as it must appear on the request line (already signed). */
  path: string;
  headers: Record<string, string>;
  body?: Buffer;
  timeoutMs: number;
  maxResponseBytes: number;
  signal?: AbortSignal;
}

export interface TransportResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

/** Pluggable transport (custom networking or tests). */
export interface Transport {
  request(req: TransportRequest): Promise<TransportResponse>;
  close(): void;
}

export interface NodeHttpTransportOptions {
  locale?: Locale;
  /** Extra trusted CA certificate(s) (PEM) for self-hosted nodes. TLS verification is always on. */
  ca?: string | Buffer | Array<string | Buffer>;
}

/** `node:http(s)` transport bound to one broker endpoint. */
export class NodeHttpTransport implements Transport {
  readonly #endpoint: BrokerEndpoint;
  readonly #agent: http.Agent;
  readonly #locale: Locale | undefined;
  readonly #ca: NodeHttpTransportOptions["ca"];

  constructor(endpoint: BrokerEndpoint, options: NodeHttpTransportOptions = {}) {
    this.#endpoint = endpoint;
    this.#locale = options.locale;
    this.#ca = options.ca;
    const agentOptions = { keepAlive: true, maxSockets: 16 };
    this.#agent =
      endpoint.kind === "tcp" && endpoint.protocol === "https:"
        ? new https.Agent({ ...agentOptions, ...(options.ca !== undefined ? { ca: options.ca } : {}) })
        : new http.Agent(agentOptions);
  }

  request(req: TransportRequest): Promise<TransportResponse> {
    const endpoint = this.#endpoint;
    const locale = this.#locale;
    return new Promise<TransportResponse>((resolve, reject) => {
      if (req.signal?.aborted) {
        reject(new AbortedError("ABORTED", msg(locale, "aborted")));
        return;
      }
      const headers: Record<string, string> = { ...req.headers };
      if (req.body !== undefined) headers["content-length"] = String(req.body.length);
      const options: https.RequestOptions = { method: req.method, path: req.path, headers, agent: this.#agent };
      let lib: typeof http | typeof https = http;
      if (endpoint.kind === "unix") {
        options.socketPath = endpoint.socketPath;
        headers.host = "localhost";
      } else {
        options.hostname = endpoint.hostname;
        options.port = endpoint.port;
        if (endpoint.protocol === "https:") {
          lib = https;
          if (this.#ca !== undefined) options.ca = this.#ca;
        }
      }

      let settled = false;
      let timer: NodeJS.Timeout | undefined;
      const cleanup = () => {
        if (timer) clearTimeout(timer);
        req.signal?.removeEventListener("abort", onAbort);
      };
      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err);
      };
      const onAbort = () => {
        const err = new AbortedError("ABORTED", msg(locale, "aborted"));
        fail(err);
        outgoing.destroy(err);
      };

      const outgoing = lib.request(options, (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > req.maxResponseBytes) {
            const err = new InvalidResponseError("INVALID_RESPONSE", msg(locale, "responseTooLarge", { limit: req.maxResponseBytes }), {
              httpStatus: res.statusCode ?? 0,
            });
            fail(err);
            res.destroy();
            outgoing.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) });
        });
        res.on("error", (err) => fail(this.#networkError(err)));
        res.on("aborted", () => fail(this.#networkError(new Error("response aborted"))));
      });

      outgoing.on("error", (err) => fail(err instanceof AbortedError || err instanceof AIPassTimeoutError ? err : this.#networkError(err)));
      if (req.timeoutMs > 0) {
        timer = setTimeout(() => {
          const err = new AIPassTimeoutError("TIMEOUT", msg(locale, "requestTimeout", { ms: req.timeoutMs }));
          fail(err);
          outgoing.destroy(err);
        }, req.timeoutMs);
      }
      req.signal?.addEventListener("abort", onAbort, { once: true });
      outgoing.end(req.body);
    });
  }

  #networkError(err: Error & { code?: string }): NetworkError {
    const detail = err.message || err.code || "connection failed";
    return new NetworkError("NETWORK_ERROR", msg(this.#locale, "network", { target: this.#endpoint.display, detail }), { cause: err });
  }

  close(): void {
    this.#agent.destroy();
  }
}
