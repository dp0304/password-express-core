// SPDX-License-Identifier: Apache-2.0
/**
 * Broker endpoint parsing and resolution.
 *
 * Accepted forms: `http://host:port[/base]`, `https://host:port[/base]`, `unix:///abs/path.sock`
 * (also `unix:/abs/path.sock`). Resolution order when nothing is passed (same as the MCP
 * bridge, CONTRACTS §9): `AIPASS_BROKER_URL` > `<AIPASS_HOME>/broker.json` >
 * `unix://<AIPASS_HOME>/run/broker.sock`; `AIPASS_HOME` defaults to `~/.aipass`.
 */
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { ConfigError } from "./errors.js";
import { msg } from "./messages.js";
import type { Locale } from "./types.js";

export type BrokerEndpoint =
  | { kind: "tcp"; protocol: "http:" | "https:"; hostname: string; port: number; basePath: string; display: string }
  | { kind: "unix"; socketPath: string; basePath: string; display: string };

function badUrl(locale: Locale | undefined, detail: string): ConfigError {
  return new ConfigError("CONFIG_ERROR", msg(locale, "badUrl", { detail }));
}

/** True for hosts where plaintext http stays on this machine. */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h);
}

export interface ParseBrokerUrlOptions {
  locale?: Locale;
  /** Allow plaintext http to non-loopback hosts (not recommended). */
  allowInsecureHttp?: boolean;
}

/** Parse a broker URL into a transport endpoint. */
export function parseBrokerUrl(url: string, options: ParseBrokerUrlOptions = {}): BrokerEndpoint {
  const { locale } = options;
  if (typeof url !== "string" || url.trim() === "") throw badUrl(locale, "empty");
  const text = url.trim();
  if (text.startsWith("unix:")) {
    let path = text.slice("unix:".length);
    if (path.startsWith("//")) path = path.slice(2);
    try {
      path = decodeURIComponent(path);
    } catch {
      throw badUrl(locale, "unix socket path is not valid percent-encoding");
    }
    if (!path.startsWith("/")) throw badUrl(locale, "unix socket path must be absolute (unix:///abs/path.sock)");
    return { kind: "unix", socketPath: path, basePath: "", display: `unix://${path}` };
  }
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    throw badUrl(locale, "not a URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw badUrl(locale, `unsupported scheme ${parsed.protocol}`);
  if (parsed.username || parsed.password) throw badUrl(locale, "URLs must not embed credentials");
  if (parsed.search || parsed.hash) throw badUrl(locale, "URLs must not contain a query or fragment");
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  if (!hostname) throw badUrl(locale, "missing host");
  if (parsed.protocol === "http:" && !isLoopbackHost(hostname) && !options.allowInsecureHttp) {
    throw new ConfigError("CONFIG_ERROR", msg(locale, "insecureHttp", { host: hostname }));
  }
  const port = parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80;
  const basePath = parsed.pathname.replace(/\/+$/, "");
  return {
    kind: "tcp",
    protocol: parsed.protocol,
    hostname,
    port,
    basePath,
    display: `${parsed.protocol}//${parsed.host}${basePath}`,
  };
}

/** `AIPASS_HOME` (default `~/.aipass`). */
export function aipassHome(env: NodeJS.ProcessEnv = process.env): string {
  const home = env.AIPASS_HOME;
  return home && home.trim() !== "" ? home : join(homedir(), ".aipass");
}

/**
 * Resolve the broker URL: explicit value > `AIPASS_BROKER_URL` > `<AIPASS_HOME>/broker.json`
 * (`{"broker_url": "…"}` or `{"url": "…"}`) > `unix://<AIPASS_HOME>/run/broker.sock`.
 */
export function resolveBrokerUrl(explicit?: string, env: NodeJS.ProcessEnv = process.env): string {
  if (explicit && explicit.trim() !== "") return explicit.trim();
  const fromEnv = env.AIPASS_BROKER_URL;
  if (fromEnv && fromEnv.trim() !== "") return fromEnv.trim();
  const home = aipassHome(env);
  const brokerJson = join(home, "broker.json");
  if (existsSync(brokerJson)) {
    try {
      const doc = JSON.parse(readFileSync(brokerJson, "utf8")) as { broker_url?: unknown; url?: unknown };
      const value = typeof doc.broker_url === "string" ? doc.broker_url : typeof doc.url === "string" ? doc.url : undefined;
      if (value && value.trim() !== "") return value.trim();
    } catch {
      // Ignore a malformed broker.json and fall through to the default socket.
    }
  }
  const sock = join(home, "run", "broker.sock");
  return `unix://${isAbsolute(sock) ? sock : join(process.cwd(), sock)}`;
}
