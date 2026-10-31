// SPDX-License-Identifier: Apache-2.0
/**
 * Messages for errors raised by the SDK itself (server errors carry the broker's own
 * localised `message`). zh-CN is the default; English is complete.
 */
import type { Locale } from "./types.js";

type Params = Record<string, string | number>;
type Template = (p: Params) => string;

const zh = {
  network: (p) => `无法连接到 AI 通行证授权代理（${p.target}）：${p.detail}`,
  requestTimeout: (p) =>
    `请求授权代理超时（${p.ms} ms）。超时不代表外部操作没有发生；可使用相同的 idempotency_key 安全重试。`,
  waitTimeout: (p) => `等待结果超时，当前状态为 ${p.status}。等待超时绝不会被视为批准。`,
  aborted: () => "请求已被调用方取消。",
  invalidResponse: (p) => `授权代理返回了无法识别的响应（HTTP ${p.status}）。`,
  responseTooLarge: (p) => `授权代理的响应超过上限（${p.limit} 字节）。`,
  approvalRequired: () => "请在已配对的手机或可信客户端批准本次访问。",
  approvalDenied: () => "用户拒绝了本次请求。",
  approvalExpired: () => "批准窗口已过期，未获批准（不会自动批准）。",
  operationCancelled: () => "操作已取消。",
  operationFailed: (p) => `操作未成功完成（状态：${p.status}）。`,
  outcomeUnknown: () => "外部服务可能已经执行，结果未知；请先核实再决定是否重试。",
  pairingDenied: () => "连接请求被拒绝。",
  pairingExpired: () => "配对请求已过期，请重新发起。",
  pairingMismatch: () => "授权代理返回的连接 ID 与配对请求不一致。",
  noAuth: () => "缺少认证信息：请提供 connectionKey、keyFile 或 bearerToken 之一。",
  multipleAuth: () => "只能提供 connectionKey、keyFile、bearerToken 中的一种认证方式。",
  badToken: () => "bearerToken 必须是 aipc_（节点签发的连接令牌）或 aipa_（云端访问令牌）开头。",
  badUrl: (p) => `无效的授权代理地址：${p.detail}`,
  insecureHttp: (p) => `拒绝通过未加密的 http 连接远程主机 ${p.host}；请使用 https，或在确认风险后设置 allowInsecureHttp。`,
  keyFileMissing: (p) => `找不到连接密钥文件：${p.path}`,
  keyFilePerms: (p) => `连接密钥文件权限过宽（${p.mode}），其他用户可读取。请执行 chmod 600 ${p.path}。`,
  keyFileInvalid: (p) => `连接密钥文件格式无效：${p.detail}`,
  keyFileExists: (p) => `文件已存在，未覆盖：${p.path}`,
  keyMismatch: () => "连接密钥文件中的公钥与私钥不匹配。",
  invalidArgument: (p) => `参数无效：${p.detail}`,
  unknownTool: (p) => `未知的工具：${p.name}`,
} satisfies Record<string, Template>;

const en: Record<keyof typeof zh, Template> = {
  network: (p) => `Could not reach the AI Pass broker (${p.target}): ${p.detail}`,
  requestTimeout: (p) =>
    `The request to the AI Pass broker timed out after ${p.ms} ms. A timeout does not mean the external action did not happen; retry with the same idempotency_key.`,
  waitTimeout: (p) => `Timed out while waiting; the current status is ${p.status}. A wait timeout is never treated as approval.`,
  aborted: () => "The request was aborted by the caller.",
  invalidResponse: (p) => `The broker returned an unrecognised response (HTTP ${p.status}).`,
  responseTooLarge: (p) => `The broker response exceeded the limit (${p.limit} bytes).`,
  approvalRequired: () => "Please approve this access on your paired phone or trusted client.",
  approvalDenied: () => "The request was denied.",
  approvalExpired: () => "The approval window expired without approval (never auto-approved).",
  operationCancelled: () => "The operation was cancelled.",
  operationFailed: (p) => `The operation did not complete successfully (status: ${p.status}).`,
  outcomeUnknown: () => "The external service may have executed the action; the outcome is unknown. Verify before retrying.",
  pairingDenied: () => "The connection request was denied.",
  pairingExpired: () => "The pairing request expired; start a new one.",
  pairingMismatch: () => "The broker returned a connection id that does not match the pairing request.",
  noAuth: () => "Missing credentials: provide exactly one of connectionKey, keyFile or bearerToken.",
  multipleAuth: () => "Provide only one of connectionKey, keyFile or bearerToken.",
  badToken: () => "bearerToken must start with aipc_ (node-issued connection token) or aipa_ (cloud access token).",
  badUrl: (p) => `Invalid broker URL: ${p.detail}`,
  insecureHttp: (p) => `Refusing to talk to remote host ${p.host} over unencrypted http; use https, or set allowInsecureHttp if you accept the risk.`,
  keyFileMissing: (p) => `Connection key file not found: ${p.path}`,
  keyFilePerms: (p) => `Connection key file permissions are too open (${p.mode}); other users can read it. Run chmod 600 ${p.path}.`,
  keyFileInvalid: (p) => `Invalid connection key file: ${p.detail}`,
  keyFileExists: (p) => `File already exists, not overwritten: ${p.path}`,
  keyMismatch: () => "The public key in the connection key file does not match its private key.",
  invalidArgument: (p) => `Invalid argument: ${p.detail}`,
  unknownTool: (p) => `Unknown tool: ${p.name}`,
};

export type MessageKey = keyof typeof zh;

export function msg(locale: Locale | undefined, key: MessageKey, params: Params = {}): string {
  const table = locale === "en" ? en : zh;
  const template = table[key] as Template;
  return template(params);
}

export function normalizeLocale(locale: string | undefined): Locale {
  return typeof locale === "string" && locale.toLowerCase().startsWith("en") ? "en" : "zh-CN";
}
