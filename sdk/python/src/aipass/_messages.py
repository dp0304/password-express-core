# SPDX-License-Identifier: Apache-2.0
"""Messages for errors raised by the SDK itself (broker errors carry the broker's own localised
``message``). zh-CN is the default; English is complete."""

from __future__ import annotations

from typing import Dict, Optional

_ZH: Dict[str, str] = {
    "network": "无法连接到 AI 通行证授权代理（{target}）：{detail}",
    "request_timeout": "请求授权代理超时（{seconds} 秒）。超时不代表外部操作没有发生；可使用相同的 idempotency_key 安全重试。",
    "wait_timeout": "等待结果超时，当前状态为 {status}。等待超时绝不会被视为批准。",
    "aborted": "请求已被调用方取消。",
    "invalid_response": "授权代理返回了无法识别的响应（HTTP {status}）。",
    "response_too_large": "授权代理的响应超过上限（{limit} 字节）。",
    "approval_required": "请在已配对的手机或可信客户端批准本次访问。",
    "approval_denied": "用户拒绝了本次请求。",
    "approval_expired": "批准窗口已过期，未获批准（不会自动批准）。",
    "operation_cancelled": "操作已取消。",
    "operation_failed": "操作未成功完成（状态：{status}）。",
    "outcome_unknown": "外部服务可能已经执行，结果未知；请先核实再决定是否重试。",
    "pairing_mismatch": "授权代理返回的连接 ID 与配对请求不一致。",
    "no_auth": "缺少认证信息：请提供 connection_key、key_file 或 bearer_token 之一。",
    "multiple_auth": "只能提供 connection_key、key_file、bearer_token 中的一种认证方式。",
    "bad_token": "bearer_token 必须是 aipc_（节点签发的连接令牌）或 aipa_（云端访问令牌）开头。",
    "bad_url": "无效的授权代理地址：{detail}",
    "insecure_http": "拒绝通过未加密的 http 连接远程主机 {host}；请使用 https，或在确认风险后设置 allow_insecure_http。",
    "key_file_missing": "找不到连接密钥文件：{path}",
    "key_file_perms": "连接密钥文件权限过宽（{mode}），其他用户可读取。请执行 chmod 600 {path}。",
    "key_file_invalid": "连接密钥文件格式无效：{detail}",
    "key_file_exists": "文件已存在，未覆盖：{path}",
    "key_mismatch": "连接密钥文件中的公钥与私钥不匹配。",
    "invalid_argument": "参数无效：{detail}",
    "unknown_tool": "未知的工具：{name}",
}

_EN: Dict[str, str] = {
    "network": "Could not reach the AI Pass broker ({target}): {detail}",
    "request_timeout": (
        "The request to the AI Pass broker timed out after {seconds} s. A timeout does not mean the external "
        "action did not happen; retry with the same idempotency_key."
    ),
    "wait_timeout": "Timed out while waiting; the current status is {status}. A wait timeout is never treated as approval.",
    "aborted": "The request was aborted by the caller.",
    "invalid_response": "The broker returned an unrecognised response (HTTP {status}).",
    "response_too_large": "The broker response exceeded the limit ({limit} bytes).",
    "approval_required": "Please approve this access on your paired phone or trusted client.",
    "approval_denied": "The request was denied.",
    "approval_expired": "The approval window expired without approval (never auto-approved).",
    "operation_cancelled": "The operation was cancelled.",
    "operation_failed": "The operation did not complete successfully (status: {status}).",
    "outcome_unknown": "The external service may have executed the action; the outcome is unknown. Verify before retrying.",
    "pairing_mismatch": "The broker returned a connection id that does not match the pairing request.",
    "no_auth": "Missing credentials: provide exactly one of connection_key, key_file or bearer_token.",
    "multiple_auth": "Provide only one of connection_key, key_file or bearer_token.",
    "bad_token": "bearer_token must start with aipc_ (node-issued connection token) or aipa_ (cloud access token).",
    "bad_url": "Invalid broker URL: {detail}",
    "insecure_http": (
        "Refusing to talk to remote host {host} over unencrypted http; use https, or set allow_insecure_http "
        "if you accept the risk."
    ),
    "key_file_missing": "Connection key file not found: {path}",
    "key_file_perms": "Connection key file permissions are too open ({mode}); other users can read it. Run chmod 600 {path}.",
    "key_file_invalid": "Invalid connection key file: {detail}",
    "key_file_exists": "File already exists, not overwritten: {path}",
    "key_mismatch": "The public key in the connection key file does not match its private key.",
    "invalid_argument": "Invalid argument: {detail}",
    "unknown_tool": "Unknown tool: {name}",
}

assert set(_ZH) == set(_EN)


def normalize_locale(locale: Optional[str]) -> str:
    return "en" if isinstance(locale, str) and locale.lower().startswith("en") else "zh-CN"


def msg(locale: Optional[str], key: str, **params: object) -> str:
    table = _EN if normalize_locale(locale) == "en" else _ZH
    return table[key].format(**params)
