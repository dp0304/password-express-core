// SPDX-License-Identifier: Apache-2.0
/**
 * @aipass/sdk — AI 通行证 (AI Pass) SDK for custom agents.
 *
 * Agents discover resources, request structured operations, wait for the user's approval on a
 * trusted device, and read permitted results — without ever seeing raw credentials.
 */
export { VERSION } from "./version.js";

export {
  AIPassClient,
  errorForOperation,
  generateIdempotencyKey,
  type AIPassClientOptions,
  type FindResourceQuery,
  type RequestOperationOptions,
  type RequestOptions,
  type WaitForAccessOptions,
  type WaitForOperationOptions,
} from "./client.js";

export {
  pair,
  PairingSession,
  startPairing,
  type PairingConnectionOptions,
  type PairingInfo,
  type PairingResult,
  type PairOptions,
  type StartPairingOptions,
  type WaitForPairingOptions,
} from "./pairing.js";

export {
  buildStringToSign,
  ConnectionKey,
  formatAuthorization,
  NONCE_BYTES,
  parseAuthorization,
  SIGNATURE_SCHEME,
  signRequest,
  SigningKey,
  STRING_TO_SIGN_VERSION,
  verifySignature,
  type SignedRequest,
  type SignRequestInput,
} from "./signing.js";

export { KEY_FILE_FORMAT, loadConnectionKey, saveConnectionKey, type KeyFileMetadata, type LoadedKeyFile, type LoadKeyOptions, type SaveKeyOptions } from "./keyfile.js";

export { b64uDecode, b64uEncode, sha256B64u } from "./encoding.js";

export { aipassHome, isLoopbackHost, parseBrokerUrl, resolveBrokerUrl, type BrokerEndpoint, type ParseBrokerUrlOptions } from "./url.js";

export { NodeHttpTransport, type NodeHttpTransportOptions, type Transport, type TransportRequest, type TransportResponse } from "./transport.js";

export { BearerAuthenticator, SignatureAuthenticator, type Authenticator } from "./auth.js";

export type { Logger } from "./core.js";

export { backoffDelay, jittered, poll, resolveBackoff, type BackoffOptions, type PollOptions, type PollOutcome } from "./wait.js";

export {
  anthropicTools,
  canonicalToolName,
  handleToolCall,
  jsonSchemaTools,
  openAIResponsesTools,
  openAITools,
  systemPrompt,
  toAnthropicToolResult,
  TOOL_ALIASES,
  TOOL_NAMES,
  toolDefinitions,
  toOpenAIResponsesOutput,
  toOpenAIToolMessage,
  type HandleToolCallOptions,
  type JsonSchema,
  type ToolCallResult,
  type ToolDefinition,
  type ToolName,
  type ToolOptions,
} from "./tools.js";

export {
  AbortedError,
  AIPassError,
  AIPassTimeoutError,
  ApprovalDeniedError,
  ApprovalExpiredError,
  ApprovalRequiredError,
  BudgetExhaustedError,
  ConfigError,
  ConnectionPausedError,
  ControlChannelLostError,
  ERROR_CODES,
  errorClassForCode,
  errorFromCode,
  errorFromResponse,
  ExecutorOfflineError,
  ForbiddenError,
  GrantExpiredError,
  GrantRevokedError,
  IdempotencyConflictError,
  IdentityUnverifiedError,
  IntegrityFailedError,
  InteractiveAuthRequiredError,
  InternalError,
  InvalidRequestError,
  InvalidResponseError,
  NetworkError,
  NotFoundError,
  NotSupportedError,
  OperationCancelledError,
  PaymentRequiredError,
  PreconditionFailedError,
  QuotaExceededError,
  RateLimitedError,
  ResultRestrictedError,
  RollbackDetectedError,
  ScopeDeniedError,
  SDK_ERROR_CODES,
  SecretUnavailableError,
  SyncConflictError,
  UnauthenticatedError,
  UpstreamError,
  UpstreamOutcomeUnknownError,
  type AIPassErrorOptions,
  type ErrorCode,
} from "./errors.js";

export {
  isTerminalAccessStatus,
  isTerminalOperationStatus,
  TERMINAL_ACCESS_STATUSES,
  TERMINAL_OPERATION_STATUSES,
  type AccessRequest,
  type AccessRequestResponse,
  type AccessRequestStatus,
  type CancelResponse,
  type ConnectionTransport,
  type ErrorBody,
  type GrantScope,
  type HealthResponse,
  type HostType,
  type Limits,
  type ListResourcesParams,
  type Locale,
  type OperationRequest,
  type OperationResponse,
  type OperationResult,
  type OperationSpecView,
  type OperationStatus,
  type PairRequestBody,
  type PairStartResponse,
  type PairStatus,
  type PairStatusResponse,
  type ReleaseResponse,
  type ResourceList,
  type ResourceStatus,
  type ResourceView,
  type SideEffects,
} from "./types.js";
