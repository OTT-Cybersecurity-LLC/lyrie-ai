/**
 * MCP wire-protocol types (subset — what Lyrie needs).
 *
 * Source of truth: https://modelcontextprotocol.io/specification
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Transport definitions ───────────────────────────────────────────────────

export interface StdioTransport {
  type: "stdio";
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface HttpTransport {
  type: "http" | "sse";
  url: string;
  headers?: Record<string, string>;
}

export type Transport = StdioTransport | HttpTransport;

// ─── JSON-RPC base ───────────────────────────────────────────────────────────

export interface JsonRpcRequest<P = unknown> {
  jsonrpc: "2.0";
  id: number | string;
  method: string;
  params?: P;
}

export interface JsonRpcNotification<P = unknown> {
  jsonrpc: "2.0";
  method: string;
  params?: P;
}

export interface JsonRpcResponse<R = unknown, E = unknown> {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: R;
  error?: { code: number; message: string; data?: E };
}

// ─── MCP method shapes (subset) ──────────────────────────────────────────────

export interface InitializeParams {
  protocolVersion: string;
  capabilities: ClientCapabilities;
  clientInfo: { name: string; version: string };
}

export interface ClientCapabilities {
  experimental?: Record<string, unknown>;
  sampling?: Record<string, unknown>;
  roots?: { listChanged?: boolean };
}

export interface ServerCapabilities {
  experimental?: Record<string, unknown>;
  logging?: Record<string, unknown>;
  prompts?: { listChanged?: boolean };
  resources?: { subscribe?: boolean; listChanged?: boolean };
  tools?: { listChanged?: boolean };
}

export interface InitializeResult {
  protocolVersion: string;
  capabilities: ServerCapabilities;
  serverInfo: { name: string; version: string };
  instructions?: string;
}

export interface Tool {
  name: string;
  description?: string;
  inputSchema: unknown;
}

export interface ListToolsResult {
  tools: Tool[];
  nextCursor?: string;
}

export interface CallToolParams {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface CallToolResult {
  content: Array<TextContent | ImageContent | ResourceContent>;
  isError?: boolean;
}

export interface TextContent {
  type: "text";
  text: string;
}
export interface ImageContent {
  type: "image";
  data: string;
  mimeType: string;
}
export interface ResourceContent {
  type: "resource";
  resource: { uri: string; mimeType?: string; text?: string; blob?: string };
}

export interface Resource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface ListResourcesResult {
  resources: Resource[];
  nextCursor?: string;
}

// ─── Lyrie config shapes ─────────────────────────────────────────────────────

export interface McpServerConfig {
  /** Human name used in tool prefixes (e.g. "filesystem") */
  name?: string;
  /** stdio transport */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  /** http/sse transport */
  url?: string;
  headers?: Record<string, string>;
  transportType?: "stdio" | "http" | "sse";
  /** Optional per-server allow/deny lists */
  allowTools?: string[];
  denyTools?: string[];
  /** Disable a server without removing the config entry */
  disabled?: boolean;
}

export interface McpConfigFile {
  mcpServers: Record<string, McpServerConfig>;
}
