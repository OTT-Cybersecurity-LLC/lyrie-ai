//! JSON-RPC server over stdin/stdout.
//!
//! Protocol: newline-delimited JSON.
//! Request:  {"id": 1, "method": "scan_file",  "params": {"path": "...", "content": "..."}}
//! Request:  {"id": 2, "method": "analyze_tool_sequence", "params": {"calls": [...]}}
//! Request:  {"id": 3, "method": "scan_outbound_request", "params": {"url": "...", "headers": {}, "body": "..."}}
//! Request:  {"id": 4, "method": "status", "params": {}}
//! Response: {"id": 1, "result": {"clean": true, "threats": [], "latency_ms": 0.8}}
//! Error:    {"id": 1, "error": "message"}

use crate::LyrieShield;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, Write};
use std::time::Instant;

// ─── Request / Response ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub id: Value,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub clean: bool,
    pub threats: Vec<String>,
    pub latency_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct BehaviorReport {
    pub suspicious: bool,
    pub threats: Vec<String>,
    pub latency_ms: f64,
}

// ─── Params shapes ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ScanFileParams {
    path: String,
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ToolCall {
    tool: String,
    args: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct AnalyzeToolSequenceParams {
    calls: Vec<ToolCall>,
}

#[derive(Debug, Deserialize)]
struct ScanOutboundRequestParams {
    url: String,
    headers: Option<Value>,
    body: Option<String>,
}

// ─── RPC Server ──────────────────────────────────────────────────────────────

pub fn run_rpc_server(shield: &LyrieShield) {
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = handle_line(&line, shield);
        let json = serde_json::to_string(&response).unwrap_or_else(|e| {
            format!(r#"{{"id":null,"error":"Serialization error: {}"}}"#, e)
        });

        let mut out = stdout.lock();
        writeln!(out, "{}", json).ok();
        out.flush().ok();
    }
}

fn handle_line(line: &str, shield: &LyrieShield) -> RpcResponse {
    let request: RpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return RpcResponse {
                id: Value::Null,
                result: None,
                error: Some(format!("Parse error: {}", e)),
            }
        }
    };

    let id = request.id.clone();
    match dispatch(&request, shield) {
        Ok(result) => RpcResponse {
            id,
            result: Some(result),
            error: None,
        },
        Err(msg) => RpcResponse {
            id,
            result: None,
            error: Some(msg),
        },
    }
}

fn dispatch(req: &RpcRequest, shield: &LyrieShield) -> Result<Value, String> {
    match req.method.as_str() {
        "scan_file" => {
            let params: ScanFileParams = parse_params(&req.params)?;
            let start = Instant::now();

            // If content provided, write to a temp file for scanning, or scan
            // the existing path. We use the behavioral analyzer on the content
            // and the file scanner on the path.
            let threat = if let Some(ref content) = params.content {
                shield.behavioral.analyze_command(content)
            } else {
                shield.scan_file(&params.path)
            };

            // Also run WAF on path itself
            let waf_result = shield.waf.check_url(&params.path);

            let latency = start.elapsed().as_secs_f64() * 1000.0;

            let mut threats: Vec<String> = Vec::new();
            if threat.blocked || threat.threat_type.is_some() {
                if let Some(desc) = &threat.description {
                    threats.push(desc.clone());
                }
                if let Some(t) = &threat.threat_type {
                    threats.push(format!("type:{}", t));
                }
            }
            if waf_result.blocked {
                if let Some(desc) = &waf_result.description {
                    threats.push(desc.clone());
                }
            }

            let result = ScanResult {
                clean: threats.is_empty(),
                threats,
                latency_ms: (latency * 10.0).round() / 10.0,
            };
            Ok(serde_json::to_value(result).unwrap())
        }

        "analyze_tool_sequence" => {
            let params: AnalyzeToolSequenceParams = parse_params(&req.params)?;
            let start = Instant::now();

            let dangerous_tools = ["exec", "bash", "shell", "python", "node"];
            let mut threats: Vec<String> = Vec::new();
            let mut dangerous_count = 0u32;

            for call in &params.calls {
                // Flag dangerous tool usage
                if dangerous_tools.contains(&call.tool.as_str()) {
                    dangerous_count += 1;

                    // If args contain a command, run behavioral analysis
                    if let Some(args) = &call.args {
                        let cmd = extract_command(args);
                        if !cmd.is_empty() {
                            let report = shield.behavioral.analyze_command(&cmd);
                            if report.blocked || report.threat_type.is_some() {
                                if let Some(desc) = &report.description {
                                    threats.push(format!("[{}] {}", call.tool, desc));
                                }
                            }
                        }
                    }
                }

                // Repeated dangerous calls = suspicious
                if dangerous_count >= 5 {
                    threats.push(format!(
                        "Repeated dangerous tool calls: {} uses of exec/shell-like tools",
                        dangerous_count
                    ));
                    break;
                }
            }

            let latency = start.elapsed().as_secs_f64() * 1000.0;
            let report = BehaviorReport {
                suspicious: !threats.is_empty(),
                threats,
                latency_ms: (latency * 10.0).round() / 10.0,
            };
            Ok(serde_json::to_value(report).unwrap())
        }

        "scan_outbound_request" => {
            let params: ScanOutboundRequestParams = parse_params(&req.params)?;
            let start = Instant::now();

            let url_result = shield.waf.check_url(&params.url);
            let mut threats: Vec<String> = Vec::new();

            if url_result.blocked || url_result.threat_type.is_some() {
                if let Some(desc) = &url_result.description {
                    threats.push(desc.clone());
                }
            }

            if let Some(body) = &params.body {
                if !body.is_empty() {
                    let body_result = shield.waf.check_request_body(body);
                    if body_result.blocked || body_result.threat_type.is_some() {
                        if let Some(desc) = &body_result.description {
                            threats.push(desc.clone());
                        }
                    }
                }
            }

            let latency = start.elapsed().as_secs_f64() * 1000.0;
            let result = ScanResult {
                clean: threats.is_empty(),
                threats,
                latency_ms: (latency * 10.0).round() / 10.0,
            };
            Ok(serde_json::to_value(result).unwrap())
        }

        "status" => Ok(serde_json::json!({
            "status": "active",
            "version": "0.1.0",
            "modules": ["scanner", "waf", "behavioral", "malware", "rogue_ai"]
        })),

        unknown => Err(format!("Unknown method: {}", unknown)),
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn parse_params<T: for<'de> Deserialize<'de>>(params: &Option<Value>) -> Result<T, String> {
    let val = params.as_ref().cloned().unwrap_or(Value::Object(Default::default()));
    serde_json::from_value(val).map_err(|e| format!("Invalid params: {}", e))
}

fn extract_command(args: &Value) -> String {
    // Try common field names for shell commands
    for key in &["command", "cmd", "script", "code", "input"] {
        if let Some(v) = args.get(key) {
            if let Some(s) = v.as_str() {
                return s.to_string();
            }
        }
    }
    String::new()
}
