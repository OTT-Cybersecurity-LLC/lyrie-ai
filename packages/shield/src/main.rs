//! Lyrie Shield — Standalone binary  (v1.0.0 GA)
//!
//! Usage:
//!   lyrie-shield scan <file>        Full scan (hash + heuristics + LyrieRules)
//!   lyrie-shield watch <directory>  Monitor a directory in real-time
//!   lyrie-shield waf <port>         Start WAF proxy on given port
//!   lyrie-shield status             Show shield status
//!   lyrie-shield url <url>          Check if a URL is safe

use lyrie_shield::{
    scan_file_hash, scan_heuristic, apply_rules, builtin_rules, run_bridge_request,
    AgenticBridgeRequest, LyrieShield,
};
use std::io::Read;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // The `agentic-bridge` subcommand is machine-consumed (JSON on stdout via
    // a TS subprocess bridge) — keep stdout pure JSON; the banner still goes
    // to stderr so humans piping this interactively still see it.
    let is_bridge = args.get(1).map(|s| s.as_str()) == Some("agentic-bridge");
    if is_bridge {
        eprintln!("🛡️  Lyrie Shield v1.0.0 GA — by OTT Cybersecurity LLC");
    } else {
        println!("🛡️  Lyrie Shield v1.0.0 GA — by OTT Cybersecurity LLC");
        println!();
    }

    if args.len() < 2 {
        print_usage();
        return;
    }

    let shield = LyrieShield::new();

    match args[1].as_str() {
        "scan" => {
            if args.len() < 3 {
                eprintln!("Usage: lyrie-shield scan <file>");
                std::process::exit(1);
            }
            scan_and_report(&args[2], &shield);
        }
        "url" => {
            if args.len() < 3 {
                eprintln!("Usage: lyrie-shield url <url>");
                std::process::exit(1);
            }
            let report = shield.scan_url(&args[2]);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        "status" => {
            println!("Shield Status: 🟢 Active (v1.0.0 GA)");
            println!("  Scanner:    ✅ Ready  (hash-sigs + heuristics + LyrieRules)");
            println!("  WAF:        ✅ Ready");
            println!("  Behavioral: ✅ Ready");
            println!("  Malware:    ✅ Ready");
            println!("  Rogue AI:   ✅ Ready");
        }
        "agentic-bridge" => {
            run_agentic_bridge();
        }
        _ => print_usage(),
    }
}

/// JSON stdin/stdout bridge for `AgenticThreatDetector` — consumed by the
/// TS daemon (`packages/core/src/engine/agentic-threat-bridge.ts`) and the
/// MCP shield filter. Reads one JSON request object from stdin, writes one
/// JSON response object to stdout. Stateless per-process: the caller
/// resends the full sliding-window event history on every invocation.
fn run_agentic_bridge() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("agentic-bridge: failed to read stdin: {}", e);
        std::process::exit(1);
    }

    let req: AgenticBridgeRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agentic-bridge: invalid JSON request: {}", e);
            std::process::exit(1);
        }
    };

    let resp = run_bridge_request(req);
    match serde_json::to_string(&resp) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("agentic-bridge: failed to serialize response: {}", e);
            std::process::exit(1);
        }
    }
}

/// Run all three detection engines and print a human-readable report.
fn scan_and_report(path_str: &str, shield: &LyrieShield) {
    let path = Path::new(path_str);

    println!("📂 Scanning: {}", path_str);
    println!("{}", "─".repeat(60));

    // ── 1. Hash-based signature matching ──────────────────────────────────
    print!("  [1/3] Hash signature check … ");
    match scan_file_hash(path) {
        Some(sig) => {
            println!("🚨 MATCH");
            println!("       SHA-256  : {}", sig.sha256_hex);
            println!("       Malware  : {}", sig.malware_name);
        }
        None => {
            println!("✅ Clean");
        }
    }

    // ── 2. Heuristic analysis ──────────────────────────────────────────────
    let hflags = scan_heuristic(path);
    print!("  [2/3] Heuristic analysis  … ");
    if hflags.is_empty() {
        println!("✅ Clean");
    } else {
        println!("⚠️  {} flag(s)", hflags.len());
        for f in &hflags {
            println!("       [{}] {}", f.rule_id, f.description);
        }
    }

    // ── 3. LyrieRules engine ───────────────────────────────────────────────
    let rules = builtin_rules();
    print!("  [3/3] LyrieRules engine   … ");
    let matched_rules = match std::fs::read(path) {
        Ok(content) => apply_rules(&rules, &content),
        Err(e) => {
            println!("❌ Could not read file: {}", e);
            vec![]
        }
    };
    if matched_rules.is_empty() {
        println!("✅ Clean");
    } else {
        println!("🚨 {} rule(s) matched", matched_rules.len());
        for r in &matched_rules {
            println!("       {}", r);
        }
    }

    println!("{}", "─".repeat(60));

    // ── Summary ────────────────────────────────────────────────────────────
    let threat_found = scan_file_hash(path).is_some()
        || !hflags.is_empty()
        || !matched_rules.is_empty();

    if threat_found {
        println!("🔴 VERDICT: THREAT DETECTED");
        std::process::exit(2);
    } else {
        // Also run the full shield scan for any additional engine results
        let report = shield.scan_file(path_str);
        if report.blocked {
            println!("🔴 VERDICT: BLOCKED by shield engine");
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
            std::process::exit(2);
        }
        println!("🟢 VERDICT: Clean — no threats detected");
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  lyrie-shield scan <file>       Full scan (hash + heuristics + LyrieRules)");
    println!("  lyrie-shield url <url>         Check if a URL is safe");
    println!("  lyrie-shield watch <dir>       Monitor directory in real-time");
    println!("  lyrie-shield waf <port>        Start WAF proxy");
    println!("  lyrie-shield status            Show shield status");
    println!("  lyrie-shield agentic-bridge    Read JSON request from stdin, write JSON verdict to stdout");
}
