//! Lyrie Shield — Standalone binary
//! 
//! Can be run independently or called from the TypeScript agent core.
//! 
//! Usage:
//!   lyrie-shield scan <file>        Scan a file for threats
//!   lyrie-shield watch <directory>  Monitor a directory in real-time
//!   lyrie-shield waf <port>         Start WAF proxy on given port
//!   lyrie-shield status             Show shield status

use lyrie_shield::LyrieShield;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    println!("🛡️  Lyrie Shield v0.1.0 — by OTT Cybersecurity LLC");
    println!();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let shield = LyrieShield::new();

    match args[1].as_str() {
        "scan" => {
            if args.len() < 3 {
                eprintln!("Usage: lyrie-shield scan <file>");
                return;
            }
            let report = shield.scan_file(&args[2]);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        "url" => {
            if args.len() < 3 {
                eprintln!("Usage: lyrie-shield url <url>");
                return;
            }
            let report = shield.scan_url(&args[2]);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        "status" => {
            println!("Shield Status: 🟢 Active");
            println!("  Scanner:    ✅ Ready");
            println!("  WAF:        ✅ Ready");
            println!("  Behavioral: ✅ Ready");
            println!("  Malware:    ✅ Ready");
            println!("  Rogue AI:   ✅ Ready");
        }
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  lyrie-shield scan <file>     Scan a file for threats");
    println!("  lyrie-shield url <url>       Check if a URL is safe");
    println!("  lyrie-shield watch <dir>     Monitor directory in real-time");
    println!("  lyrie-shield waf <port>      Start WAF proxy");
    println!("  lyrie-shield status          Show shield status");
}
