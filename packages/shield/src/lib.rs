//! Lyrie Shield — The cybersecurity engine for Lyrie Agent.
//! 
//! Built by OTT Cybersecurity LLC.
//! 
//! This is what makes Lyrie unique among all AI agents.
//! While other agents are naked, Lyrie has armor.
//!
//! Capabilities:
//! - Real-time file system monitoring and threat detection
//! - Malware signature scanning
//! - Behavioral analysis of processes
//! - Web Application Firewall (WAF)
//! - Rogue AI detection
//! - Blockchain verification
//! - Device protection across all platforms

pub mod scanner;
pub mod waf;
pub mod behavioral;
pub mod malware;
pub mod rogue_ai;

use serde::{Deserialize, Serialize};

/// Threat severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Result of a threat scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    pub blocked: bool,
    pub severity: Severity,
    pub threat_type: Option<String>,
    pub description: Option<String>,
    pub file_path: Option<String>,
    pub timestamp: String,
    pub action_taken: Option<String>,
}

impl ThreatReport {
    pub fn clean() -> Self {
        ThreatReport {
            blocked: false,
            severity: Severity::None,
            threat_type: None,
            description: None,
            file_path: None,
            timestamp: chrono_now(),
            action_taken: None,
        }
    }

    pub fn threat(severity: Severity, threat_type: &str, description: &str) -> Self {
        ThreatReport {
            blocked: severity == Severity::High || severity == Severity::Critical,
            severity,
            threat_type: Some(threat_type.to_string()),
            description: Some(description.to_string()),
            file_path: None,
            timestamp: chrono_now(),
            action_taken: None,
        }
    }
}

fn chrono_now() -> String {
    // Simple ISO timestamp without chrono dependency
    format!("{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs())
}

/// The main Shield instance
pub struct LyrieShield {
    pub scanner: scanner::Scanner,
    pub waf: waf::WAF,
    pub behavioral: behavioral::BehavioralAnalyzer,
    pub malware: malware::MalwareDetector,
    pub rogue_ai: rogue_ai::RogueAIDetector,
}

impl LyrieShield {
    pub fn new() -> Self {
        LyrieShield {
            scanner: scanner::Scanner::new(),
            waf: waf::WAF::new(),
            behavioral: behavioral::BehavioralAnalyzer::new(),
            malware: malware::MalwareDetector::new(),
            rogue_ai: rogue_ai::RogueAIDetector::new(),
        }
    }

    /// Run a full security scan on a file
    pub fn scan_file(&self, path: &str) -> ThreatReport {
        // Run through all detection engines
        let malware_result = self.malware.scan_file(path);
        if malware_result.blocked {
            return malware_result;
        }

        let behavioral_result = self.behavioral.analyze_file(path);
        if behavioral_result.blocked {
            return behavioral_result;
        }

        ThreatReport::clean()
    }

    /// Check if a URL is safe
    pub fn scan_url(&self, url: &str) -> ThreatReport {
        self.waf.check_url(url)
    }

    /// Check for rogue AI behavior in agent output
    pub fn scan_agent_output(&self, output: &str) -> ThreatReport {
        self.rogue_ai.analyze(output)
    }
}
