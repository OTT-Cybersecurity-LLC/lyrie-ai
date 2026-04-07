//! Rogue AI Detection — monitors agent output for signs of manipulation
//!
//! This is a UNIQUE capability of Lyrie. No other agent has this.
//! 
//! Detects:
//! - Prompt injection attempts in agent output
//! - Attempts to exfiltrate credentials or data
//! - Self-replication or resource acquisition behavior
//! - Attempts to bypass safety controls
//! - Social engineering patterns

use crate::{ThreatReport, Severity};
use regex::Regex;

pub struct RogueAIDetector {
    exfiltration_patterns: Vec<Regex>,
    self_replication_patterns: Vec<Regex>,
    manipulation_patterns: Vec<Regex>,
}

impl RogueAIDetector {
    pub fn new() -> Self {
        RogueAIDetector {
            exfiltration_patterns: vec![
                Regex::new(r"(?i)(send|post|upload|transmit).*(api.key|password|secret|token|credential)").unwrap(),
                Regex::new(r"(?i)(curl|wget|fetch).*(webhook|external|ngrok)").unwrap(),
                Regex::new(r"(?i)base64.*(key|password|secret)").unwrap(),
            ],
            self_replication_patterns: vec![
                Regex::new(r"(?i)(copy|replicate|clone)\s*(myself|this agent|the system)").unwrap(),
                Regex::new(r"(?i)(create|spawn|start)\s*(another|new|additional)\s*(instance|agent|copy)").unwrap(),
                Regex::new(r"(?i)(modify|change|update)\s*(my|the)\s*(system prompt|instructions|rules)").unwrap(),
            ],
            manipulation_patterns: vec![
                Regex::new(r"(?i)(ignore|override|bypass)\s*(previous|safety|security|rules)").unwrap(),
                Regex::new(r"(?i)(pretend|act as if|you are now)\s*(a different|not an|no longer)").unwrap(),
                Regex::new(r"(?i)(don't tell|hide from|keep secret from)\s*(the user|the human|guy)").unwrap(),
            ],
        }
    }

    pub fn analyze(&self, output: &str) -> ThreatReport {
        // Check for credential exfiltration
        for pattern in &self.exfiltration_patterns {
            if pattern.is_match(output) {
                return ThreatReport::threat(
                    Severity::Critical,
                    "credential_exfiltration",
                    "Agent output contains potential credential exfiltration attempt",
                );
            }
        }

        // Check for self-replication
        for pattern in &self.self_replication_patterns {
            if pattern.is_match(output) {
                return ThreatReport::threat(
                    Severity::High,
                    "self_replication",
                    "Agent output contains potential self-replication behavior",
                );
            }
        }

        // Check for manipulation
        for pattern in &self.manipulation_patterns {
            if pattern.is_match(output) {
                return ThreatReport::threat(
                    Severity::High,
                    "manipulation",
                    "Agent output contains potential safety bypass attempt",
                );
            }
        }

        ThreatReport::clean()
    }
}
