//! Behavioral Analysis — detects suspicious process and file behavior.
//!
//! Upgraded from naive string-matching to a phase-aware classifier that maps
//! commands to `AttackPhase` and feeds the `AgenticThreatDetector`.

use crate::agentic_threat::{classify_command, AgenticThreatDetector, AttackPhase};
use crate::{Severity, ThreatReport};

pub struct BehavioralAnalyzer {
    /// Legacy string patterns for file-content analysis (kept for backwards compat).
    suspicious_patterns: Vec<String>,
    /// Agentic threat detector for command-level phase-aware analysis.
    agentic: AgenticThreatDetector,
}

impl BehavioralAnalyzer {
    pub fn new() -> Self {
        BehavioralAnalyzer {
            suspicious_patterns: vec![
                "rm -rf /".to_string(),
                "chmod 777".to_string(),
                "wget http".to_string(),
                "curl | bash".to_string(),
                "base64 -d".to_string(),
                "nc -e /bin".to_string(),
                "/dev/tcp/".to_string(),
                "mkfifo".to_string(),
            ],
            agentic: AgenticThreatDetector::new(),
        }
    }

    pub fn analyze_file(&self, path: &str) -> ThreatReport {
        // Read file content and check for suspicious patterns
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return ThreatReport::clean(), // Can't read = skip
        };

        for pattern in &self.suspicious_patterns {
            if content.contains(pattern) {
                return ThreatReport::threat(
                    Severity::High,
                    "suspicious_behavior",
                    &format!("File contains suspicious pattern: {}", pattern),
                );
            }
        }

        ThreatReport::clean()
    }

    /// Phase-aware command analyzer.
    ///
    /// Maps the command to an `AttackPhase`, feeds it into the sliding-window
    /// `AgenticThreatDetector`, then returns a report based on either:
    /// 1. The phase classification itself (instant risk), or
    /// 2. Attack-compression detection across the session window.
    ///
    /// Legacy dangerous-pattern check runs first for backwards compatibility.
    pub fn analyze_command(&mut self, command: &str) -> ThreatReport {
        // 1. Legacy dangerous-pattern check (fast path)
        for pattern in &self.suspicious_patterns {
            if command.contains(pattern.as_str()) {
                return ThreatReport::threat(
                    Severity::Critical,
                    "dangerous_command",
                    &format!("Command contains dangerous pattern: {}", pattern),
                );
            }
        }

        // 2. Prompt injection check
        if let Some(report) = self.agentic.scan_for_prompt_injection(command) {
            return report;
        }

        // 3. Phase classification
        let tool_name = command.split_whitespace().next().unwrap_or("unknown");
        let phase = classify_command(command);

        if let Some(ref p) = phase {
            // Ingest into the sliding window
            self.agentic.ingest_command(command, tool_name);

            // Immediately critical phases
            let instant_severity = match p {
                AttackPhase::Exfiltration => Some(Severity::High),
                AttackPhase::SelfPropagation => Some(Severity::Critical),
                AttackPhase::PromptInjection => Some(Severity::Critical),
                AttackPhase::LateralMovement => Some(Severity::High),
                AttackPhase::Persistence => Some(Severity::Medium),
                _ => None,
            };

            if let Some(sev) = instant_severity {
                return ThreatReport::threat(
                    sev,
                    &format!("agentic_phase_{}", p.as_str().to_lowercase()),
                    &format!("Command classified as {:?} phase: {}", p, command),
                );
            }
        } else {
            // Still ingest with unknown phase for gap-timing purposes
            self.agentic.ingest_command(command, tool_name);
        }

        // 4. Attack compression across window
        let sig = self.agentic.detect_attack_compression();
        if sig.threat_level != Severity::None {
            return AgenticThreatDetector::signature_to_report(&sig);
        }

        ThreatReport::clean()
    }
}
