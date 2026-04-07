//! Behavioral Analysis — detects suspicious process and file behavior

use crate::{ThreatReport, Severity};

pub struct BehavioralAnalyzer {
    suspicious_patterns: Vec<String>,
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

    pub fn analyze_command(&self, command: &str) -> ThreatReport {
        for pattern in &self.suspicious_patterns {
            if command.contains(pattern) {
                return ThreatReport::threat(
                    Severity::Critical,
                    "dangerous_command",
                    &format!("Command contains dangerous pattern: {}", pattern),
                );
            }
        }

        ThreatReport::clean()
    }
}
