//! File scanner — monitors file system for threats

use crate::ThreatReport;

pub struct Scanner {
    watched_paths: Vec<String>,
}

impl Scanner {
    pub fn new() -> Self {
        Scanner {
            watched_paths: vec![],
        }
    }

    pub fn watch(&mut self, path: &str) {
        self.watched_paths.push(path.to_string());
    }

    pub fn scan_file(&self, path: &str) -> ThreatReport {
        // Check file extension for known dangerous types
        let dangerous_extensions = [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js.download"];
        
        for ext in &dangerous_extensions {
            if path.to_lowercase().ends_with(ext) {
                return ThreatReport::threat(
                    crate::Severity::Medium,
                    "suspicious_extension",
                    &format!("File has potentially dangerous extension: {}", ext),
                );
            }
        }

        // TODO: Hash-based signature matching
        // TODO: Heuristic analysis
        // TODO: YARA rules integration

        ThreatReport::clean()
    }
}
