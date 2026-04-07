//! Web Application Firewall — protects web-facing endpoints

use crate::{ThreatReport, Severity};
use regex::Regex;

pub struct WAF {
    sql_injection_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    blocked_domains: Vec<String>,
}

impl WAF {
    pub fn new() -> Self {
        WAF {
            sql_injection_patterns: vec![
                Regex::new(r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)").unwrap(),
                Regex::new(r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'1)").unwrap(),
                Regex::new(r"(?i)(exec\s*\(|execute\s*\(|xp_cmdshell)").unwrap(),
            ],
            xss_patterns: vec![
                Regex::new(r"<script[^>]*>").unwrap(),
                Regex::new(r"(?i)(javascript:|onerror=|onload=|onclick=)").unwrap(),
                Regex::new(r"(?i)(document\.cookie|window\.location|eval\()").unwrap(),
            ],
            blocked_domains: vec![
                "malware.example.com".to_string(),
            ],
        }
    }

    pub fn check_url(&self, url: &str) -> ThreatReport {
        // Check against blocked domains
        for domain in &self.blocked_domains {
            if url.contains(domain) {
                return ThreatReport::threat(
                    Severity::Critical,
                    "blocked_domain",
                    &format!("URL contains blocked domain: {}", domain),
                );
            }
        }

        // Check for SQL injection in URL parameters
        for pattern in &self.sql_injection_patterns {
            if pattern.is_match(url) {
                return ThreatReport::threat(
                    Severity::High,
                    "sql_injection",
                    "Potential SQL injection detected in URL",
                );
            }
        }

        // Check for XSS in URL parameters
        for pattern in &self.xss_patterns {
            if pattern.is_match(url) {
                return ThreatReport::threat(
                    Severity::High,
                    "xss",
                    "Potential XSS attack detected in URL",
                );
            }
        }

        ThreatReport::clean()
    }

    pub fn check_request_body(&self, body: &str) -> ThreatReport {
        for pattern in &self.sql_injection_patterns {
            if pattern.is_match(body) {
                return ThreatReport::threat(
                    Severity::High,
                    "sql_injection",
                    "Potential SQL injection detected in request body",
                );
            }
        }

        for pattern in &self.xss_patterns {
            if pattern.is_match(body) {
                return ThreatReport::threat(
                    Severity::High,
                    "xss",
                    "Potential XSS attack detected in request body",
                );
            }
        }

        ThreatReport::clean()
    }
}
