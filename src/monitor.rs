use std::collections::HashSet;

use chrono::Utc;
use sysinfo::System;
use tracing::{info, warn};

use crate::config::MonitorConfig;
use crate::models::{Violation, ViolationKind};

/// Holds a system handle and the ban configuration.
pub struct Monitor {
    sys: System,
    banned_procs: HashSet<String>,
    banned_domains: HashSet<String>,
    hostname: String,
    username: String,
}

impl Monitor {
    pub fn new(cfg: &MonitorConfig, hostname: String, username: String) -> Self {
        // Store everything lowercased for case-insensitive matching
        let banned_procs = cfg
            .banned_processes
            .names
            .iter()
            .map(|n| n.to_lowercase())
            .collect();

        let banned_domains = cfg
            .banned_domains
            .names
            .iter()
            .map(|d| d.to_lowercase())
            .collect();

        Self {
            sys: System::new_all(),
            banned_procs,
            banned_domains,
            hostname,
            username,
        }
    }

    // ── Process scanning ────────────────────────────────────────

    /// Refresh process list, kill banned ones, return violations.
    pub fn scan_processes(&mut self) -> Vec<Violation> {
        self.sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

        let mut violations = Vec::new();

        for (pid, proc) in self.sys.processes() {
            let name = proc.name().to_string_lossy().to_lowercase();
            // Strip .exe suffix for matching
            let name_clean = name.strip_suffix(".exe").unwrap_or(&name);

            if self.banned_procs.contains(name_clean) || self.banned_procs.contains(&*name) {
                info!("🚫 Banned process detected: {} (PID {})", name, pid);

                let killed = proc.kill();
                if killed {
                    info!("   ✅ Killed PID {pid}");
                } else {
                    warn!("   ⚠️  Failed to kill PID {pid}");
                }

                violations.push(Violation {
                    hostname: self.hostname.clone(),
                    target: name.clone(),
                    kind: ViolationKind::Process,
                    action_taken: killed,
                    username: self.username.clone(),
                    timestamp: Utc::now(),
                });
            }
        }

        violations
    }

    // ── DNS cache scanning (Windows) ────────────────────────────

    /// Parse `ipconfig /displaydns` output for banned domains.
    pub fn scan_dns_cache(&self) -> Vec<Violation> {
        let output = match std::process::Command::new("ipconfig")
            .arg("/displaydns")
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                warn!("Could not run ipconfig /displaydns: {e}");
                return Vec::new();
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        let mut violations = Vec::new();
        let mut seen = HashSet::new();

        for domain in &self.banned_domains {
            if stdout.contains(domain.as_str()) && seen.insert(domain.clone()) {
                info!("🌐 Banned domain found in DNS cache: {domain}");

                violations.push(Violation {
                    hostname: self.hostname.clone(),
                    target: domain.clone(),
                    kind: ViolationKind::Domain,
                    action_taken: false, // DNS flush happens below
                    username: self.username.clone(),
                    timestamp: Utc::now(),
                });
            }
        }

        // Flush the DNS cache so we detect *new* visits next cycle
        if !violations.is_empty() {
            self.flush_dns();
        }

        violations
    }

    /// Flush the Windows DNS resolver cache.
    fn flush_dns(&self) {
        match std::process::Command::new("ipconfig")
            .arg("/flushdns")
            .output()
        {
            Ok(_) => info!("DNS cache flushed"),
            Err(e) => warn!("Failed to flush DNS cache: {e}"),
        }
    }

    // ── Browser window title scanning ───────────────────────────

    /// On Windows, enumerate top-level window titles to catch banned sites
    /// even when DNS caching is unreliable. This shells out to a tiny
    /// PowerShell one-liner for zero extra dependencies.
    pub fn scan_window_titles(&self) -> Vec<Violation> {
        let ps_script = r#"Get-Process | Where-Object {$_.MainWindowTitle -ne ''} | Select-Object -ExpandProperty MainWindowTitle"#;

        let output = match std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_script])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                warn!("PowerShell window title scan failed: {e}");
                return Vec::new();
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        let mut violations = Vec::new();
        let mut seen = HashSet::new();

        for domain in &self.banned_domains {
            // Check both the full domain and the base name (e.g. "roblox")
            let base = domain.split('.').next().unwrap_or(domain);
            if (stdout.contains(domain.as_str()) || stdout.contains(base))
                && seen.insert(domain.clone())
            {
                info!("🪟 Banned site detected in window title: {domain}");
                violations.push(Violation {
                    hostname: self.hostname.clone(),
                    target: domain.clone(),
                    kind: ViolationKind::Domain,
                    action_taken: false,
                    username: self.username.clone(),
                    timestamp: Utc::now(),
                });
            }
        }

        violations
    }

    // ── Full scan (combines all methods) ────────────────────────

    /// Run every detection method and return combined violations.
    pub fn full_scan(&mut self) -> Vec<Violation> {
        let mut all = self.scan_processes();
        all.extend(self.scan_dns_cache());
        all.extend(self.scan_window_titles());
        all
    }
}
