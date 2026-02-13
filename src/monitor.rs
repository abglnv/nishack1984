use std::collections::HashSet;

use chrono::Utc;
use sysinfo::System;
use tracing::{info, warn};

use crate::config::MonitorConfig;
use crate::models::{Violation, ViolationKind};

/// Create a `Command` that will NOT pop up a console window on Windows.
#[cfg(target_os = "windows")]
fn silent_cmd(program: &str) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new(program);
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd
}

#[cfg(not(target_os = "windows"))]
fn silent_cmd(program: &str) -> std::process::Command {
    std::process::Command::new(program)
}

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

    /// Hot-reload ban lists from centrally-managed config.
    pub fn update_bans(&mut self, banned_procs: Vec<String>, banned_domains: Vec<String>) {
        self.banned_procs = banned_procs.iter().map(|n| n.to_lowercase()).collect();
        self.banned_domains = banned_domains.iter().map(|d| d.to_lowercase()).collect();
        info!("🔄 Ban lists updated: {} processes, {} domains",
            self.banned_procs.len(), self.banned_domains.len());
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

    // ── DNS cache scanning (Cross-platform) ─────────────────────

    /// Parse DNS cache output for banned domains.
    /// Windows: ipconfig /displaydns
    /// macOS/Linux: dscacheutil -cachedump or parse browser history/network logs
    pub fn scan_dns_cache(&self) -> Vec<Violation> {
        let output = if cfg!(target_os = "windows") {
            match silent_cmd("ipconfig")
                .arg("/displaydns")
                .output()
            {
                Ok(o) => o,
                Err(e) => {
                    warn!("Could not run ipconfig /displaydns: {e}");
                    return Vec::new();
                }
            }
        } else if cfg!(target_os = "macos") {
            // On macOS, use dscacheutil to dump DNS cache
            match std::process::Command::new("dscacheutil")
                .arg("-cachedump")
                .arg("-entries")
                .output()
            {
                Ok(o) => o,
                Err(e) => {
                    warn!("Could not run dscacheutil (macOS DNS cache): {e}");
                    return Vec::new();
                }
            }
        } else {
            // Linux - no standard DNS cache command, skip
            warn!("DNS cache scanning not supported on this platform");
            return Vec::new();
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

    /// Flush the DNS resolver cache (platform-specific).
    fn flush_dns(&self) {
        let result = if cfg!(target_os = "windows") {
            silent_cmd("ipconfig")
                .arg("/flushdns")
                .output()
        } else if cfg!(target_os = "macos") {
            // macOS: requires sudo, so we use dscacheutil or killall
            std::process::Command::new("dscacheutil")
                .arg("-flushcache")
                .output()
                .or_else(|_| {
                    // Alternative: killall -HUP mDNSResponder
                    std::process::Command::new("killall")
                        .arg("-HUP")
                        .arg("mDNSResponder")
                        .output()
                })
        } else {
            // Linux - depends on the resolver
            std::process::Command::new("systemd-resolve")
                .arg("--flush-caches")
                .output()
        };

        match result {
            Ok(_) => info!("DNS cache flushed"),
            Err(e) => warn!("Failed to flush DNS cache: {e}"),
        }
    }

    // ── Browser window title scanning (Cross-platform) ──────────

    /// Enumerate window titles to catch banned sites.
    /// Windows: PowerShell Get-Process
    /// macOS: AppleScript to query browser windows
    pub fn scan_window_titles(&self) -> Vec<Violation> {
        let output = if cfg!(target_os = "windows") {
            let ps_script = r#"Get-Process | Where-Object {$_.MainWindowTitle -ne ''} | Select-Object -ExpandProperty MainWindowTitle"#;
            
            match silent_cmd("powershell")
                .args(["-NoProfile", "-Command", ps_script])
                .output()
            {
                Ok(o) => o,
                Err(e) => {
                    warn!("PowerShell window title scan failed: {e}");
                    return Vec::new();
                }
            }
        } else if cfg!(target_os = "macos") {
            // macOS: Use AppleScript to get browser window titles
            let apple_script = r#"
                set windowTitles to ""
                tell application "System Events"
                    set processList to name of every process whose background only is false
                end tell
                repeat with processName in processList
                    try
                        tell application processName
                            if it is running then
                                repeat with w in windows
                                    set windowTitles to windowTitles & (name of w) & return
                                end repeat
                            end if
                        end tell
                    end try
                end repeat
                return windowTitles
            "#;
            
            match std::process::Command::new("osascript")
                .arg("-e")
                .arg(apple_script)
                .output()
            {
                Ok(o) => o,
                Err(e) => {
                    warn!("AppleScript window title scan failed: {e}");
                    return Vec::new();
                }
            }
        } else {
            warn!("Window title scanning not supported on this platform");
            return Vec::new();
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
