//! Command-line definition.

use crate::allowlist::Allowlist;
use crate::engine::ScanOptions;
use crate::limits::Limits;
use crate::model::Severity;
use crate::ports;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::time::Duration;

const ABOUT: &str = "Scan your home network for vulnerable IoT devices.\n\n\
Finds devices (TCP sweep, ARP, mDNS, SSDP, IPv6), identifies what they run, and checks for known problems such as the October 2026 PHP2Shell flaws (CVE-2026-109618 / CVE-2026-109619), end-of-life PHP, exposed Telnet and UPnP.\n\n\
Only scan networks you own or are authorised to test.";

const AFTER: &str = "EXAMPLES:\n  iotscan                          scan every local subnet\n  iotscan 192.168.1.0/24 --active  also look for exposed phpinfo() pages\n  iotscan --json > scan.json       machine-readable output\n  iotscan --html report.html       shareable report\n  iotscan gui                      open the graphical interface\n  iotscan diff old.json new.json   compare two scans\n  iotscan doctor                   check privileges and network setup\n\nEXIT STATUS: 0 = ok, 1 = findings at or above --fail-on, 2 = error.\nSee `man iotscan` for details.";

/// Top-level CLI.
#[derive(Parser, Debug)]
#[command(name = "iotscan", version, about = ABOUT, after_help = AFTER, args_conflicts_with_subcommands = true)]
pub struct Cli {
    /// Scan options (used when no subcommand is given).
    #[command(flatten)]
    pub scan: ScanArgs,
    /// Subcommand.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Subcommands.
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Scan the network (the default).
    Scan(ScanArgs),
    /// Open the graphical interface in your browser.
    Gui(GuiArgs),
    /// Compare two saved scans.
    Diff {
        /// Earlier scan (JSON file).
        old: PathBuf,
        /// Later scan (JSON file).
        new: PathBuf,
        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List saved scans.
    History {
        /// Use this history directory.
        #[arg(long)]
        history_dir: Option<PathBuf>,
    },
    /// List the available checkers.
    Checkers {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show or validate the advisory database.
    Advisories {
        /// Extra advisory file to merge and validate.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check privileges, interfaces and configuration.
    Doctor,
    /// Run the built-in tests against mock devices on localhost.
    Selftest,
    /// Start mock devices on localhost for trying the scanner and the GUI.
    #[command(hide = true)]
    Mock,
    /// Print a shell completion script.
    Completions {
        /// Shell.
        shell: Shell,
    },
}

/// Supported shells.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Shell {
    /// bash
    Bash,
    /// zsh
    Zsh,
    /// fish
    Fish,
}

/// When to colour output.
#[derive(Clone, Copy, Debug, Default, ValueEnum, PartialEq, Eq)]
pub enum ColorMode {
    /// Colour when writing to a terminal.
    #[default]
    Auto,
    /// Always.
    Always,
    /// Never.
    Never,
}

/// GUI options.
#[derive(Args, Debug, Clone)]
pub struct GuiArgs {
    /// TCP port to listen on (127.0.0.1 only). 0 = pick a free one.
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Do not try to open a browser; just print the URL.
    #[arg(long)]
    pub no_open: bool,
    /// History directory.
    #[arg(long)]
    pub history_dir: Option<PathBuf>,
    /// Extra advisory file.
    #[arg(long)]
    pub advisories: Option<PathBuf>,
    /// Allowlist file.
    #[arg(long)]
    pub allowlist: Option<PathBuf>,
    /// Do not use raw ARP even if CAP_NET_RAW is available.
    #[arg(long)]
    pub no_arp: bool,
    /// Show sample data instead of scanning (try the interface without a network).
    #[arg(long)]
    pub demo: bool,
}

/// Scan options.
#[derive(Args, Debug, Clone, Default)]
pub struct ScanArgs {
    /// What to scan: IPs, CIDR blocks (192.168.1.0/24) or ranges (10.0.0.5-50). Default: your local subnets.
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Ports: `default`, `web`, a list `80,443`, or ranges `8000-8100`.
    #[arg(short, long, default_value = "default", value_name = "PORTS")]
    pub ports: String,

    /// Send extra, still non-destructive, requests (e.g. look for exposed phpinfo() pages). Never sends exploit payloads.
    #[arg(long)]
    pub active: bool,

    /// Faster, less polite: more parallelism, no rate limit, shorter timeouts.
    #[arg(long)]
    pub fast: bool,

    /// Maximum new connections per second across the whole scan (0 = unlimited).
    #[arg(long, value_name = "N")]
    pub rate: Option<u32>,

    /// Maximum simultaneous connections to one device.
    #[arg(long, value_name = "N")]
    pub per_host: Option<usize>,

    /// TCP connect timeout in milliseconds.
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,

    /// Skip mDNS discovery.
    #[arg(long)]
    pub no_mdns: bool,
    /// Skip SSDP/UPnP discovery.
    #[arg(long)]
    pub no_ssdp: bool,
    /// Skip IPv6 neighbour discovery.
    #[arg(long)]
    pub no_ipv6: bool,
    /// Do not use raw ARP even if CAP_NET_RAW is available.
    #[arg(long)]
    pub no_arp: bool,

    /// Refuse to scan more than this many addresses.
    #[arg(long, default_value_t = crate::scope::DEFAULT_MAX_HOSTS, value_name = "N")]
    pub max_hosts: usize,

    /// Only use this network interface for auto-detection and discovery.
    #[arg(short, long, value_name = "IFACE")]
    pub iface: Option<String>,

    /// Confirm you are authorised to scan non-private addresses.
    #[arg(long)]
    pub allow_public: bool,

    /// Run only these checkers (comma separated ids; see `iotscan checkers`).
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    pub only: Vec<String>,
    /// Skip these checkers.
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    pub skip: Vec<String>,

    /// Extra advisory file merged over the built-in database.
    #[arg(long, value_name = "FILE")]
    pub advisories: Option<PathBuf>,
    /// Allowlist of accepted risks (default: ~/.config/iotscan/allowlist.toml).
    #[arg(long, value_name = "FILE")]
    pub allowlist: Option<PathBuf>,

    /// Print the result as JSON on stdout (the text report is skipped).
    #[arg(long)]
    pub json: bool,
    /// Also write JSON to this file.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Write a standalone HTML report to this file.
    #[arg(long, value_name = "FILE")]
    pub html: Option<PathBuf>,
    /// Colour output.
    #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
    pub color: ColorMode,
    /// Show evidence and low-severity details.
    #[arg(short, long)]
    pub verbose: bool,
    /// Do not print progress.
    #[arg(short, long)]
    pub quiet: bool,
    /// Include findings suppressed by the allowlist.
    #[arg(long)]
    pub show_suppressed: bool,

    /// Do not read or write scan history (disables the comparison with the last scan).
    #[arg(long)]
    pub no_history: bool,
    /// Compare with this saved scan instead of the latest in history.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,
    /// History directory (default: ~/.local/share/iotscan/history).
    #[arg(long, value_name = "DIR")]
    pub history_dir: Option<PathBuf>,

    /// Exit with status 1 when a finding at or above this severity exists (`none` disables).
    #[arg(long, default_value = "high", value_name = "SEVERITY")]
    pub fail_on: String,
}

impl ScanArgs {
    /// Defaults equivalent to running `iotscan` with no flags (used by the GUI).
    pub fn gui_defaults() -> ScanArgs {
        ScanArgs { ports: "default".into(), max_hosts: crate::scope::DEFAULT_MAX_HOSTS, fail_on: "high".into(), ..ScanArgs::default() }
    }

    /// Severity threshold for the exit status; `None` = never fail.
    pub fn fail_threshold(&self) -> Result<Option<Severity>, String> {
        if self.fail_on.eq_ignore_ascii_case("none") {
            return Ok(None);
        }
        Severity::parse(&self.fail_on)
            .map(Some)
            .ok_or_else(|| format!("--fail-on: '{}' is not one of none, info, low, medium, high, critical", self.fail_on))
    }

    /// Whether this scan will want to use raw ARP.
    pub fn wants_arp(&self) -> bool {
        !self.no_arp
    }

    /// Convert to engine options.
    pub fn to_options(&self) -> Result<ScanOptions, String> {
        let mut limits = if self.fast { Limits::fast() } else { Limits::default() };
        if let Some(r) = self.rate {
            limits.rate_per_sec = r;
        }
        if let Some(n) = self.per_host {
            if n == 0 || n > 64 {
                return Err("--per-host must be between 1 and 64".into());
            }
            limits.per_host = n;
        }
        if let Some(ms) = self.timeout_ms {
            if !(50..=30_000).contains(&ms) {
                return Err("--timeout-ms must be between 50 and 30000".into());
            }
            limits.connect_timeout = Duration::from_millis(ms);
        }
        if self.max_hosts == 0 || self.max_hosts > 1 << 20 {
            return Err("--max-hosts must be between 1 and 1048576".into());
        }
        let allowlist = Allowlist::load(self.allowlist.as_deref())?;
        Ok(ScanOptions {
            targets: self.targets.clone(),
            ports: ports::parse_ports(&self.ports)?,
            limits,
            active: self.active,
            mdns: !self.no_mdns,
            ssdp: !self.no_ssdp,
            ipv6: !self.no_ipv6,
            arp: !self.no_arp,
            max_hosts: self.max_hosts,
            iface: self.iface.clone(),
            allow_public: self.allow_public,
            only: self.only.clone(),
            skip: self.skip.clone(),
            advisories: self.advisories.clone(),
            allowlist,
            ..ScanOptions::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("iotscan").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn clap_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_invocation_scans() {
        let c = parse(&[]);
        assert!(c.command.is_none());
        assert!(c.scan.targets.is_empty());
        let o = c.scan.to_options().unwrap();
        assert!(!o.active && o.mdns && o.ssdp);
    }

    #[test]
    fn targets_and_flags() {
        let c = parse(&["192.168.1.0/24", "10.0.0.5", "--active", "--fast", "-p", "80,8080", "--only", "php2shell,php-eol", "--no-mdns"]);
        let o = c.scan.to_options().unwrap();
        assert_eq!(o.targets.len(), 2);
        assert!(o.active && !o.mdns);
        assert_eq!(o.ports, vec![80, 8080]);
        assert_eq!(o.only, vec!["php2shell", "php-eol"]);
        assert_eq!(o.limits.rate_per_sec, 0, "--fast removes the rate limit");
    }

    #[test]
    fn explicit_subcommands() {
        assert!(matches!(parse(&["scan", "10.0.0.0/24"]).command, Some(Command::Scan(_))));
        assert!(matches!(parse(&["doctor"]).command, Some(Command::Doctor)));
        assert!(matches!(parse(&["diff", "a.json", "b.json"]).command, Some(Command::Diff { .. })));
        assert!(matches!(parse(&["gui", "--no-open"]).command, Some(Command::Gui(_))));
    }

    #[test]
    fn validation() {
        assert!(parse(&["--per-host", "0"]).scan.to_options().is_err());
        assert!(parse(&["--timeout-ms", "1"]).scan.to_options().is_err());
        assert!(parse(&["--max-hosts", "0"]).scan.to_options().is_err());
        assert!(parse(&["-p", "99999"]).scan.to_options().is_err());
        assert!(Cli::try_parse_from(["iotscan", "--bogus"]).is_err());
    }

    #[test]
    fn fail_on_parsing() {
        assert_eq!(parse(&[]).scan.fail_threshold().unwrap(), Some(Severity::High));
        assert_eq!(parse(&["--fail-on", "none"]).scan.fail_threshold().unwrap(), None);
        assert_eq!(parse(&["--fail-on", "CRITICAL"]).scan.fail_threshold().unwrap(), Some(Severity::Critical));
        assert!(parse(&["--fail-on", "bad"]).scan.fail_threshold().is_err());
    }
}
