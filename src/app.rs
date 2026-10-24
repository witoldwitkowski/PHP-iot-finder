//! Command implementations behind the CLI.

use crate::advisories::AdvisoryDb;
use crate::checkers::Registry;
use crate::cli::{ColorMode, Command, GuiArgs, ScanArgs, Shell};
use crate::diff::{self, Diff};
use crate::engine::{self, Environment, ScanError};
use crate::model::{ScanResult, Severity};
use crate::progress::Progress;
use crate::report::{self, terminal};
use crate::scope::{self, Scope};
use crate::{caps, history, privsep, selftest, sys};
use clap::CommandFactory;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// Exit status for findings at or above the threshold.
pub const EXIT_FINDINGS: u8 = 1;
/// Exit status for errors.
pub const EXIT_ERROR: u8 = 2;

/// Entry point used by `main`: dispatches a parsed command line.
pub fn run(cli: crate::cli::Cli) -> Result<ExitCode, String> {
    let cmd = cli.command.unwrap_or(Command::Scan(cli.scan));
    match cmd {
        Command::Scan(a) => scan_command(a),
        Command::Gui(a) => gui_command(a),
        Command::Diff { old, new, json } => {
            drop_privileges_only()?;
            diff_command(&old, &new, json)
        }
        Command::History { history_dir } => {
            drop_privileges_only()?;
            history_command(history_dir)
        }
        Command::Checkers { json } => {
            drop_privileges_only()?;
            checkers_command(json)
        }
        Command::Advisories { file, json } => {
            drop_privileges_only()?;
            advisories_command(file, json)
        }
        Command::Doctor => doctor_command(),
        Command::Selftest => {
            drop_privileges_only()?;
            selftest_command()
        }
        Command::Mock => {
            drop_privileges_only()?;
            mock_command()
        }
        Command::Completions { shell } => {
            let mut c = crate::cli::Cli::command();
            let s = match shell {
                Shell::Bash => clap_complete::Shell::Bash,
                Shell::Zsh => clap_complete::Shell::Zsh,
                Shell::Fish => clap_complete::Shell::Fish,
            };
            clap_complete::generate(s, &mut c, "iotscan", &mut std::io::stdout());
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Subcommands that never touch the network still shed privileges.
fn drop_privileges_only() -> Result<(), String> {
    privsep::init(false, &[], false).map(|_| ())
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
        .map_err(|e| format!("cannot start async runtime: {e}"))
}

fn use_color(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            std::io::stdout().is_terminal()
                && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
                && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
        }
    }
}

fn term_width() -> usize {
    sys::terminal_width().or_else(|| std::env::var("COLUMNS").ok().and_then(|c| c.parse().ok())).unwrap_or(100)
}

fn confirm_public(targets: &[String]) -> Result<(), String> {
    eprintln!("\n⚠  These targets are outside private address space: {}", targets.join(", "));
    eprintln!("   Scanning networks you do not own or are not authorised to test may be illegal.");
    if !std::io::stdin().is_terminal() {
        return Err("refusing to scan public addresses non-interactively; pass --allow-public to confirm you are authorised".into());
    }
    eprint!("   Type 'yes' to confirm you are authorised to scan them: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    if line.trim().eq_ignore_ascii_case("yes") { Ok(()) } else { Err("not confirmed; nothing was scanned".into()) }
}

fn scan_command(args: ScanArgs) -> Result<ExitCode, String> {
    let mut opts = args.to_options()?;
    let threshold = args.fail_threshold()?;

    // Validate targets and handle public ranges before any privileged setup.
    if !opts.targets.is_empty() && !opts.targets.iter().any(|t| t == "auto") {
        let scope = Scope::parse(&opts.targets).map_err(|e| e.to_string())?;
        let public = scope.public_targets();
        if !public.is_empty() && !opts.allow_public {
            confirm_public(&public)?;
            opts.allow_public = true;
        }
    }

    // Privileged start-up (single-threaded), then drop everything.
    let nets = scope::local_subnets(opts.max_hosts, opts.iface.as_deref());
    let privs = privsep::init(args.wants_arp(), &nets, false)?;
    let env = Arc::new(Environment::from(privs));

    let progress = Progress::new(!args.quiet);
    let rt = runtime()?;
    let result = rt.block_on(async {
        let cancel = progress.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("\n  cancelling…");
                cancel.cancel();
            }
        });
        engine::run(opts, env, progress.clone()).await
    });
    let result = match result {
        Ok(r) => r,
        Err(ScanError::Cancelled) => return Err("scan cancelled".into()),
        Err(e) => return Err(e.to_string()),
    };

    // History + diff.
    let hist_dir = args.history_dir.clone().or_else(history::default_dir);
    let mut diff: Option<Diff> = None;
    if let Some(b) = &args.baseline {
        let old = history::load_path(b)?;
        diff = Some(diff::compare(&old, &result));
    } else if !args.no_history
        && let Some((_, old)) = hist_dir.as_deref().and_then(history::latest)
    {
        diff = Some(diff::compare(&old, &result));
    }
    if !args.no_history {
        match hist_dir.as_deref() {
            Some(d) => {
                if let Err(e) = history::save(d, &result) {
                    eprintln!("warning: could not save scan history in {}: {e}", d.display());
                }
            }
            None => eprintln!("warning: no home directory; scan history not saved"),
        }
    }

    // Output.
    if let Some(p) = &args.output {
        write_private(p, report::json(&result).as_bytes())?;
        if !args.quiet {
            eprintln!("wrote {}", p.display());
        }
    }
    if let Some(p) = &args.html {
        write_private(p, report::html::render(&result, diff.as_ref()).as_bytes())?;
        if !args.quiet {
            eprintln!("wrote {}", p.display());
        }
    }
    if args.json {
        println!("{}", report::json(&JsonOut { result: &result, diff: diff.as_ref() }));
    } else {
        let o = terminal::Opts {
            color: use_color(args.color),
            width: term_width(),
            verbose: args.verbose,
            show_suppressed: args.show_suppressed,
        };
        print!("{}", terminal::render(&result, diff.as_ref(), &o));
    }

    Ok(exit_for(&result, threshold))
}

#[derive(serde::Serialize)]
struct JsonOut<'a> {
    #[serde(flatten)]
    result: &'a ScanResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<&'a Diff>,
}

fn exit_for(r: &ScanResult, threshold: Option<Severity>) -> ExitCode {
    match threshold {
        Some(t) if r.count_at_least(t) > 0 => ExitCode::from(EXIT_FINDINGS),
        _ => ExitCode::SUCCESS,
    }
}

/// Write a file readable only by the current user.
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // `mode` applies only when the file is created; tighten a pre-existing file too.
    f.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| format!("{}: {e}", path.display()))
}

fn gui_command(args: GuiArgs) -> Result<ExitCode, String> {
    let nets = scope::local_subnets(scope::DEFAULT_MAX_HOSTS, None);
    let privs = privsep::init(!args.no_arp, &nets, !args.no_open)?;
    let env = Arc::new(Environment::from(privs));
    let rt = runtime()?;
    rt.block_on(crate::gui::serve(args, env)).map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}

fn diff_command(old: &std::path::Path, new: &std::path::Path, json: bool) -> Result<ExitCode, String> {
    let (o, n) = (history::load_path(old)?, history::load_path(new)?);
    let d = diff::compare(&o, &n);
    if json {
        println!("{}", report::json(&d));
    } else {
        println!("{}", d.summary());
        for x in &d.new_devices {
            println!("  + new device  {:<15} {}", x.ip, x.label);
        }
        for x in &d.missing_devices {
            println!("  - gone        {:<15} {}", x.ip, x.label);
        }
        for c in &d.changed {
            println!("  ~ changed     {:<15} {}", c.device.ip, c.device.label);
            for p in &c.opened_ports {
                println!("      port {p} newly open");
            }
            for p in &c.closed_ports {
                println!("      port {p} closed");
            }
            for f in &c.new_findings {
                println!("      new: [{}] {}", f.severity, f.title);
            }
            for f in &c.resolved_findings {
                println!("      resolved: {}", f.title);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn history_command(dir: Option<PathBuf>) -> Result<ExitCode, String> {
    let dir = dir.or_else(history::default_dir).ok_or("no home directory")?;
    let entries = history::list(&dir);
    if entries.is_empty() {
        println!("No saved scans in {}", dir.display());
    } else {
        println!("{} ({} scans)", dir.display(), entries.len());
        for e in entries {
            println!("  {}  {:>3} devices  {:>3} findings  {}", e.started, e.devices, e.findings, e.name);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn checkers_command(json: bool) -> Result<ExitCode, String> {
    let metas = Registry::builtin().list();
    if json {
        println!("{}", report::json(&metas));
    } else {
        for m in metas {
            println!("{:<18} {}{}", m.id, m.name, if m.uses_active_probes { "  [--active]" } else { "" });
            println!("{:<18} {}", "", m.description);
        }
        println!("\nUse --only ID,ID or --skip ID,ID to choose. Add your own with docs/WRITING_CHECKERS.md.");
    }
    Ok(ExitCode::SUCCESS)
}

fn advisories_command(file: Option<PathBuf>, json: bool) -> Result<ExitCode, String> {
    let (db, warnings) = AdvisoryDb::load(file.as_deref());
    let problems = db.validate();
    if json {
        #[derive(serde::Serialize)]
        struct A<'a> {
            id: &'a str,
            product: &'a str,
            title: &'a str,
            severity: Severity,
            cves: &'a [String],
            published: &'a str,
            verified: bool,
        }
        let list: Vec<A> = db
            .advisory
            .iter()
            .map(|a| A {
                id: &a.id,
                product: &a.product,
                title: &a.title,
                severity: a.severity,
                cves: &a.cves,
                published: &a.published,
                verified: a.verified,
            })
            .collect();
        println!(
            "{}",
            report::json(&serde_json::json!({ "updated": db.updated, "advisories": list, "warnings": warnings, "problems": problems }))
        );
    } else {
        println!("Advisory database (data updated {})", db.updated);
        for a in &db.advisory {
            println!(
                "  {:<18} {:<8} {}  {}{}",
                a.id,
                a.severity.as_str(),
                a.cves.join(","),
                a.title,
                if a.verified { "" } else { "  [unverified]" }
            );
        }
        for w in &warnings {
            println!("warning: {w}");
        }
        if problems.is_empty() {
            println!(
                "\nDatabase is valid. Your own file: {}",
                crate::advisories::user_db_path().map(|p| p.display().to_string()).unwrap_or_else(|| "(no home directory)".into())
            );
        } else {
            println!();
            for p in &problems {
                println!("problem: {p}");
            }
        }
    }
    Ok(if problems.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(EXIT_ERROR) })
}

fn selftest_command() -> Result<ExitCode, String> {
    let rt = runtime()?;
    println!("Running iotscan self-test against mock devices on 127.0.0.1 (about 15 seconds)…\n");
    let checks = rt.block_on(selftest::run());
    let mut failed = 0;
    for c in &checks {
        if c.ok {
            println!("  ✓ {}", c.name);
        } else {
            failed += 1;
            println!("  ✗ {}\n      {}", c.name, c.detail);
        }
    }
    println!("\n{} checks, {} failed", checks.len(), failed);
    Ok(if failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(EXIT_ERROR) })
}

fn mock_command() -> Result<ExitCode, String> {
    let rt = runtime()?;
    rt.block_on(async {
        let fleet = crate::testkit::fleet().await;
        let ports = fleet.all_ports().iter().map(u16::to_string).collect::<Vec<_>>().join(",");
        println!("Mock devices are listening on 127.0.0.1. Try:\n\n    iotscan 127.0.0.1 -p {ports} --active\n\nor use target 127.0.0.1 and ports {ports} in `iotscan gui`.\nPress Ctrl-C to stop.");
        let _ = tokio::signal::ctrl_c().await;
    });
    Ok(ExitCode::SUCCESS)
}

fn doctor_command() -> Result<ExitCode, String> {
    let raw = caps::can_raw();
    let root = sys::euid() == 0;
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "iotscan".into());
    println!("iotscan {} doctor\n", env!("CARGO_PKG_VERSION"));
    let mark = |ok: bool| if ok { "✓" } else { "·" };
    println!(
        " {} running as {}",
        mark(!root),
        if root { "root (not recommended: privileges are dropped after start-up)" } else { "an ordinary user" }
    );
    println!(" {} CAP_NET_RAW: {}", mark(raw), if raw { "available: the raw ARP sweep will be used" } else { "not granted (optional)" });
    if !raw && !root {
        println!("     enable the faster raw ARP sweep with:  {}", caps::setcap_hint(&exe));
        println!("     (without it iotscan still learns MAC addresses from the kernel ARP cache)");
    }
    let ping = std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range").unwrap_or_default();
    let ping_ok = ping
        .split_whitespace()
        .next_back()
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|hi| hi > 0 && ping.split_whitespace().next() == Some("0"));
    println!(
        " {} unprivileged ICMP (IPv6 neighbour discovery): {}",
        mark(ping_ok),
        if ping_ok { "allowed" } else { "restricted (ping_group_range); IPv6 discovery may be skipped" }
    );

    let nets = scope::local_subnets(scope::DEFAULT_MAX_HOSTS, None);
    if nets.is_empty() {
        println!(" ✗ no usable network interface found");
    }
    for n in &nets {
        println!(
            " ✓ interface {:<10} {}/{}  → will scan {}{}",
            n.iface,
            n.addr,
            n.prefix,
            n.target,
            if n.narrowed { " (narrowed)" } else { "" }
        );
    }
    let (db, warnings) = AdvisoryDb::load(None);
    let problems = db.validate();
    println!(" {} advisory database: {} advisories, data updated {}", mark(problems.is_empty()), db.advisory.len(), db.updated);
    for w in warnings.iter().chain(problems.iter()) {
        println!("     ! {w}");
    }
    println!(" ✓ MAC vendor table: {} entries", crate::oui::entries());
    match history::default_dir() {
        Some(d) => println!(" ✓ scan history: {}", d.display()),
        None => println!(" ✗ no home directory: scan history disabled"),
    }
    match crate::allowlist::Allowlist::load(None) {
        Ok(a) => println!(" ✓ allowlist: {} entr{}", a.allow.len(), if a.allow.len() == 1 { "y" } else { "ies" }),
        Err(e) => println!(" ✗ allowlist: {e}"),
    }
    drop_privileges_only()?;
    let eff = sys::effective_caps_raw();
    println!(
        " {} privileges after start-up: CapEff={eff:016x}{}",
        mark(eff == 0),
        if eff == 0 { " (no capabilities held)" } else { " (still holding capabilities!)" }
    );
    println!("\nNext: run `iotscan selftest` to verify the scanner, then `iotscan`.");
    Ok(ExitCode::SUCCESS)
}
