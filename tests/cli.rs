//! Tests that drive the real `iotscan` binary.

use iotscan::testkit;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_iotscan");

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// A world-writable sandbox so the test also passes when run as root (iotscan drops to `nobody`).
fn sandbox() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    d
}

fn run_in(home: &Path, args: &[&str]) -> Out {
    let o = Command::new(BIN)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("NO_COLOR")
        .env_remove("SUDO_UID")
        .stdin(Stdio::null())
        .output()
        .expect("run iotscan");
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

async fn run_async(home: std::path::PathBuf, args: Vec<String>) -> Out {
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_in(&home, &refs)
    })
    .await
    .unwrap()
}

fn scan_args(ports: &str, extra: &[&str]) -> Vec<String> {
    let mut v: Vec<String> =
        ["127.0.0.1", "-p", ports, "--no-mdns", "--no-ssdp", "--no-ipv6", "--no-arp", "--fast"].iter().map(|s| s.to_string()).collect();
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

#[test]
fn help_and_version() {
    let d = sandbox();
    let h = run_in(d.path(), &["--help"]);
    assert_eq!(h.code, 0);
    assert!(h.stdout.contains("PHP2Shell") && h.stdout.contains("--active") && h.stdout.contains("EXIT STATUS"));
    let v = run_in(d.path(), &["--version"]);
    assert_eq!(v.code, 0);
    assert!(v.stdout.starts_with("iotscan "));
    let bad = run_in(d.path(), &["--no-such-flag"]);
    assert_eq!(bad.code, 2);
    assert!(bad.stderr.contains("--no-such-flag"));
}

#[test]
fn checkers_and_advisories_listings() {
    let d = sandbox();
    let c = run_in(d.path(), &["checkers"]);
    assert_eq!(c.code, 0);
    for id in ["php2shell", "php-eol", "php-info-exposed", "telnet-open", "upnp-exposed", "data-advisory"] {
        assert!(c.stdout.contains(id), "{id} missing from:\n{}", c.stdout);
    }
    let j: serde_json::Value = serde_json::from_str(&run_in(d.path(), &["checkers", "--json"]).stdout).unwrap();
    assert!(j.as_array().unwrap().len() >= 6);

    let a = run_in(d.path(), &["advisories"]);
    assert_eq!(a.code, 0);
    assert!(a.stdout.contains("php2shell") && a.stdout.contains("CVE-2026-109618") && a.stdout.contains("valid"));

    let bad = d.path().join("bad.toml");
    std::fs::write(&bad, "[[advisory]]\nid='x'\nproduct='P'\ntitle=''\nseverity='high'\n").unwrap();
    let r = run_in(d.path(), &["advisories", "--file", bad.to_str().unwrap()]);
    assert!(r.stdout.contains("ignoring") || r.stdout.contains("problem"), "{}", r.stdout);
}

#[test]
fn completions_and_doctor() {
    let d = sandbox();
    let c = run_in(d.path(), &["completions", "bash"]);
    assert_eq!(c.code, 0);
    assert!(c.stdout.contains("iotscan"));
    let doc = run_in(d.path(), &["doctor"]);
    assert_eq!(doc.code, 0);
    assert!(doc.stdout.contains("CAP_NET_RAW") && doc.stdout.contains("advisory database"));
}

#[test]
fn public_targets_need_confirmation_non_interactively() {
    let d = sandbox();
    let r = run_in(d.path(), &["8.8.8.8", "--no-history"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("--allow-public"), "{}", r.stderr);
    let r = run_in(d.path(), &["10.0.0.0/8", "--no-history"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("limit"), "{}", r.stderr);
    let r = run_in(d.path(), &["127.0.0.1", "--only", "typo-checker", "--no-history"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("unknown checker"), "{}", r.stderr);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn json_scan_exit_codes_and_outputs() {
    let fleet = testkit::fleet().await;
    let ports = fleet.all_ports().iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let d = sandbox();

    // JSON on stdout; critical finding => exit 1.
    let r = run_async(d.path().to_path_buf(), scan_args(&ports, &["--json", "--no-history", "-q"])).await;
    assert_eq!(r.code, 1, "stderr: {}", r.stderr);
    let j: serde_json::Value = serde_json::from_str(&r.stdout).expect("stdout must be pure JSON");
    assert_eq!(j["schema_version"], 1);
    assert_eq!(j["devices"].as_array().unwrap().len(), 1);
    let findings = j["devices"][0]["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["checker"] == "php2shell" && f["severity"] == "critical" && f["confidence"] == "likely"));
    assert!(findings.iter().any(|f| f["checker"] == "telnet-open"));

    // Thresholds.
    for (flag, want) in [("none", 0), ("critical", 1), ("high", 1), ("low", 1)] {
        let r = run_async(d.path().to_path_buf(), scan_args(&ports, &["--json", "--no-history", "-q", "--fail-on", flag])).await;
        assert_eq!(r.code, want, "--fail-on {flag}");
    }
    let r = run_async(d.path().to_path_buf(), scan_args(&ports, &["--no-history", "-q", "--fail-on", "bogus"])).await;
    assert_eq!(r.code, 2);

    // A clean target exits 0.
    let clean = fleet.port("plain-web").to_string();
    let r = run_async(d.path().to_path_buf(), scan_args(&clean, &["--no-history", "-q"])).await;
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stdout.contains("No findings"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn text_colour_and_report_files() {
    let fleet = testkit::fleet().await;
    let ports = [fleet.port("php-vulnerable"), fleet.port("telnet")].iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let d = sandbox();
    let json_path = d.path().join("out.json");
    let html_path = d.path().join("out.html");

    let plain = run_async(d.path().to_path_buf(), scan_args(&ports, &["--no-history", "-q", "--color", "never"])).await;
    assert!(!plain.stdout.contains('\x1b'));
    assert!(plain.stdout.contains("CRITICAL") && plain.stdout.contains("PHP2Shell") && plain.stdout.contains("Telnet is enabled"));
    assert!(plain.stdout.contains("Fix:") && plain.stdout.contains("CVE-2026-109618"));

    let col = run_async(d.path().to_path_buf(), scan_args(&ports, &["--no-history", "-q", "--color", "always"])).await;
    assert!(col.stdout.contains("\x1b["));

    let r = run_async(
        d.path().to_path_buf(),
        scan_args(&ports, &["--no-history", "-q", "-o", json_path.to_str().unwrap(), "--html", html_path.to_str().unwrap()]),
    )
    .await;
    assert_eq!(r.code, 1);
    let saved: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
    assert_eq!(saved["devices"].as_array().unwrap().len(), 1);
    let html = std::fs::read_to_string(&html_path).unwrap();
    assert!(html.starts_with("<!doctype html>") && html.contains("PHP2Shell") && !html.contains("<script"));
    // Overwriting an existing, world-readable file must tighten it.
    std::fs::set_permissions(&json_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let again = run_async(d.path().to_path_buf(), scan_args(&ports, &["--no-history", "-q", "-o", json_path.to_str().unwrap()])).await;
    assert_eq!(again.code, 1);
    // Result files may describe your network: owner-only.
    assert_eq!(std::fs::metadata(&json_path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&html_path).unwrap().permissions().mode() & 0o777, 0o600);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_diff_and_baseline() {
    let fleet = testkit::fleet().await;
    let d = sandbox();
    let home = d.path().to_path_buf();
    let both = [fleet.port("php-vulnerable"), fleet.port("telnet")].iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let one = fleet.port("php-vulnerable").to_string();

    // First scan: nothing to compare with.
    let a = run_async(home.clone(), scan_args(&both, &["-q", "--color", "never"])).await;
    assert!(!a.stdout.contains("CHANGES"), "{}", a.stdout);
    // Second scan, Telnet "fixed" (port no longer scanned): resolved finding appears in the changes.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await; // distinct history file names
    let b = run_async(home.clone(), scan_args(&one, &["-q", "--color", "never"])).await;
    assert!(b.stdout.contains("CHANGES"), "{}", b.stdout);
    assert!(b.stdout.contains("resolved") || b.stdout.contains("closed"), "{}", b.stdout);

    // `history` lists both, newest first.
    let h = run_in(&home, &["history"]);
    assert_eq!(h.code, 0);
    assert_eq!(h.stdout.matches("scan-").count(), 2, "{}", h.stdout);

    // Files are private.
    let hist_dir = home.join("data/iotscan/history");
    let mode = std::fs::metadata(&hist_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    // `diff` between two saved scans.
    let mut files: Vec<_> = std::fs::read_dir(&hist_dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    let dd = run_in(&home, &["diff", files[0].to_str().unwrap(), files[1].to_str().unwrap()]);
    assert_eq!(dd.code, 0);
    assert!(dd.stdout.contains("Since the previous scan") || dd.stdout.contains("No changes"), "{}", dd.stdout);
    let dj = run_in(&home, &["diff", "--json", files[0].to_str().unwrap(), files[1].to_str().unwrap()]);
    assert!(serde_json::from_str::<serde_json::Value>(&dj.stdout).is_ok());

    // --baseline overrides history; --no-history leaves it alone.
    let before = std::fs::read_dir(&hist_dir).unwrap().count();
    let c =
        run_async(home.clone(), scan_args(&both, &["-q", "--color", "never", "--no-history", "--baseline", files[0].to_str().unwrap()]))
            .await;
    assert!(c.stdout.contains("CHANGES"), "{}", c.stdout);
    assert_eq!(std::fs::read_dir(&hist_dir).unwrap().count(), before);
    let bad = run_in(&home, &["127.0.0.1", "--baseline", "/nonexistent.json", "--no-history", "-q"]);
    assert_eq!(bad.code, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allowlist_file_is_honoured() {
    let fleet = testkit::fleet().await;
    let d = sandbox();
    let al = d.path().join("allow.toml");
    std::fs::write(&al, "[[allow]]\ndevice='127.0.0.1'\nreason='lab network, accepted'\n").unwrap();
    let port = fleet.port("php-vulnerable").to_string();
    let r =
        run_async(d.path().to_path_buf(), scan_args(&port, &["--json", "--no-history", "-q", "--allowlist", al.to_str().unwrap()])).await;
    assert_eq!(r.code, 0, "suppressed findings must not fail the run: {}", r.stderr);
    let j: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(j["devices"][0]["findings"][0]["suppressed"], "lab network, accepted");
    assert!(j["stats"]["suppressed"].as_u64().unwrap() >= 1);
    // A broken allowlist is an error, not silently ignored.
    std::fs::write(&al, "[[allow]]\ndevice='???'\nreason='x'\n").unwrap();
    let r = run_async(d.path().to_path_buf(), scan_args(&port, &["--no-history", "-q", "--allowlist", al.to_str().unwrap()])).await;
    assert_eq!(r.code, 2);
}

#[test]
fn selftest_command_passes() {
    let d = sandbox();
    let r = run_in(d.path(), &["selftest"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(r.stdout.contains("0 failed"));
}
