//! JSON API and scan lifecycle for the GUI.

use super::server::{Req, Resp};
use crate::checkers::Registry;
use crate::cli::{GuiArgs, ScanArgs};
use crate::diff::{self, Diff};
use crate::engine::{self, Environment, ScanError};
use crate::history;
use crate::model::{ScanResult, Severity};
use crate::progress::Progress;
use crate::report;
use crate::scope::{self, Scope};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// A finished scan with its comparison.
pub struct Finished {
    result: ScanResult,
    diff: Option<Diff>,
    saved_as: Option<String>,
}

struct Inner {
    running: Option<Arc<Progress>>,
    last: Option<Arc<Finished>>,
    error: Option<String>,
}

/// Shared GUI state.
pub struct App {
    args: GuiArgs,
    env: Arc<Environment>,
    quit: Arc<Notify>,
    hist_dir: Option<PathBuf>,
    inner: Mutex<Inner>,
}

#[derive(Serialize)]
struct Live {
    ip: String,
    label: String,
    kind: String,
    mac: Option<String>,
    vendor: Option<String>,
    worst: Option<Severity>,
    findings: usize,
    ports: Vec<u16>,
}

/// Body of `POST /api/scan`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct ScanRequest {
    targets: Vec<String>,
    ports: Option<String>,
    active: bool,
    fast: bool,
    allow_public: bool,
    no_mdns: bool,
    no_ssdp: bool,
    no_ipv6: bool,
}

impl App {
    /// Create the shared state.
    pub fn new(args: GuiArgs, env: Arc<Environment>, quit: Arc<Notify>) -> Arc<App> {
        let hist_dir = args.history_dir.clone().or_else(history::default_dir);
        let last = if args.demo {
            let (now, earlier) = crate::demo::scans();
            let d = diff::compare(&earlier, &now);
            Some(Arc::new(Finished { result: now, diff: Some(d), saved_as: None }))
        } else {
            hist_dir.as_deref().map(|d| history::recent(d, 2)).and_then(|mut v| {
                if v.is_empty() {
                    return None;
                }
                let (name, newest) = v.remove(0);
                let d = v.first().map(|(_, old)| diff::compare(old, &newest));
                Some(Arc::new(Finished { result: newest, diff: d, saved_as: Some(name) }))
            })
        };
        Arc::new(App { args, env, quit, hist_dir, inner: Mutex::new(Inner { running: None, last, error: None }) })
    }

    /// Stop any running scan.
    pub fn shutdown(&self) {
        if let Some(p) = &self.inner.lock().unwrap_or_else(|e| e.into_inner()).running {
            p.cancel();
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn result_json(f: &Finished) -> serde_json::Value {
    serde_json::json!({ "result": f.result, "diff": f.diff, "saved_as": f.saved_as })
}

/// `GET /api/*`
pub async fn get(app: &Arc<App>, req: &Req) -> Resp {
    match req.path.as_str() {
        "/api/state" => state(app),
        "/api/result" => match app.inner().last.clone() {
            Some(f) => Resp::json(200, &result_json(&f)),
            None => Resp::error(404, "no scan yet"),
        },
        "/api/result.json" => match app.inner().last.clone() {
            Some(f) => Resp::new(200, "application/json", report::json(&f.result))
                .with("Content-Disposition", "attachment; filename=\"iotscan-result.json\""),
            None => Resp::error(404, "no scan yet"),
        },
        "/api/report.html" => match app.inner().last.clone() {
            Some(f) => Resp::new(200, "text/html; charset=utf-8", report::html::render(&f.result, f.diff.as_ref()))
                .with("Content-Disposition", "attachment; filename=\"iotscan-report.html\""),
            None => Resp::error(404, "no scan yet"),
        },
        "/api/history" => match &app.hist_dir {
            Some(d) if !app.args.demo => Resp::json(200, &history::list(d)),
            _ => Resp::json(200, &Vec::<history::Entry>::new()),
        },
        "/api/checkers" => Resp::json(200, &Registry::builtin().list()),
        p if p.starts_with("/api/history/") => {
            let name = &p["/api/history/".len()..];
            let Some(dir) = &app.hist_dir else { return Resp::error(404, "no history") };
            match history::load(dir, name) {
                Ok(r) => Resp::json(200, &serde_json::json!({ "result": r, "diff": null, "saved_as": name })),
                Err(e) => Resp::error(404, &e),
            }
        }
        _ => Resp::error(404, "not found"),
    }
}

fn state(app: &Arc<App>) -> Resp {
    let inner = app.inner();
    let progress = inner.running.as_ref().map(|p| p.snapshot());
    let live: Vec<Live> = inner
        .running
        .as_ref()
        .map(|p| {
            p.live()
                .into_iter()
                .map(|d| Live {
                    ip: d.ip.to_string(),
                    label: d.label.clone(),
                    kind: d.kind.clone(),
                    mac: d.mac.clone(),
                    vendor: d.vendor.clone(),
                    worst: d.worst().map(|f| f.severity),
                    findings: d.active_findings().count(),
                    ports: d.open_ports(),
                })
                .collect()
        })
        .unwrap_or_default();
    let nets: Vec<serde_json::Value> = scope::local_subnets(scope::DEFAULT_MAX_HOSTS, None)
        .into_iter()
        .map(|n| serde_json::json!({ "iface": n.iface, "addr": n.addr.to_string(), "prefix": n.prefix, "target": n.target.to_string(), "narrowed": n.narrowed }))
        .collect();
    Resp::json(
        200,
        &serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "demo": app.args.demo,
            "running": inner.running.is_some(),
            "progress": progress,
            "live": live,
            "networks": nets,
            "raw_arp": !app.env.arp.is_empty(),
            "notes": app.env.notes,
            "has_result": inner.last.is_some(),
            "error": inner.error,
        }),
    )
}

/// `POST /api/*`
pub async fn post(app: &Arc<App>, req: &Req) -> Resp {
    match req.path.as_str() {
        "/api/scan" => start_scan(app, req),
        "/api/cancel" => {
            if let Some(p) = &app.inner().running {
                p.cancel();
            }
            Resp::json(200, &serde_json::json!({ "ok": true }))
        }
        "/api/quit" => {
            app.quit.notify_one();
            Resp::json(200, &serde_json::json!({ "ok": true }))
        }
        _ => Resp::error(404, "not found"),
    }
}

fn start_scan(app: &Arc<App>, req: &Req) -> Resp {
    if app.args.demo {
        return Resp::error(409, "demo mode shows sample data; restart without --demo to scan");
    }
    let body: ScanRequest = match serde_json::from_slice(&req.body) {
        Ok(b) => b,
        Err(e) => return Resp::error(400, &format!("invalid JSON: {e}")),
    };
    if body.targets.len() > 16 || body.targets.iter().any(|t| t.len() > 100) || body.ports.as_ref().is_some_and(|p| p.len() > 200) {
        return Resp::error(400, "too many or too long targets/ports");
    }
    let mut args = ScanArgs::gui_defaults();
    args.targets = body.targets.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
    args.ports = body.ports.filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "default".into());
    args.active = body.active;
    args.fast = body.fast;
    args.allow_public = body.allow_public;
    args.no_mdns = body.no_mdns;
    args.no_ssdp = body.no_ssdp;
    args.no_ipv6 = body.no_ipv6;
    args.no_arp = app.args.no_arp;
    args.allowlist = app.args.allowlist.clone();
    args.advisories = app.args.advisories.clone();
    let opts = match args.to_options() {
        Ok(o) => o,
        Err(e) => return Resp::error(400, &e),
    };
    if !opts.targets.is_empty() && !opts.targets.iter().any(|t| t == "auto") {
        match Scope::parse(&opts.targets) {
            Ok(s) => {
                let public = s.public_targets();
                if !public.is_empty() && !opts.allow_public {
                    return Resp::json(400, &serde_json::json!({ "error": "public", "targets": public }));
                }
            }
            Err(e) => return Resp::error(400, &e.to_string()),
        }
    }

    let progress = Progress::new(false);
    {
        let mut inner = app.inner();
        if inner.running.is_some() {
            return Resp::error(409, "a scan is already running");
        }
        inner.running = Some(progress.clone());
        inner.error = None;
    }
    let app2 = app.clone();
    tokio::spawn(async move {
        let res = engine::run(opts, app2.env.clone(), progress.clone()).await;
        let mut finished: Option<Arc<Finished>> = None;
        let mut err = None;
        match res {
            Ok(result) => {
                let previous = app2.hist_dir.as_deref().and_then(history::latest).map(|(_, r)| r);
                let diff = previous.as_ref().map(|old| diff::compare(old, &result));
                let saved_as = app2.hist_dir.as_deref().and_then(|d| history::save(d, &result).ok());
                finished = Some(Arc::new(Finished { result, diff, saved_as }));
            }
            Err(ScanError::Cancelled) => err = Some("Scan cancelled.".to_string()),
            Err(e) => err = Some(e.to_string()),
        }
        let mut inner = app2.inner();
        inner.running = None;
        if let Some(f) = finished {
            inner.last = Some(f);
        }
        inner.error = err;
    });
    Resp::json(202, &serde_json::json!({ "started": true }))
}
