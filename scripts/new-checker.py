#!/usr/bin/env python3
"""Scaffold a new iotscan checker.

  data  - a data-only advisory appended to data/advisories.toml (banner-identifiable software)
  rust  - a Rust checker module registered in src/checkers/mod.rs

Examples:
  scripts/new-checker.py data --id boa-unmaintained --product boa --title "Boa web server is unmaintained" \
      --severity high --cve CVE-2017-9833 --published 2017-06-20 \
      --summary "..." --remediation "..." --reference https://nvd.nist.gov/vuln/detail/CVE-2017-9833 \
      --affected from=0.0

  scripts/new-checker.py rust --id mqtt-anonymous --name "Anonymous MQTT broker" \
      --description "An MQTT broker that accepts connections without credentials." \
      --category exposure --banner-port 1883 --active

The scaffold is deliberately incomplete: the Rust template contains a test that panics until it is
replaced, and scripts/verify.sh fails while any TODO(agent) marker remains.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEVERITIES = ["info", "low", "medium", "high", "critical"]
CATEGORIES = {"web": "Web", "remote-access": "RemoteAccess", "exposure": "Exposure", "lifecycle": "Lifecycle",
              "credentials": "Credentials", "other": "Other"}


def die(msg):
    print(f"new-checker: {msg}", file=sys.stderr)
    sys.exit(2)


def toml_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def check_id(i):
    if not re.fullmatch(r"[a-z][a-z0-9]*(-[a-z0-9]+)*", i) or len(i) > 48:
        die(f"id {i!r} must be lowercase kebab-case (a-z, 0-9, -), at most 48 characters")


def existing_ids():
    ids = set(re.findall(r'^id = "([^"]+)"', (ROOT / "data/advisories.toml").read_text(), re.M))
    mod = (ROOT / "src/checkers/mod.rs").read_text()
    for f in (ROOT / "src/checkers").glob("*.rs"):
        ids |= set(re.findall(r'pub const ID: &str = "([^"]+)"', f.read_text()))
    return ids | set(re.findall(r'id: "([^"]+)"', mod))


def cmd_data(a):
    check_id(a.id)
    if a.id in existing_ids():
        die(f"id {a.id!r} already exists")
    if a.product != a.product.lower() or not a.product:
        die("--product must be the lowercase name used in the Server/X-Powered-By banner")
    for c in a.cve:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", c):
            die(f"{c!r} is not a CVE id")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", a.published):
        die("--published must be YYYY-MM-DD")
    lines = ["", "[[advisory]]", f"id = {toml_str(a.id)}", f"product = {toml_str(a.product)}", f"title = {toml_str(a.title)}",
             f"severity = {toml_str(a.severity)}", f"cves = [{', '.join(toml_str(c) for c in a.cve)}]",
             f"published = {toml_str(a.published)}", f"summary = {toml_str(a.summary)}", f"remediation = {toml_str(a.remediation)}",
             "references = [" + ", ".join(toml_str(r) for r in a.reference) + "]",
             f"verified = {'true' if a.verified else 'false'}"]
    if a.any_version:
        lines.append("any_version = true")
    if not a.verified:
        lines.append('notes = ["TODO(agent): which sources were read, on what date, and what is unconfirmed or conflicting."]')
    for spec in a.affected:
        kv = dict(p.split("=", 1) for p in spec.split(","))
        bad = set(kv) - {"branch", "from", "fixed"}
        if bad:
            die(f"--affected accepts branch=, from=, fixed= (got {sorted(bad)})")
        lines += ["", "[[advisory.affected]]"] + [f"{k} = {toml_str(v)}" for k, v in kv.items()]
    if not a.affected:
        die("at least one --affected rule is required, e.g. --affected branch=1.4,fixed=1.4.2 or --affected from=0.0 (never fixed)")
    path = ROOT / "data/advisories.toml"
    path.write_text(path.read_text().rstrip("\n") + "\n" + "\n".join(lines) + "\n")
    print(f"appended advisory {a.id!r} to data/advisories.toml")
    print("next: fill in notes/verified, write docs/research/<cve>.md, add a mock device + selftest scenario,")
    print("      add a test, then run scripts/verify.sh   (see .claude/skills/add-checker/SKILL.md)")


TEMPLATE = '''//! {name}
//!
//! TODO(agent): one paragraph: what the weakness is, how it shows up remotely, which evidence this
//! checker uses, and what it deliberately does NOT do (it never exploits anything).
//! Research notes: docs/research/{id}.md

use super::*;
use crate::model::Severity;

/// Checker id.
pub const ID: &str = "{id}";

/// {name}
pub struct {struct};

impl Checker for {struct} {{
    fn meta(&self) -> CheckerMeta {{
        CheckerMeta {{
            id: ID,
            name: {name_lit},
            description: {desc_lit},
            category: Category::{category},
            tags: &[],
            uses_active_probes: {active},
        }}
    }}
{needs}
    // TODO(agent): add `fn probes(&self, device: &Device, db: &AdvisoryDb) -> Vec<Probe>` if you need
    // requests beyond `GET /`. Anything beyond that is Probe::active (needs --active).

    fn evaluate(&self, input: &CheckInput) -> Vec<Finding> {{
        // TODO(agent): judge the evidence; delete this line. Use Confidence::Possible whenever a
        // vendor could have back-ported a fix or the signal is circumstantial.
        let _ = (input, Severity::Info);
        vec![]
    }}
}}

#[cfg(test)]
mod tests {{
    use super::super::testutil::*;
    use super::*;

    #[test]
    fn scaffold_must_be_replaced() {{
        panic!("TODO(agent): write real tests: affected, fixed/clean, vendor-packaged (lower confidence), hidden/unknown, hostile input");
    }}
}}
'''


def cmd_rust(a):
    check_id(a.id)
    if a.id in existing_ids():
        die(f"id {a.id!r} already exists")
    mod = a.id.replace("-", "_")
    struct = "".join(p.capitalize() for p in a.id.split("-"))
    needs = [f"Need::Banner({p})" for p in a.banner_port] + [f"Need::Port({p})" for p in a.port]
    needs += (["Need::Ssdp"] if a.ssdp else []) + (["Need::Mdns"] if a.mdns else [])
    needs_src = f"\n    fn needs(&self) -> Vec<Need> {{\n        vec![{', '.join(needs)}]\n    }}\n" if needs else ""
    src = TEMPLATE.format(id=a.id, name=a.name, struct=struct, name_lit=toml_str(a.name), desc_lit=toml_str(a.description),
                          category=CATEGORIES[a.category], active="true" if a.active else "false", needs=needs_src)
    target = ROOT / f"src/checkers/{mod}.rs"
    if target.exists():
        die(f"{target} already exists")
    target.write_text(src)
    modrs = ROOT / "src/checkers/mod.rs"
    text = modrs.read_text()
    mods = list(re.finditer(r"^pub mod (\w+);$", text, re.M))
    after = next((m for m in mods if m.group(1) > mod), None)
    if after:
        text = text[:after.start()] + f"pub mod {mod};\n" + text[after.start():]
    else:
        text = text[:mods[-1].end()] + f"\npub mod {mod};" + text[mods[-1].end():]
    marker = re.search(r"(Box::new\(data_advisory::DataAdvisory\),)", text)
    if not marker:
        die("could not find the registry in src/checkers/mod.rs; add the checker by hand")
    text = text.replace(marker.group(1), f"Box::new({mod}::{struct}),\n                {marker.group(1)}", 1)
    modrs.write_text(text)
    print(f"created src/checkers/{mod}.rs and registered it in src/checkers/mod.rs")
    print("next: implement evaluate()/probes(), replace the placeholder test, add a mock device to src/testkit.rs and a")
    print("      scenario to src/selftest.rs, write docs/research/<cve>.md, run scripts/verify.sh")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="kind", required=True)
    d = sub.add_parser("data", help="data-only advisory")
    d.add_argument("--id", required=True)
    d.add_argument("--product", required=True)
    d.add_argument("--title", required=True)
    d.add_argument("--severity", required=True, choices=SEVERITIES)
    d.add_argument("--cve", action="append", default=[])
    d.add_argument("--published", required=True)
    d.add_argument("--summary", required=True)
    d.add_argument("--remediation", required=True)
    d.add_argument("--reference", action="append", default=[])
    d.add_argument("--affected", action="append", default=[], help="branch=1.4,fixed=1.4.2 | from=0.0 | from=1.2,fixed=1.2.9")
    d.add_argument("--any-version", action="store_true", help="also match banners that name the product without a version (every version affected)")
    d.add_argument("--verified", action="store_true", help="only if checked against the vendor's own advisory")
    r = sub.add_parser("rust", help="Rust checker module")
    r.add_argument("--id", required=True)
    r.add_argument("--name", required=True)
    r.add_argument("--description", required=True)
    r.add_argument("--category", choices=sorted(CATEGORIES), default="other")
    r.add_argument("--port", type=int, action="append", default=[], help="add this TCP port to the sweep")
    r.add_argument("--banner-port", type=int, action="append", default=[], help="add the port and read its banner")
    r.add_argument("--ssdp", action="store_true")
    r.add_argument("--mdns", action="store_true")
    r.add_argument("--active", action="store_true", help="the checker will use Probe::active requests")
    a = p.parse_args()
    {"data": cmd_data, "rust": cmd_rust}[a.kind](a)


if __name__ == "__main__":
    main()
