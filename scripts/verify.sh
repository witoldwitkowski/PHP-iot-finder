#!/bin/sh
# One command that decides whether a change is done. Used by contributors, CI and agents.
#   scripts/verify.sh          full gate
#   scripts/verify.sh --quick  skip the slow integration tests
set -u
cd "$(dirname "$0")/.."
quick=0; [ "${1:-}" = "--quick" ] && quick=1
fail=0
step() { printf '\n==> %s\n' "$1"; }
run()  { if ! "$@"; then printf 'FAILED: %s\n' "$*"; fail=1; fi; }

step "no unfinished scaffold markers"
if grep -rn --exclude=_TEMPLATE.md "TODO(agent)" src data docs/research 2>/dev/null; then
    echo "FAILED: resolve every TODO(agent) marker"; fail=1
fi

step "agent/docs references point at real files"
run python3 - <<'PY'
import re, sys, pathlib
root = pathlib.Path(".")
docs = [*root.glob(".claude/**/*.md"), root / "CLAUDE.md", *root.glob("docs/*.md"), root / "README.md"]
bad = []
for d in docs:
    for ref in set(re.findall(r"`((?:scripts|docs|src|data|tests|assets|man|packaging)/[A-Za-z0-9_./-]+)`", d.read_text())):
        if any(ch in ref for ch in "<>*") or ref.endswith("/"):
            continue
        if not (root / ref).exists():
            bad.append(f"{d}: `{ref}` does not exist")
for m in re.findall(r"\.claude/(?:skills|agents)/[\w./-]+", (root / "CLAUDE.md").read_text() + (root / "docs/CVE_INTAKE.md").read_text()):
    if not (root / m).exists() and "<" not in m:
        bad.append(f"missing {m}")
for f in [*root.glob(".claude/skills/*/SKILL.md"), *root.glob(".claude/agents/*.md")]:
    t = f.read_text()
    if not t.startswith("---\n") or "\nname:" not in t.split("---", 2)[1] or "\ndescription:" not in t.split("---", 2)[1]:
        bad.append(f"{f}: needs YAML frontmatter with name and description")
print("\n".join(bad) if bad else "all references resolve")
sys.exit(1 if bad else 0)
PY

step "formatting";  run cargo fmt --check
step "lints";       run cargo clippy --all-targets --locked -- -D warnings
if [ $quick -eq 1 ]; then
    step "unit tests (quick)"; run cargo test --locked --lib
else
    step "all tests (unit, engine, CLI, GUI, plugin API)"; run cargo test --locked
fi
step "built-in selftest (includes the plugin conformance rules)"
run cargo run --locked --quiet -- selftest
step "advisory database"
run cargo run --locked --quiet -- advisories
if command -v cargo-audit >/dev/null 2>&1; then step "cargo audit"; run cargo audit; else echo "(skipping cargo audit: not installed)"; fi
if command -v cargo-deny  >/dev/null 2>&1; then step "cargo deny";  run cargo deny check; else echo "(skipping cargo deny: not installed)"; fi

if [ $fail -eq 0 ]; then printf '\nALL CHECKS PASSED\n'; else printf '\nSOME CHECKS FAILED\n'; fi
exit $fail
