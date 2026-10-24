# iotscan

Scan your home network for vulnerable IoT devices. One static binary, no
dependencies, command line **and** an optional graphical interface. It runs
on Ubuntu, Lubuntu and other Linux systems, on x86_64 and on Raspberry Pi
(aarch64).

It ships with a checker for the **October 2026 PHP2Shell flaws
(CVE-2026-109618 / CVE-2026-109619)**, plus end-of-life PHP, exposed
`phpinfo()` pages, Telnet and UPnP. New vulnerabilities are added as small,
tested checkers (often just a few lines of TOML): see
[docs/WRITING_CHECKERS.md](docs/WRITING_CHECKERS.md).

> Only scan networks you own or are authorised to test.

## Quick start

```sh
tar xzf iotscan-0.1.0-x86_64-linux.tar.gz   # or the aarch64 one on a Raspberry Pi
cd iotscan-0.1.0-x86_64-linux
./iotscan selftest        # 15 s, verifies the scanner against mock devices
./iotscan doctor          # shows privileges, interfaces, config
./iotscan                 # scan every local subnet
./iotscan gui             # same, in your browser
```

Install for all users (binary, man page, desktop launcher, shell completions):

```sh
sudo make install                 # /usr/local
# or
sudo apt install ./iotscan_0.1.0_amd64.deb
man iotscan
```

Optional, faster discovery (raw ARP sweep) **without running as root**:

```sh
sudo setcap cap_net_raw+ep "$(command -v iotscan)"
```

The capability is used only to open ARP sockets at start-up and is then
dropped permanently. Without it iotscan still learns MAC addresses from the
kernel's ARP cache.

## What it does

1. **Finds devices** with a TCP sweep, the ARP cache (and raw ARP if allowed),
   mDNS, SSDP/UPnP and IPv6 neighbour discovery, and names them from their MAC
   vendor, UPnP description, mDNS announcements and web page titles.
2. **Identifies services**: HTTP and HTTPS (self-signed is fine), SSH, Telnet,
   FTP, RTSP, MQTT.
3. **Checks** what it found and reports each finding with a **severity** and a
   **confidence**:

   | Confidence | Meaning |
   | --- | --- |
   | confirmed | observed directly (an open Telnet port, a reachable page) |
   | likely | good evidence: an authoritative version in the affected range |
   | possible | weak or indirect: a hidden version, or a Debian/Ubuntu/RHEL build that may have back-ported the fix |

4. **Compares with the last scan**: new devices, devices that vanished, newly
   open ports, new and resolved findings.

```
$ iotscan
iotscan 0.1.0  192.168.1.0/24 · 16 devices · 14.2s

DEVICES
ADDRESS         MAC                 DEVICE                     OPEN PORTS           RISK
192.168.1.20    04:03:12:5a:11:20   Network Camera             23 80 554            ◆ critical
192.168.1.71    10:d0:7a:41:00:71   IP Baby Monitor            23 80                ▲ high
...
FINDINGS  6 on 4 devices

192.168.1.20  Network Camera · 04:03:12:5a:11:20
   ◆ CRITICAL  PHP2Shell: unauthenticated remote code execution in PHP
      likely · port 80 · CVE-2026-109618, CVE-2026-109619
      PHP 7.4.33 on port 80 is on an end-of-life branch. ...
      Fix: Upgrade PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or newer), ...
```

## The PHP2Shell checker, and its limits

It compares the PHP version a device discloses (`X-Powered-By`, `Server`, or a
`phpinfo()` page) with the patched releases **8.5.12, 8.4.27, 8.3.36, 8.2.35**.
PHP 8.1, 8.0 and 7.4 have no official fix and are flagged; older branches are
flagged as *possible* only.

* It **never sends an exploit** or anything that could corrupt memory. These are
  memory-safety bugs, so a truly safe remote *verification* does not exist;
  version evidence is what is available.
* Distributions (Debian, Ubuntu, RHEL, Raspberry Pi OS) **back-port fixes without
  changing the version number**. Such builds are reported as *possible*; check
  `apt changelog php8.2-common | grep CVE-2026-109618` or the vendor's firmware
  notes.
* If a device hides its PHP version, run with `--active`: iotscan then also
  requests well-known paths such as `/phpinfo.php` (plain `GET`s) to read it.
* The affected-version data was compiled from vendor and press write-ups of
  the advisory; the primary sources were not reachable when it was written.
  Verify against [php.net/security](https://www.php.net/security) and correct
  `data/advisories.toml` (or your own `~/.config/iotscan/advisories.toml`) if
  needed: `iotscan advisories` validates it.

## Using it

```sh
iotscan                               # auto-detect and scan local subnets
iotscan 192.168.1.0/24 10.0.0.5       # explicit targets
iotscan --active                      # also look for exposed phpinfo() pages
iotscan -v                            # show evidence for every finding
iotscan --json > scan.json            # machine-readable
iotscan --html report.html            # shareable report (no scripts)
iotscan diff old.json new.json        # compare two scans
iotscan history                       # saved scans
iotscan checkers                      # what can be checked
iotscan --only php2shell,php-eol      # run some checkers
iotscan --fail-on critical -q         # for cron: exit 1 only on critical findings
```

Exit status: `0` fine, `1` findings at or above `--fail-on` (default `high`),
`2` error. Full reference: `man iotscan` (also in [man/iotscan.1](man/iotscan.1)).

### Graphical interface

`iotscan gui` opens a local page: your network shown as a **panel of breakers**
(a tripped breaker needs attention), a prioritised list of findings, a searchable
device table, per-device advice, live progress, comparison with earlier scans and
report export. `iotscan gui --demo` shows sample data without scanning.
It listens on 127.0.0.1 only and needs the private link printed in the terminal.
On Lubuntu/Ubuntu it launches through `xdg-open`; an application-menu entry is
installed by `make install` / the `.deb`.

### Accepting a risk

`~/.config/iotscan/allowlist.toml`:

```toml
[[allow]]
device  = "aa:bb:cc:dd:ee:ff"
checker = "php2shell"
reason  = "Vendor confirmed back-ported fix in firmware 2.4"
expires = "2027-03-01"
```

A reason is required. Suppressed findings are still stored (and shown with
`--show-suppressed`) but do not affect the exit status.

## Safety

* Polite by default: 2 connections per device, 400 new connections/s overall,
  response and banner size caps, deadlines on every exchange. `--fast` relaxes it.
* Only `GET`/`HEAD`/`OPTIONS` are ever sent. No credentials, no logins, no
  exploits. Redirects never leave the device.
* Runs without privileges; the optional capability is dropped after start-up.
* Text from devices is sanitised (no terminal-escape injection) and escaped in HTML.
* Public address ranges need explicit confirmation.

Details and threat model: [docs/SECURITY.md](docs/SECURITY.md).

## Building from source

```sh
cargo build --release                         # dynamic, for this machine
make dist                                     # static x86_64 + aarch64 tarballs and .deb files in dist/
cargo test                                    # unit, integration and end-to-end tests
./target/release/iotscan selftest
```

`make dist` needs `musl-tools` and `gcc-aarch64-linux-gnu`
(`rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl`).
Architecture notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Keeping it current

* **Vulnerability data**: edit `data/advisories.toml`, or drop entries in
  `~/.config/iotscan/advisories.toml`. The MAC-vendor table is refreshed with
  `scripts/update-oui.sh`.
* **Dependencies**: Dependabot opens weekly update PRs, CI runs `cargo audit`
  and `cargo deny`, and the lockfile is committed so builds are reproducible.

## Troubleshooting

Run `iotscan doctor`. Common causes of "I see fewer devices than expected":
the machine is on a different VLAN or guest network than the devices; the
devices drop all probes and have not yet talked on the network (they appear
once they answer ARP); the target was narrowed (see the note at the top of the
report); multicast is filtered by an access point (use `--no-mdns --no-ssdp`).
