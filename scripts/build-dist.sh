#!/bin/sh
# Build static release binaries for x86_64 and aarch64 and package them.
#
# Needs: rustup targets x86_64-unknown-linux-musl and aarch64-unknown-linux-musl,
#        musl-tools (musl-gcc) and gcc-aarch64-linux-gnu, dpkg-deb.
set -eu
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
OUT=dist
WORK=$OUT/work
rm -rf "$WORK"; mkdir -p "$WORK" "$OUT"

build_one() {
    target=$1; arch=$2; debarch=$3
    echo "==> building $target"
    cargo build --release --locked --target "$target"
    bin=target/$target/release/iotscan

    # --- tarball ---
    name=iotscan-$VERSION-$arch-linux
    d=$WORK/$name
    mkdir -p "$d"
    cp "$bin" "$d/iotscan"
    cp -r man packaging docs README.md LICENSE CHANGELOG.md "$d/"
    cat > "$d/install.sh" <<'INST'
#!/bin/sh
# Installs iotscan system-wide (default /usr/local). Run with sudo.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
prefix=${PREFIX:-/usr/local}
install -Dm755 "$here/iotscan" "$prefix/bin/iotscan"
install -Dm644 "$here/man/iotscan.1" "$prefix/share/man/man1/iotscan.1"
install -Dm644 "$here/packaging/iotscan.desktop" "$prefix/share/applications/iotscan.desktop"
install -Dm644 "$here/packaging/iotscan.svg" "$prefix/share/icons/hicolor/scalable/apps/iotscan.svg"
mkdir -p "$prefix/share/bash-completion/completions"
"$prefix/bin/iotscan" completions bash > "$prefix/share/bash-completion/completions/iotscan"
echo "Installed to $prefix. Try: iotscan selftest && iotscan"
echo "Optional faster discovery: sudo setcap cap_net_raw+ep $prefix/bin/iotscan"
INST
    chmod 755 "$d/install.sh"
    tar -C "$WORK" -czf "$OUT/$name.tar.gz" "$name"

    # --- .deb ---
    p=$WORK/deb-$debarch
    mkdir -p "$p/DEBIAN" "$p/usr/bin" "$p/usr/share/man/man1" "$p/usr/share/applications" \
             "$p/usr/share/icons/hicolor/scalable/apps" "$p/usr/share/doc/iotscan" \
             "$p/usr/share/bash-completion/completions"
    install -m755 "$bin" "$p/usr/bin/iotscan"
    gzip -9n -c man/iotscan.1 > "$p/usr/share/man/man1/iotscan.1.gz"
    install -m644 packaging/iotscan.desktop "$p/usr/share/applications/iotscan.desktop"
    install -m644 packaging/iotscan.svg "$p/usr/share/icons/hicolor/scalable/apps/iotscan.svg"
    install -m644 README.md "$p/usr/share/doc/iotscan/README.md"
    install -m644 docs/WRITING_CHECKERS.md "$p/usr/share/doc/iotscan/WRITING_CHECKERS.md"
    install -m644 LICENSE "$p/usr/share/doc/iotscan/copyright"
    # completions come from the host-runnable binary when possible; otherwise skipped
    if [ "$arch" = "$(uname -m)" ]; then "$bin" completions bash > "$p/usr/share/bash-completion/completions/iotscan"; fi
    size=$(du -sk "$p" | cut -f1)
    cat > "$p/DEBIAN/control" <<CTRL
Package: iotscan
Version: $VERSION
Section: net
Priority: optional
Architecture: $debarch
Installed-Size: $size
Maintainer: iotscan contributors <noreply@example.invalid>
Description: Scan your home network for vulnerable IoT devices
 iotscan finds the devices on your local network, identifies what they run and
 checks for known vulnerabilities such as the October 2026 PHP2Shell flaws
 (CVE-2026-109618 and CVE-2026-109619), end-of-life PHP, exposed Telnet and UPnP.
 It is a single static binary, runs without privileges, and includes a local web
 interface (iotscan gui). Optional: sudo setcap cap_net_raw+ep /usr/bin/iotscan
 enables a faster raw ARP sweep.
CTRL
    cat > "$p/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
if command -v gtk-update-icon-cache >/dev/null 2>&1; then gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true; fi
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q 2>/dev/null || true; fi
exit 0
POST
    chmod 755 "$p/DEBIAN/postinst"
    dpkg-deb --root-owner-group --build "$p" "$OUT/iotscan_${VERSION}_${debarch}.deb" >/dev/null
}

build_one x86_64-unknown-linux-musl  x86_64  amd64
build_one aarch64-unknown-linux-musl aarch64 arm64

( cd "$OUT" && sha256sum iotscan-*.tar.gz iotscan_*.deb > SHA256SUMS )
rm -rf "$WORK"
echo "==> done"; ls -la "$OUT"
