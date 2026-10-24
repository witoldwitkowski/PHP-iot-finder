# iotscan: build, install and package.
PREFIX  ?= /usr/local
DESTDIR ?=
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
BIN     ?= target/release/iotscan

.PHONY: build test install uninstall dist deb clean fmt lint

build:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt --check

lint:
	cargo clippy --all-targets -- -D warnings

# Installs the binary built by `make build` (or a prebuilt one: make install BIN=./iotscan).
install:
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/iotscan
	install -Dm644 man/iotscan.1 $(DESTDIR)$(PREFIX)/share/man/man1/iotscan.1
	install -Dm644 packaging/iotscan.desktop $(DESTDIR)$(PREFIX)/share/applications/iotscan.desktop
	install -Dm644 packaging/iotscan.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/iotscan.svg
	mkdir -p $(DESTDIR)$(PREFIX)/share/bash-completion/completions $(DESTDIR)$(PREFIX)/share/zsh/site-functions $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
	$(BIN) completions bash > $(DESTDIR)$(PREFIX)/share/bash-completion/completions/iotscan
	$(BIN) completions zsh  > $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_iotscan
	$(BIN) completions fish > $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/iotscan.fish
	install -Dm644 README.md $(DESTDIR)$(PREFIX)/share/doc/iotscan/README.md
	install -Dm644 docs/WRITING_CHECKERS.md $(DESTDIR)$(PREFIX)/share/doc/iotscan/WRITING_CHECKERS.md
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/doc/iotscan/copyright
	-gtk-update-icon-cache -q $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true
	@echo "Installed. Optional faster discovery: sudo setcap cap_net_raw+ep $(PREFIX)/bin/iotscan"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/iotscan $(DESTDIR)$(PREFIX)/share/man/man1/iotscan.1 \
	      $(DESTDIR)$(PREFIX)/share/applications/iotscan.desktop \
	      $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/iotscan.svg \
	      $(DESTDIR)$(PREFIX)/share/bash-completion/completions/iotscan \
	      $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_iotscan \
	      $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/iotscan.fish
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/iotscan

# Static x86_64 + aarch64 tarballs and .deb packages in dist/.
dist deb:
	./scripts/build-dist.sh

clean:
	cargo clean
	rm -rf dist/work
