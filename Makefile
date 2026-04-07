BINARY        := dns-message-broker
EXAMPLE       := dnc
EXAMPLE2      := dchat
SOCKS_CLIENT  := socks-client
EXIT_NODE     := exit-node
VERSION       := $(shell cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
DIST          := dist

# Targets
LINUX_X64  := x86_64-unknown-linux-musl
LINUX_ARM  := aarch64-unknown-linux-musl
MACOS_X64  := x86_64-apple-darwin
MACOS_ARM  := aarch64-apple-darwin

.PHONY: all build test clean dist linux-x64 linux-arm macos-x64 macos-arm setup

# Touch crate roots to force cargo to rebuild everything.
TOUCH_SOURCES := src/lib.rs src/main.rs crates/dns-socks-proxy/src/lib.rs crates/dns-socks-proxy/src/bin/socks_client.rs crates/dns-socks-proxy/src/bin/exit_node.rs examples/dnc.rs examples/dchat.rs

all: build

build:
	@touch $(TOUCH_SOURCES)
	cargo build --release --workspace --examples

test:
	cargo test --workspace

setup:
	rustup target add $(LINUX_X64) $(LINUX_ARM)
	@echo "Ensure zig is installed: brew install zig"
	@echo "Ensure cargo-zigbuild is installed: cargo install cargo-zigbuild"

# --- Helper to copy all binaries into dist ---

define COPY_BINS
	@mkdir -p $(DIST)/$(1)
	cp target/$(1)/release/$(BINARY) $(DIST)/$(1)/
	cp target/$(1)/release/examples/$(EXAMPLE) $(DIST)/$(1)/
	cp target/$(1)/release/examples/$(EXAMPLE2) $(DIST)/$(1)/
	cp target/$(1)/release/$(SOCKS_CLIENT) $(DIST)/$(1)/
	cp target/$(1)/release/$(EXIT_NODE) $(DIST)/$(1)/
	@echo "Built: $(DIST)/$(1)/"
endef

# --- Linux musl static builds (via zig) ---

linux-x64:
	@touch $(TOUCH_SOURCES)
	cargo zigbuild --release --workspace --target $(LINUX_X64)
	cargo zigbuild --release --examples --target $(LINUX_X64)
	$(call COPY_BINS,$(LINUX_X64))

linux-arm:
	@touch $(TOUCH_SOURCES)
	cargo zigbuild --release --workspace --target $(LINUX_ARM)
	cargo zigbuild --release --examples --target $(LINUX_ARM)
	$(call COPY_BINS,$(LINUX_ARM))

# --- macOS builds ---

macos-x64:
	@touch $(TOUCH_SOURCES)
	cargo build --release --workspace --target $(MACOS_X64)
	cargo build --release --examples --target $(MACOS_X64)
	$(call COPY_BINS,$(MACOS_X64))

macos-arm:
	@touch $(TOUCH_SOURCES)
	cargo build --release --workspace --target $(MACOS_ARM)
	cargo build --release --examples --target $(MACOS_ARM)
	$(call COPY_BINS,$(MACOS_ARM))

# --- Bundles ---

linux: linux-x64 linux-arm

macos: macos-arm

dist: linux macos
	@echo ""
	@echo "All builds in $(DIST)/:"
	@ls -d $(DIST)/*/

# --- Tarballs ---

tarball-linux-x64: linux-x64
	tar -czf $(DIST)/$(BINARY)-$(VERSION)-linux-x64.tar.gz -C $(DIST)/$(LINUX_X64) .

tarball-linux-arm: linux-arm
	tar -czf $(DIST)/$(BINARY)-$(VERSION)-linux-arm64.tar.gz -C $(DIST)/$(LINUX_ARM) .

tarball-macos-x64: macos-x64
	tar -czf $(DIST)/$(BINARY)-$(VERSION)-macos-x64.tar.gz -C $(DIST)/$(MACOS_X64) .

tarball-macos-arm: macos-arm
	tar -czf $(DIST)/$(BINARY)-$(VERSION)-macos-arm64.tar.gz -C $(DIST)/$(MACOS_ARM) .

tarballs: tarball-linux-x64 tarball-linux-arm tarball-macos-x64 tarball-macos-arm
	@echo ""
	@ls -lh $(DIST)/*.tar.gz

clean:
	cargo clean
	rm -rf $(DIST)
