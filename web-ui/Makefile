PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
LIBEXECDIR = $(PREFIX)/libexec
TEMPLATEDIR = $(LIBEXECDIR)/sysmon-web/templates
STATICDIR = $(LIBEXECDIR)/sysmon-web/static

GO = go
# Binary optimization flags:
# -s: strip symbol table (reduces size, but makes debugging harder)
# -w: strip DWARF debugging information (reduces size)
# Current binary size: ~8.3MB (stripped)
# Size breakdown: ~8MB code, ~377KB data, ~193KB bss
# Main contributors: Go runtime, net/http, crypto/tls, encoding/xml, html/template
# NOTE: crypto/tls (~2-3MB) is pulled in by net/http even though we don't use HTTPS
GOFLAGS = -ldflags="-s -w"

.PHONY: all build build-small clean install uninstall dev

all: build

build:
	cd backend && $(GO) build $(GOFLAGS) -o sysmon-web ./cmd/sysmon-web

# Alternative build with additional size optimizations
# Uses UPX compression (if installed) to reduce binary size by ~50-70%
# Final size typically: ~2-4MB (vs ~8.3MB uncompressed)
# Note: UPX-compressed binaries are slower to start but run at full speed
build-small: build
	@which upx > /dev/null 2>&1 && upx --best --lzma backend/sysmon-web || \
		(echo "Warning: UPX not installed. Binary not compressed."; \
		 echo "Install with: apt-get install upx-ucl (Debian/Ubuntu)"; \
		 echo "          or: yum install upx (RHEL/CentOS)"; \
		 echo "          or: brew install upx (macOS)")

clean:
	rm -f backend/sysmon-web

install: build
	install -d $(BINDIR)
	install -d $(LIBEXECDIR)/sysmon-web
	install -d $(TEMPLATEDIR)
	install -d $(STATICDIR)
	install -m 755 backend/sysmon-web $(BINDIR)/sysmon-web
	install -m 644 backend/templates/*.html $(TEMPLATEDIR)/
	@echo "Installation complete!"
	@echo "Run: sysmon-web -listen :8080 (dev mode)"
	@echo "Or configure as FastCGI service"

uninstall:
	rm -f $(BINDIR)/sysmon-web
	rm -rf $(LIBEXECDIR)/sysmon-web

dev:
	cd backend && $(GO) run ./cmd/sysmon-web -listen :8080 -templates ./templates -config ../sysmon.conf

test:
	cd backend && $(GO) test ./...

fmt:
	cd backend && $(GO) fmt ./...
