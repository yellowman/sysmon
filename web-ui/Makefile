PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
LIBEXECDIR = $(PREFIX)/libexec
TEMPLATEDIR = $(LIBEXECDIR)/sysmon-web/templates

GO = go
# Binary optimization flags:
# -s: strip symbol table (reduces size, but makes debugging harder)
# -w: strip DWARF debugging information (reduces size)
# Current binary size: ~8.3MB (stripped)
# Size breakdown: ~8MB code, ~377KB data, ~193KB bss
# Main contributors: Go runtime, net/http, crypto/tls, encoding/xml, html/template
# NOTE: crypto/tls (~2-3MB) is pulled in by net/http even though we don't use HTTPS
# -buildvcs=false: nothing in sysmon-web reads the VCS stamp, and asking
# git for it fails in the situations people actually build in - root in
# another user's checkout (git refuses the repo as dubious), or a
# tarball with no .git at all.
GOFLAGS = -buildvcs=false -ldflags="-s -w"

.PHONY: all build build-small clean install uninstall dev css

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

# Templates and static assets are read from disk; the old copies are
# replaced wholesale so removed files do not linger. Restart the service
# after - templates parse at startup, so a running process keeps serving
# whatever it started with.
#
# install does NOT rebuild. The usual flow is "make" as yourself, then
# "make install" as root - and a rebuild as root writes root-owned
# artifacts into your checkout and trips git's dubious-ownership
# refusal. Install copies what the build produced, or says to build.
install:
	@test -x backend/sysmon-web || \
		{ echo "*** backend/sysmon-web is not built - run 'make' first (as your build user, not root)"; exit 1; }
	install -d $(BINDIR)
	install -m 755 backend/sysmon-web $(BINDIR)/sysmon-web
	rm -rf $(LIBEXECDIR)/sysmon-web
	install -d $(TEMPLATEDIR)
	install -m 644 backend/templates/*.html $(TEMPLATEDIR)/
	cp -R backend/static $(LIBEXECDIR)/sysmon-web/static
	@echo "Installation complete - restart the sysmon-web service to pick it up."

uninstall:
	rm -f $(BINDIR)/sysmon-web
	rm -rf $(LIBEXECDIR)/sysmon-web

dev:
	cd backend && $(GO) run ./cmd/sysmon-web -listen :8080 -templates ./templates -config ../sysmon.conf

# Rebuild the committed Tailwind output after changing classes in the
# templates. Needs node; go build does not.
css:
	cd backend && npx tailwindcss@3.4.19 -c tailwind.config.js -i tailwind.input.css -o static/app.css --minify

test:
	cd backend && $(GO) test ./...

fmt:
	cd backend && $(GO) fmt ./...
