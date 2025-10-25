PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
LIBEXECDIR = $(PREFIX)/libexec
TEMPLATEDIR = $(LIBEXECDIR)/sysmon-web/templates
STATICDIR = $(LIBEXECDIR)/sysmon-web/static

GO = go
GOFLAGS = -ldflags="-s -w"

.PHONY: all build clean install uninstall dev

all: build

build:
	cd backend && $(GO) build $(GOFLAGS) -o sysmon-web ./cmd/sysmon-web

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
