package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"

	"sysmon-web/internal/api"
	"sysmon-web/internal/auth"
	"sysmon-web/internal/config"
	"sysmon-web/internal/monitoring"
	"sysmon-web/internal/push"
	"sysmon-web/internal/settings"
)

func main() {
	// Command line flags
	socketPath := flag.String("socket", "/var/run/sysmon-web.sock", "FastCGI socket path")
	configPath := flag.String("config", "/etc/sysmon.conf", "Sysmon config file path")
	sysmonAddr := flag.String("sysmon", "localhost:1345", "Sysmon daemon address (default port 1345)")
	auditLog := flag.String("audit", "/var/log/sysmon-web-audit.log", "Audit log path")
	backupDir := flag.String("backups", "/var/backups/sysmon", "Backup directory")
	templateDir := flag.String("templates", "", "Templates directory (default: auto-detect)")
	listen := flag.String("listen", "", "HTTP listen address (for dev mode, leave empty for FastCGI)")
	flag.Parse()

	// Initialize services
	log.Println("Initializing sysmon web configuration manager...")

	// Auto-detect template directory if not specified
	finalTemplateDir := *templateDir
	if finalTemplateDir == "" {
		// Try installed location first
		if _, err := os.Stat("/usr/local/libexec/sysmon-web/templates"); err == nil {
			finalTemplateDir = "/usr/local/libexec/sysmon-web/templates"
			log.Printf("Using installed templates at %s", finalTemplateDir)
		} else if _, err := os.Stat("./templates"); err == nil {
			// Fall back to development location
			finalTemplateDir = "./templates"
			log.Printf("Using development templates at %s", finalTemplateDir)
		} else {
			log.Fatal("Could not find templates directory. Use -templates flag to specify location.")
		}
	}

	// Load templates
	if err := api.InitTemplates(finalTemplateDir); err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}
	log.Printf("Templates loaded successfully from %s", finalTemplateDir)

	configService := config.NewService(*configPath, *backupDir, *auditLog)
	monitoringService := monitoring.NewService(*sysmonAddr)

	// Web-only settings (push credentials etc.) live in their own bbolt
	// store, not in sysmon.conf — they aren't sysmond's concern.
	settingsStore, err := settings.NewStore("/var/lib/sysmon/settings.db")
	if err != nil {
		log.Fatalf("Failed to initialize settings store: %v", err)
	}
	defer settingsStore.Close()

	// pushFactory rebuilds the push service from a config. Used by main
	// for boot, and by the router for on-demand reinit if boot failed
	// (e.g. /var/lib/sysmon/push.db was unwritable at boot but the
	// operator has since fixed permissions).
	pushFactory := func(cfg push.Config) (*push.Service, error) {
		svc, err := push.NewService(cfg, "/var/lib/sysmon/push.db", monitoringService)
		if err != nil {
			return nil, err
		}
		svc.Start()
		return svc, nil
	}

	// Initialize push notification service from the settings store. If
	// init fails (e.g. push.db is unwritable at boot), pushService stays
	// nil; the router retries via pushFactory on the next settings
	// change, so the operator can fix the underlying problem and apply
	// settings through the admin UI without a process restart. Lifecycle
	// (Stop) is owned by the router, not this local — see the shutdown
	// func returned by NewRouter — because the router may swap in a
	// lazily-created instance that this local would never see.
	var pushService *push.Service
	if pc, err := settingsStore.GetPush(); err != nil {
		log.Printf("WARNING: could not read push settings: %v", err)
	} else {
		svc, err := pushFactory(push.Config{
			Enabled:        pc.Enabled,
			FCMCredentials: pc.FCMCredentials,
			APNsCertPEM:    pc.APNsCertPEM,
			APNsKeyPEM:     pc.APNsKeyPEM,
			APNsBundleID:   pc.APNsBundleID,
			APNsProduction: pc.APNsProduction,
		})
		if err != nil {
			log.Printf("WARNING: push notification init failed: %v (will retry on next settings change)", err)
		} else {
			pushService = svc
		}
	}

	// Initialize auth service
	authService, err := auth.NewService("/var/lib/sysmon/auth.db")
	if err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}
	defer authService.Close()

	// Create API router. The returned stopPush shuts down whichever push
	// service the router ends up owning (boot instance or a lazy reinit).
	handler, stopPush := api.NewRouter(configService, monitoringService, pushService, pushFactory, authService, settingsStore)
	defer stopPush()

	// Development mode (HTTP) or production (FastCGI)
	if *listen != "" {
		// HTTP mode for development
		log.Printf("Starting HTTP server on %s (development mode)", *listen)
		if err := http.ListenAndServe(*listen, handler); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	} else {
		// FastCGI mode for production
		log.Printf("Starting FastCGI server on socket %s", *socketPath)

		// Remove old socket if exists
		os.Remove(*socketPath)

		// Create socket
		listener, err := net.Listen("unix", *socketPath)
		if err != nil {
			log.Fatalf("Failed to create socket: %v", err)
		}
		defer listener.Close()

		// Set permissions on socket
		if err := os.Chmod(*socketPath, 0660); err != nil {
			log.Fatalf("Failed to chmod socket: %v", err)
		}

		// Serve FastCGI
		log.Println("Ready to accept connections")
		if err := fcgi.Serve(listener, handler); err != nil {
			log.Fatalf("FastCGI server failed: %v", err)
		}
	}
}
