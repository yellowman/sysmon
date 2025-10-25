package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"

	"sysmon-web/internal/api"
	"sysmon-web/internal/config"
	"sysmon-web/internal/monitoring"
)

func main() {
	// Command line flags
	socketPath := flag.String("socket", "/var/run/sysmon-web.sock", "FastCGI socket path")
	configPath := flag.String("config", "/etc/sysmon.conf", "Sysmon config file path")
	sysmonAddr := flag.String("sysmon", "localhost:3333", "Sysmon daemon address")
	auditLog := flag.String("audit", "/var/log/sysmon-web-audit.log", "Audit log path")
	backupDir := flag.String("backups", "/var/backups/sysmon", "Backup directory")
	templateDir := flag.String("templates", "./templates", "Templates directory")
	listen := flag.String("listen", "", "HTTP listen address (for dev mode, leave empty for FastCGI)")
	flag.Parse()

	// Initialize services
	log.Println("Initializing sysmon web configuration manager...")

	// Load templates
	if err := api.InitTemplates(*templateDir); err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	configService := config.NewService(*configPath, *backupDir, *auditLog)
	monitoringService := monitoring.NewService(*sysmonAddr)

	// Create API router
	handler := api.NewRouter(configService, monitoringService)

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
