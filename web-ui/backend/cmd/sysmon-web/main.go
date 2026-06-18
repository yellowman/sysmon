package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"sysmon-web/internal/api"
	"sysmon-web/internal/auth"
	"sysmon-web/internal/config"
	"sysmon-web/internal/monitoring"
	"sysmon-web/internal/push"
	"sysmon-web/internal/settings"
)

// daemonEnvMarker is set in the detached child's environment so it knows
// not to re-daemonize (which would fork-bomb).
const daemonEnvMarker = "_SYSMON_WEB_DAEMON"

// daemonize re-executes this process detached from the controlling
// terminal — new session (setsid), std streams to /dev/null — then exits
// the parent. The detached child runs with daemonEnvMarker set so it
// skips this and proceeds to run the server. No-op if we're already the
// child. The working directory is intentionally preserved so relative
// template/static paths still resolve.
func daemonize() {
	if os.Getenv(daemonEnvMarker) == "1" {
		return // we are the detached child
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: daemonize: %v\n", err)
		os.Exit(1)
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: daemonize: open %s: %v\n", os.DevNull, err)
		os.Exit(1)
	}
	defer null.Close()

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), daemonEnvMarker+"=1")
	cmd.Stdin = null
	cmd.Stdout = null
	cmd.Stderr = null
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: daemonize: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("sysmon-web: started in background (pid %d)\n", cmd.Process.Pid)
	os.Exit(0)
}

// chownSocket changes the socket's owner and/or group by name. Either
// may be empty to leave that component unchanged (os.Chown takes -1 for
// "no change"). A no-op when both are empty.
func chownSocket(path, userName, groupName string) error {
	if userName == "" && groupName == "" {
		return nil
	}
	uid, gid := -1, -1
	if userName != "" {
		u, err := user.Lookup(userName)
		if err != nil {
			return fmt.Errorf("lookup user %q: %w", userName, err)
		}
		if uid, err = strconv.Atoi(u.Uid); err != nil {
			return fmt.Errorf("parse uid for %q: %w", userName, err)
		}
	}
	if groupName != "" {
		g, err := user.LookupGroup(groupName)
		if err != nil {
			return fmt.Errorf("lookup group %q: %w", groupName, err)
		}
		if gid, err = strconv.Atoi(g.Gid); err != nil {
			return fmt.Errorf("parse gid for %q: %w", groupName, err)
		}
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %q to %d:%d: %w", path, uid, gid, err)
	}
	return nil
}

func main() {
	// Command line flags
	socketPath := flag.String("socket", "/var/run/sysmon-web.sock", "FastCGI socket path")
	configPath := flag.String("config", "/etc/sysmon.conf", "Sysmon config file path")
	sysmonAddr := flag.String("sysmon", "localhost:1345", "Sysmon daemon address (default port 1345)")
	auditLog := flag.String("audit", "/var/log/sysmon-web-audit.log", "Audit log path")
	backupDir := flag.String("backups", "/var/backups/sysmon", "Backup directory")
	templateDir := flag.String("templates", "", "Templates directory (default: auto-detect)")
	listen := flag.String("listen", "", "HTTP listen address (for dev mode, leave empty for FastCGI)")
	socketUser := flag.String("socket-user", "", "chown the FastCGI socket to this user (so the web server can connect when sysmon-web runs as root)")
	socketGroup := flag.String("socket-group", "", "chgrp the FastCGI socket to this group (e.g. www-data on nginx, www on OpenBSD httpd)")
	debug := flag.Bool("debug", false, "run in the foreground and log to stderr (otherwise the daemon is silent)")
	foreground := flag.Bool("foreground", false, "run in the foreground without daemonizing (for systemd/rc supervisors); still silent unless -debug")
	flag.Parse()

	// Logging is off unless -debug. A daemon shouldn't chatter; if you
	// need to see what's happening, run with -debug in the foreground.
	if !*debug {
		log.SetOutput(io.Discard)
	}

	// Daemonize by default. -debug or -foreground keep us attached so a
	// process supervisor (systemd Type=simple, OpenBSD rc) can track the
	// process, and so -debug output actually reaches a terminal.
	if !*debug && !*foreground {
		daemonize() // exits the parent; the detached child returns here
	}

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

		// Hand the socket to the web server's user/group. Without this,
		// a sysmon-web started as root leaves the socket root-owned
		// (root:wheel on BSD) mode 0660, and nginx/httpd get EACCES.
		if err := chownSocket(*socketPath, *socketUser, *socketGroup); err != nil {
			log.Fatalf("Failed to set socket ownership: %v", err)
		}

		// 0660: owner + group read/write, world none. Combined with the
		// chgrp above this lets exactly the web server connect.
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
