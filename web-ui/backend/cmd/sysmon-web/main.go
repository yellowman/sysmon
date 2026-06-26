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
	"path/filepath"
	"syscall"

	"sysmon-web/internal/api"
	"sysmon-web/internal/auth"
	"sysmon-web/internal/config"
	"sysmon-web/internal/monitoring"
	"sysmon-web/internal/push"
	"sysmon-web/internal/settings"
)

// stateDir holds the bbolt stores (auth.db, push.db, settings.db).
const stateDir = "/var/lib/sysmon"

// defaultSocket is the FastCGI socket path when -socket isn't given, on
// every platform. /var/www/run is inside httpd(8)'s chroot on OpenBSD
// (referenced chroot-relative as "/run/sysmon-web.sock" in httpd.conf);
// on Linux nginx just connects to the path. The binary creates the parent
// directory before binding.
const defaultSocket = "/var/www/run/sysmon-web.sock"

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

func main() {
	// Command line flags
	socketPath := flag.String("socket", defaultSocket, "FastCGI socket path")
	configPath := flag.String("config", "/etc/sysmon.conf", "Sysmon config file path")
	sysmonAddr := flag.String("sysmon", "localhost:1345", "Sysmon daemon address (default port 1345)")
	auditLog := flag.String("audit", "/var/log/sysmon-web-audit.log", "Audit log path")
	backupDir := flag.String("backups", "/var/backups/sysmon", "Backup directory")
	templateDir := flag.String("templates", "", "Templates directory (default: auto-detect)")
	listen := flag.String("listen", "", "HTTP listen address (for dev mode, leave empty for FastCGI)")
	socketUser := flag.String("socket-user", "", "owner for the FastCGI socket (default: first of www, www-data, nobody)")
	socketGroup := flag.String("socket-group", "", "group for the FastCGI socket (default: first of www, www-data, nobody)")
	procUser := flag.String("user", "", "drop to this user when started as root (default: first of _sysmon, nobody)")
	procGroup := flag.String("group", "", "drop to this group when started as root (default: first of _sysmon, nobody)")
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

	httpMode := *listen != ""
	amRoot := syscall.Geteuid() == 0

	// === Phase 1: privileged work, then drop as soon as possible ========
	//
	// Bind the listening socket (the only thing that may genuinely need
	// root — e.g. a unix socket inside httpd's /var/www chroot, or a low
	// TCP port), hand the socket to the web server's user, prepare the
	// data directories, and immediately drop to an unprivileged user.
	// Everything after this — opening the bbolt stores, reading config,
	// serving requests — runs unprivileged.

	// Resolve the drop target before binding so we fail fast and loud if
	// there's no unprivileged account to drop to. The gid defaults to the
	// drop user's primary group; -group overrides it.
	dropUID, dropGID := -1, -1
	if amRoot {
		var ok bool
		dropUID, dropGID, _, ok = resolveUser(*procUser, "_sysmon", "nobody")
		if !ok {
			log.Fatalf("refusing to run as root: no unprivileged user to drop to " +
				"(tried -user, then _sysmon, then nobody). Create a _sysmon account or pass -user.")
		}
		if *procGroup != "" {
			gid, gok := resolveGroup(*procGroup)
			if !gok {
				log.Fatalf("group %q (from -group) not found", *procGroup)
			}
			dropGID = gid
		}
	}

	var listener net.Listener
	if httpMode {
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatalf("Failed to listen on %s: %v", *listen, err)
		}
		listener = ln
	} else {
		if err := os.MkdirAll(filepath.Dir(*socketPath), 0o755); err != nil {
			log.Fatalf("Failed to create socket directory: %v", err)
		}
		os.Remove(*socketPath)
		ln, err := net.Listen("unix", *socketPath)
		if err != nil {
			log.Fatalf("Failed to create socket: %v", err)
		}
		listener = ln

		// Hand the socket to the web server's user/group while we still
		// can (only root may chown to another user). Without this a
		// root-started daemon leaves the socket root-owned (root:wheel on
		// BSD) and nginx/httpd get EACCES.
		if amRoot {
			sUID, sGID, _, sOK := resolveUser(*socketUser, "www", "www-data", "nobody")
			if !sOK {
				log.Fatalf("cannot resolve a socket owner (tried -socket-user, then www, www-data, nobody)")
			}
			if *socketGroup != "" {
				gid, gok := resolveGroup(*socketGroup)
				if !gok {
					log.Fatalf("group %q (from -socket-group) not found", *socketGroup)
				}
				sGID = gid
			}
			if err := os.Chown(*socketPath, sUID, sGID); err != nil {
				log.Fatalf("Failed to chown socket: %v", err)
			}
		}
		// 0660: owner + group read/write, world none — so only the web
		// server's user/group (set above) can connect.
		if err := os.Chmod(*socketPath, 0o660); err != nil {
			log.Fatalf("Failed to chmod socket: %v", err)
		}
	}

	if amRoot {
		sockForPrep := *socketPath
		if httpMode {
			sockForPrep = ""
		}
		prepareRuntimeDirs(sockForPrep, stateDir, *backupDir, *auditLog, dropUID, dropGID)
		if err := dropPrivileges(dropUID, dropGID); err != nil {
			log.Fatalf("Failed to drop privileges to uid=%d gid=%d: %v", dropUID, dropGID, err)
		}
		log.Printf("Dropped privileges to uid=%d gid=%d", dropUID, dropGID)
	}

	// === Phase 2: unprivileged initialization and serving ===============
	log.Println("Initializing sysmon web configuration manager...")

	// Auto-detect template directory if not specified
	finalTemplateDir := *templateDir
	if finalTemplateDir == "" {
		if _, err := os.Stat("/usr/local/libexec/sysmon-web/templates"); err == nil {
			finalTemplateDir = "/usr/local/libexec/sysmon-web/templates"
			log.Printf("Using installed templates at %s", finalTemplateDir)
		} else if _, err := os.Stat("./templates"); err == nil {
			finalTemplateDir = "./templates"
			log.Printf("Using development templates at %s", finalTemplateDir)
		} else {
			log.Fatal("Could not find templates directory. Use -templates flag to specify location.")
		}
	}

	if err := api.InitTemplates(finalTemplateDir); err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}
	log.Printf("Templates loaded successfully from %s", finalTemplateDir)

	configService := config.NewService(*configPath, *backupDir, *auditLog)
	monitoringService := monitoring.NewService(*sysmonAddr)

	// Web-only settings (push credentials etc.) live in their own bbolt
	// store, not in sysmon.conf — they aren't sysmond's concern.
	settingsStore, err := settings.NewStore(filepath.Join(stateDir, "settings.db"))
	if err != nil {
		log.Fatalf("Failed to initialize settings store: %v", err)
	}
	defer settingsStore.Close()

	// pushFactory rebuilds the push service from a config. Used by main
	// for boot, and by the router for on-demand reinit if boot failed
	// (e.g. push.db was unwritable at boot but the operator has since
	// fixed permissions).
	pushFactory := func(cfg push.Config) (*push.Service, error) {
		svc, err := push.NewService(cfg, filepath.Join(stateDir, "push.db"), monitoringService)
		if err != nil {
			return nil, err
		}
		svc.Start()
		return svc, nil
	}

	// Initialize push notification service from the settings store. If
	// init fails, pushService stays nil; the router retries via
	// pushFactory on the next settings change. Lifecycle (Stop) is owned
	// by the router — see the shutdown func returned by NewRouter.
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
	authService, err := auth.NewService(filepath.Join(stateDir, "auth.db"))
	if err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}
	defer authService.Close()

	// Create API router. The returned stopPush shuts down whichever push
	// service the router ends up owning (boot instance or a lazy reinit).
	handler, stopPush := api.NewRouter(configService, monitoringService, pushService, pushFactory, authService, settingsStore)
	defer stopPush()

	if httpMode {
		log.Printf("Starting HTTP server on %s (development mode)", *listen)
		if err := http.Serve(listener, handler); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	} else {
		log.Printf("Starting FastCGI server on socket %s", *socketPath)
		log.Println("Ready to accept connections")
		if err := fcgi.Serve(listener, handler); err != nil {
			log.Fatalf("FastCGI server failed: %v", err)
		}
	}
}
