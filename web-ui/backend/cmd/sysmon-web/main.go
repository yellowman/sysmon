package main

import (
	"bytes"
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
	"strconv"
	"syscall"
	"time"

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

// Daemonization environment markers. The detached child inherits these so
// it (a) knows not to re-daemonize and (b) knows which inherited fds to use
// to report readiness and startup diagnostics back to the parent.
const (
	daemonEnvMarker = "_SYSMON_WEB_DAEMON"   // "1" in the child
	readyFDEnv      = "_SYSMON_WEB_READY_FD" // fd the child signals "up" on
	diagFDEnv       = "_SYSMON_WEB_DIAG_FD"  // fd the child logs startup to
	readyByte       = 'R'
	readyTimeout    = 15 * time.Second
)

// diagFile is the child's startup-diagnostics pipe back to the parent (the
// log destination until signalReady runs). nil outside the daemon child.
var diagFile *os.File

// daemonizeAndWait re-executes this process detached from the controlling
// terminal (setsid, std streams to /dev/null) and then BLOCKS until the
// child reports it is actually serving - or dies trying. Only then does it
// exit: 0 with the pid on success, non-zero with the child's captured
// startup output on failure. This closes the classic daemon gap where the
// parent reports success before the child has bound its socket / dropped
// privileges / opened its stores.
//
// Two inherited pipes carry the handshake: a "ready" pipe the child writes
// one byte to when it's up, and a "diag" pipe the child logs startup
// messages to so a failure can be relayed even though the daemon is
// otherwise silent without -debug. std streams stay pointed at /dev/null
// throughout, so the daemon can never SIGPIPE on a post-exit write.
func daemonizeAndWait() {
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

	readyR, readyW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: daemonize: pipe: %v\n", err)
		os.Exit(1)
	}
	diagR, diagW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: daemonize: pipe: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), daemonEnvMarker+"=1", readyFDEnv+"=3", diagFDEnv+"=4")
	cmd.Stdin = null
	cmd.Stdout = null
	cmd.Stderr = null
	cmd.ExtraFiles = []*os.File{readyW, diagW} // -> child fds 3 and 4
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: daemonize: %v\n", err)
		os.Exit(1)
	}
	// The child holds the write ends now; the parent must drop its copies
	// so reads see EOF when the child exits/closes them.
	readyW.Close()
	diagW.Close()

	// Capture the child's startup diagnostics so we can show them if it
	// fails. Drains to EOF (child closes diag on ready or on exit).
	var diag bytes.Buffer
	diagDone := make(chan struct{})
	go func() { io.Copy(&diag, diagR); close(diagDone) }()

	// Wait for the ready byte.
	ready := make(chan bool, 1)
	go func() {
		buf := make([]byte, 1)
		n, _ := readyR.Read(buf)
		ready <- (n == 1 && buf[0] == readyByte)
	}()

	select {
	case ok := <-ready:
		if ok {
			fmt.Printf("sysmon-web: started in background (pid %d)\n", cmd.Process.Pid)
			os.Exit(0)
		}
		// EOF without the ready byte: the child died during startup.
		<-diagDone
		_ = cmd.Wait()
		fmt.Fprintln(os.Stderr, "sysmon-web: failed to start")
		if diag.Len() > 0 {
			os.Stderr.Write(bytes.TrimRight(diag.Bytes(), "\n"))
			fmt.Fprintln(os.Stderr)
		} else {
			fmt.Fprintln(os.Stderr, "(no diagnostics; re-run with -debug)")
		}
		os.Exit(1)
	case <-time.After(readyTimeout):
		// The child never confirmed readiness. Don't leave it orphaned
		// and half-attached to pipes we're about to stop reading (and
		// don't tell the operator to start a second one, which would
		// fight the first for the socket). Abort it and fail.
		_ = cmd.Process.Kill()
		<-diagDone
		_ = cmd.Wait()
		fmt.Fprintf(os.Stderr, "sysmon-web: did not become ready within %s; aborted (pid %d)\n",
			readyTimeout, cmd.Process.Pid)
		if diag.Len() > 0 {
			os.Stderr.Write(bytes.TrimRight(diag.Bytes(), "\n"))
			fmt.Fprintln(os.Stderr)
		} else {
			fmt.Fprintln(os.Stderr, "(no diagnostics; re-run with -debug)")
		}
		os.Exit(1)
	}
}

// signalReady tells the parent (if we were daemonized) that startup
// succeeded and we're about to serve, then detaches from the startup
// channels: it closes the ready/diag pipes and silences logging so the
// running daemon is quiet. No-op when not daemonized (foreground/-debug).
func signalReady() {
	fdStr := os.Getenv(readyFDEnv)
	if fdStr == "" {
		return // not a daemon child
	}
	if fd, err := strconv.Atoi(fdStr); err == nil {
		f := os.NewFile(uintptr(fd), "ready")
		if f != nil {
			f.Write([]byte{readyByte})
			f.Close()
		}
	}
	// Startup is over: stop logging to the parent's diag pipe (which it
	// has stopped reading) and go silent for the rest of our life.
	log.SetOutput(io.Discard)
	if diagFile != nil {
		diagFile.Close()
		diagFile = nil
	}
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
	agentListen := flag.String("agent-listen", "", "TLS address to accept sysmond connections on (e.g. :1347); empty disables")
	agentCert := flag.String("agent-cert", "", "certificate for -agent-listen")
	agentKey := flag.String("agent-key", "", "private key for -agent-listen")
	debug := flag.Bool("debug", false, "run in the foreground and log to stderr (otherwise the daemon is silent)")
	foreground := flag.Bool("foreground", false, "run in the foreground without daemonizing (for systemd/rc supervisors); still silent unless -debug")
	flag.Parse()

	isDaemonChild := os.Getenv(daemonEnvMarker) == "1"

	// Logging destination:
	//   -debug                  -> stderr, verbose, stays (foreground).
	//   daemon child (startup)  -> the diag pipe, so the parent can relay
	//                              a startup failure; signalReady() later
	//                              silences us for the rest of the run.
	//   everything else         -> discard (quiet).
	switch {
	case *debug:
		// leave log going to stderr
	case isDaemonChild:
		if fdStr := os.Getenv(diagFDEnv); fdStr != "" {
			if fd, err := strconv.Atoi(fdStr); err == nil {
				diagFile = os.NewFile(uintptr(fd), "diag")
			}
		}
		if diagFile != nil {
			log.SetOutput(diagFile)
		} else {
			log.SetOutput(io.Discard)
		}
	default:
		log.SetOutput(io.Discard)
	}

	// Daemonize by default. -debug or -foreground keep us attached so a
	// process supervisor (systemd Type=simple, OpenBSD rc) can track the
	// process, and so -debug output actually reaches a terminal. The
	// parent blocks inside daemonizeAndWait until the child confirms it's
	// serving (or fails), so the shell's exit status is meaningful.
	if !*debug && !*foreground && !isDaemonChild {
		daemonizeAndWait() // never returns in the parent
	}

	httpMode := *listen != ""
	amRoot := syscall.Geteuid() == 0

	// === Phase 1: privileged work, then drop as soon as possible ========
	//
	// Bind the listening socket (the only thing that may genuinely need
	// root - e.g. a unix socket inside httpd's /var/www chroot, or a low
	// TCP port), hand the socket to the web server's user, prepare the
	// data directories, and immediately drop to an unprivileged user.
	// Everything after this - opening the bbolt stores, reading config,
	// serving requests - runs unprivileged.

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
		// Don't clobber a socket another live instance is using. Probe
		// it first: if something answers, refuse to start; only a stale
		// or absent socket is safe to remove and rebind. (net.Listen on
		// an existing path fails with EADDRINUSE whether or not anyone is
		// listening, which is why the unconditional Remove existed - but
		// that Remove would yank the socket out from under a running
		// process. The probe distinguishes the two cases.)
		if c, derr := net.DialTimeout("unix", *socketPath, 250*time.Millisecond); derr == nil {
			c.Close()
			log.Fatalf("another sysmon-web is already listening on %s", *socketPath)
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
		// 0660: owner + group read/write, world none - so only the web
		// server's user/group (set above) can connect.
		if err := os.Chmod(*socketPath, 0o660); err != nil {
			log.Fatalf("Failed to chmod socket: %v", err)
		}
	}

	if amRoot {
		// Must succeed while we still have root - otherwise the dropped
		// process can't open its stores / write backups / audit, and the
		// failure surfaces later as an opaque permission error.
		if err := prepareRuntimeDirs(stateDir, *backupDir, *auditLog, dropUID, dropGID); err != nil {
			log.Fatalf("Failed to prepare runtime directories: %v", err)
		}
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
	// CONF - sysmond's bulk object dump, and the difference between a
	// one-round-trip poll and one round trip per host - is privileged.
	monitoringService.SetAuthKeyProvider(func() string {
		snap, err := configService.GetConfig()
		if err != nil {
			return ""
		}
		return snap.Config.Global.AuthKey
	})

	// Host up/down transition history, persisted so it survives restarts.
	if historyStore, err := monitoring.OpenHistory(filepath.Join(stateDir, "history.db")); err != nil {
		log.Printf("WARNING: alert history disabled: %v", err)
	} else {
		monitoringService.SetHistory(historyStore)
		defer historyStore.Close()
	}
	// Refresh the status cache in the background so the per-host sysmond
	// fetch happens off the request path - UI/app requests serve from a
	// warm cache instead of each one driving a fresh N-round-trip query.
	// One second, and one connection: each cycle asks sysmond only for the
	// objects and traps that changed since the last one, so a quiet
	// network costs two round trips and transfers nothing.
	monitoringService.StartPoller(1 * time.Second)
	defer monitoringService.StopPoller()

	// Web-only settings (push credentials etc.) live in their own bbolt
	// store, not in sysmon.conf - they aren't sysmond's concern.
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
	// by the router - see the shutdown func returned by NewRouter.
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

	// Daemons that dial in. Off unless an address and certificate are
	// given: TLS is not optional on this listener, because it carries a
	// bearer token and, later, whole configs.
	if *agentListen != "" {
		if *agentCert == "" || *agentKey == "" {
			log.Printf("WARNING: -agent-listen needs -agent-cert and -agent-key; not accepting daemon connections")
		} else {
			al, aerr := monitoring.ListenForAgents(*agentListen, *agentCert, *agentKey,
				monitoringService,
				func(site, token, addr string) bool {
					return settingsStore.CheckAgentToken(site, token, addr)
				})
			if aerr != nil {
				log.Printf("WARNING: %v", aerr)
			} else {
				defer al.Close()
			}
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

	// Everything that can fail at startup - socket bind, privilege drop,
	// templates, the bbolt stores - is done. Tell the parent we're up
	// (if we were daemonized) before we block in Serve. Anything that
	// goes wrong before here makes the parent report a failed start;
	// anything after here is a running-daemon problem, not a start one.
	signalReady()

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
