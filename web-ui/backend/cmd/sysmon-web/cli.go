package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sysmon-web/internal/monitoring"
	"sysmon-web/internal/settings"
)

// Everything the admin page does to a monitoring box, from a terminal.
//
// Boxes get built by scripts, and a box is not finished until it holds a
// token and a certificate. Making that reachable only through a browser
// means either a person in the loop for every machine, or somebody
// scripting a login - and the second is how a admin password ends up in a
// provisioning repository.
//
// These run before the server starts and then exit.
//
// One limit worth stating plainly: settings.db is a bbolt file and a
// running sysmon-web holds it open. So these work when the service is
// stopped, or on a machine where it has not been started. While it is
// running, the page is the way in. The error says so rather than timing
// out with a lock message nobody can act on.

// cliOptions are the flags that make this a command rather than a daemon.
type cliOptions struct {
	serviceUser  string
	serviceGroup string

	mint    string
	label   string
	replace bool
	list    bool
	revoke  string
}

func (o cliOptions) wanted() bool {
	return o.mint != "" || o.list || o.revoke != ""
}

// runCLI performs the requested command and returns the process exit code.
func runCLI(o cliOptions, agentNames, agentListen string) int {
	dbPath := filepath.Join(stateDir, "settings.db")

	store, err := settings.NewStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: cannot open %s/settings.db: %v\n", stateDir, err)
		if strings.Contains(err.Error(), "timeout") {
			fmt.Fprintln(os.Stderr,
				"  A running sysmon-web holds that file open. Use Admin -> Monitoring\n"+
					"  boxes in the web interface, or stop the service and try again.")
		}
		return 1
	}
	defer store.Close()

	// The service drops privileges; this command usually does not, so a
	// database created or touched here would be left owned by root and the
	// service would fail to open it at its next start. Hand it over.
	handOverToServiceUser(dbPath, o.serviceUser, o.serviceGroup)

	switch {
	case o.list:
		return listAgents(store)
	case o.revoke != "":
		return revokeAgent(store, o.revoke)
	default:
		return mintAgent(store, o.mint, o.label, o.replace, agentNames, agentListen)
	}
}

func listAgents(store *settings.Store) int {
	agents, err := store.ListAgentTokens()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: %v\n", err)
		return 1
	}
	if len(agents) == 0 {
		fmt.Println("No monitoring boxes yet.")
		return 0
	}

	fmt.Printf("%-16s %-28s %-22s %s\n", "SITE", "LABEL", "LAST ADDRESS", "LAST SEEN")
	for _, a := range agents {
		seen := "never"
		if !a.LastSeen.IsZero() {
			seen = a.LastSeen.Format("2006-01-02 15:04:05")
		}
		addr := a.LastAddr
		if addr == "" {
			addr = "-"
		}
		label := a.Label
		if a.Revoked {
			label += " (revoked)"
		}
		fmt.Printf("%-16s %-28s %-22s %s\n", a.Site, label, addr, seen)
	}
	return 0
}

func revokeAgent(store *settings.Store, site string) int {
	if _, held := store.GetAgentToken(site); !held {
		fmt.Fprintf(os.Stderr, "sysmon-web: no box called %q\n", site)
		return 1
	}
	if err := store.RevokeAgentToken(site); err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: %v\n", err)
		return 1
	}
	fmt.Printf("Revoked the token for %s.\n", site)
	fmt.Println("That box stops reporting here. It keeps monitoring and paging.")
	return 0
}

func mintAgent(store *settings.Store, site, label string, replace bool, agentNames, agentListen string) int {
	if !monitoring.ValidSiteName(site) {
		fmt.Fprintf(os.Stderr,
			"sysmon-web: %q is not a usable site name - letters, digits, - and _ only\n", site)
		return 1
	}

	// The same rule the API applies. One token per site, so a second mint
	// stops the box holding the first, and that is not something to do
	// because a script ran twice.
	if existing, held := store.GetAgentToken(site); held && !existing.Revoked && !replace {
		fmt.Fprintf(os.Stderr, "sysmon-web: %s already has a live token", site)
		if !existing.LastSeen.IsZero() {
			fmt.Fprintf(os.Stderr, " (last seen %s from %s)",
				existing.LastSeen.Format("2006-01-02 15:04:05"), existing.LastAddr)
		}
		fmt.Fprintf(os.Stderr, ".\n  Minting another stops the box using it. "+
			"Add -replace-agent if that is what you want.\n")
		return 1
	}

	token, err := store.NewAgentToken(site, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: %v\n", err)
		return 1
	}

	fmt.Print(monitoring.AgentConfigBlock(
		site, label, monitoring.DialTarget(agentNames, agentListen), token))
	// Standard output is the config; this is the advice. They are two
	// streams so a provisioning script can append the first straight to
	// the box's config, and a person still gets told what to do.
	//
	// The certificate is a file. Naming it is more use than wrapping it in
	// a command that would only ever print it.
	fmt.Fprintf(os.Stderr,
		"\nAdd those lines to /etc/sysmon.conf on the box.\n"+
			"The token is shown one time; the server keeps only a hash.\n"+
			"The box also needs %s,\ncopied to its state directory as aggregator-ca.pem\n",
		defaultAgentCert())
	return 0
}

// handOverToServiceUser gives a file to the account sysmon-web runs as.
//
// Silent when not root: there is nothing to hand over, and a normal user
// running -list-agents should not see a warning about it.
func handOverToServiceUser(path, wantUser, wantGroup string) {
	if os.Geteuid() != 0 {
		return
	}
	uid, gid, _, ok := resolveUser(wantUser, "_sysmon", "nobody")
	if !ok {
		fmt.Fprintf(os.Stderr,
			"sysmon-web: warning: cannot find the account the service runs as, "+
				"so %s is left owned by root and the service may not start\n", path)
		return
	}
	if wantGroup != "" {
		if _, g, _, gok := resolveUser(wantGroup, wantGroup); gok {
			gid = g
		}
	}
	if err := os.Chown(path, uid, gid); err != nil {
		fmt.Fprintf(os.Stderr, "sysmon-web: warning: cannot give %s to uid %d: %v\n",
			path, uid, err)
	}
}

// defaultAgentCert is where a generated certificate lives, for messages
// that need to name it.
func defaultAgentCert() string {
	if p := monitoring.AgentCertPath(); p != "" {
		return p
	}
	return filepath.Join(stateDir, "agent", "agent-cert.pem")
}
