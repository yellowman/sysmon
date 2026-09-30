package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"sysmon-web/internal/auth"
)

func runOIDCBootstrap(args []string) int {
	flags := flag.NewFlagSet("oidc-bootstrap", flag.ContinueOnError)
	issuer := flags.String("issuer", "", "authd issuer URL")
	redirect := flags.String("redirect", "", "public Sysmon URL ending in /auth/callback")
	token := flags.String("registration-token-file", "", "owner-only file containing the one-use registration token")
	output := flags.String("client-file", "/var/lib/sysmon/oidc-client.json", "owner-only client credentials file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *issuer == "" || *redirect == "" {
		fmt.Fprintln(os.Stderr, "usage: sysmon-web oidc-bootstrap -issuer URL -redirect https://SYSMON_HOST/auth/callback -registration-token-file PATH [-client-file PATH]")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg, err := auth.EnsureOIDCRegistered(ctx, auth.OIDCConfig{Issuer: *issuer, RedirectURL: *redirect, ClientFile: *output, RegistrationTokenFile: *token})
	if err != nil {
		fmt.Fprintf(os.Stderr, "OIDC bootstrap failed: %v\n", err)
		return 1
	}
	fmt.Printf("OIDC client %s ready; credentials saved in %s\n", cfg.ClientID, *output)
	return 0
}
