// ssh-secret-broker is a stateless SSH server that brokers access to 1Password:
// SSH certificates or whitelisted keys map to principals, and rules in a config
// file map principals to tagged items in a vault.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

func main() {
	configPath := flag.String("config", "/etc/ssh-secret-broker/config.yaml", "path to the config file")
	flag.Parse()
	if err := run(*configPath); err != nil {
		log.Fatal(err)
	}
}

func run(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(cfg.HostKey)
	if err != nil {
		return err
	}
	hostKey, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return err
	}
	token, err := serviceAccountToken()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	store, err := newOPStore(ctx, token, cfg.vaults())
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	audit := slog.New(slog.NewJSONHandler(os.Stdout, nil)) // audit on stdout, operational logs on stderr
	log.Printf("listening on %s, host key %s", ln.Addr(), ssh.FingerprintSHA256(hostKey.PublicKey()))
	serve(ctx, ln, newServerConfig(cfg, hostKey, audit), &Broker{cfg: cfg, store: store, audit: audit})
	log.Print("shut down")
	return nil
}

func serviceAccountToken() (string, error) {
	if t := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"); t != "" {
		return t, nil
	}
	if path := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN_FILE"); path != "" {
		data, err := os.ReadFile(path)
		return strings.TrimSpace(string(data)), err
	}
	return "", errors.New("set OP_SERVICE_ACCOUNT_TOKEN or OP_SERVICE_ACCOUNT_TOKEN_FILE")
}
