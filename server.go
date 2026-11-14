package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	handshakeTimeout = 10 * time.Second
	requestTimeout   = 30 * time.Second // whole connection, after the handshake
)

func newServerConfig(cfg *Config, hostKey ssh.Signer, audit *slog.Logger) *ssh.ServerConfig {
	sc := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-secret-broker",
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			perms, err := cfg.authenticate(conn, key)
			if err != nil {
				fp := ssh.FingerprintSHA256(key)
				if cert, ok := key.(*ssh.Certificate); ok {
					fp = ssh.FingerprintSHA256(cert.Key)
				}
				audit.LogAttrs(context.Background(), slog.LevelInfo, "auth",
					slog.String("remote", conn.RemoteAddr().String()),
					slog.String("fingerprint", fp),
					slog.String("decision", "deny"),
					slog.String("reason", err.Error()))
			}
			return perms, err
		},
	}
	sc.AddHostKey(hostKey)
	return sc
}

// serve accepts connections until ctx is cancelled, then waits for the
// in-flight ones (each is bounded by requestTimeout).
func serve(ctx context.Context, ln net.Listener, sc *ssh.ServerConfig, b *Broker) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		wg.Go(func() { handleConn(nc, sc, b) })
	}
}

// handleConn serves exactly one exec request on one session channel.
func handleConn(nc net.Conn, sc *ssh.ServerConfig, b *Broker) {
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(handshakeTimeout))
	conn, chans, reqs, err := ssh.NewServerConn(nc, sc)
	if err != nil {
		return // failed authentications are audited by the public key callback
	}
	defer conn.Close()
	nc.SetDeadline(time.Now().Add(requestTimeout))
	go ssh.DiscardRequests(reqs) // refuses port forwarding and other global requests

	var caller Caller
	if err := json.Unmarshal([]byte(conn.Permissions.Extensions[callerExt]), &caller); err != nil {
		return
	}
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.Prohibited, "only session channels are supported")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		for req := range creqs {
			var exec struct{ Command string }
			if req.Type != "exec" || ssh.Unmarshal(req.Payload, &exec) != nil {
				req.Reply(false, nil) // shell, pty, env, subsystem, agent/X11 forwarding
				continue
			}
			req.Reply(true, nil)
			go ssh.DiscardRequests(creqs)

			ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
			out, code, msg := b.Handle(ctx, caller, conn.RemoteAddr().String(), exec.Command, ch)
			cancel()
			io.WriteString(ch, out)
			if msg != "" {
				fmt.Fprintln(ch.Stderr(), msg)
			}
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			ch.Close()
			// One command per connection: refuse anything further and let the
			// client hang up cleanly (the deadline bounds how long we wait).
			go func() {
				for nch := range chans {
					nch.Reject(ssh.Prohibited, "one command per connection")
				}
			}()
			conn.Wait()
			return
		}
		return
	}
}
