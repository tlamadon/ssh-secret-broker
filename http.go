package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"

	"github.com/tlamadon/voussh/httpcred"
)

// newVerifier pins voussh's verification keys from a local file. Nothing is
// ever fetched: the broker checks tokens offline.
func newVerifier(h *HTTP) (*httpcred.Verifier, error) {
	raw, err := os.ReadFile(h.JWKS)
	if err != nil {
		return nil, err
	}
	keys, err := httpcred.ParseJWKS(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.JWKS, err)
	}
	return httpcred.NewVerifier(httpcred.VerifierConfig{
		Issuer: h.Issuer, Audience: h.Audience, Origin: h.Origin, Keys: keys,
	})
}

// newHTTPHandler serves the same three verbs as the SSH side:
//
//	GET /v1/<vault>                  list
//	GET /v1/<vault>/<item>/<field>   read
//	PUT /v1/<vault>/<item>/<field>   write, value in the body
//
// A verified token becomes a Caller whose principals are the token's subject
// and "role:<role>"; from there the rules and the audit log are shared.
func newHTTPHandler(v *httpcred.Verifier, b *Broker) http.Handler {
	handle := func(verb string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			claims, err := v.VerifyHTTP(r)
			if err != nil {
				// The reason goes to the audit log, never to the caller.
				b.audit.LogAttrs(r.Context(), slog.LevelInfo, "auth",
					slog.String("remote", r.RemoteAddr),
					slog.String("auth", "jwt"),
					slog.String("decision", "deny"),
					slog.String("reason", err.Error()))
				w.Header().Set("WWW-Authenticate", "DPoP")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			caller := Caller{
				Auth:        "jwt",
				Principals:  []string{claims.Subject, "role:" + claims.Role},
				Fingerprint: claims.KeyThumbprint,
				Subject:     claims.Subject,
				TokenID:     claims.ID,
			}
			req := request{verb, r.PathValue("vault"), r.PathValue("item"), r.PathValue("field")}
			ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
			defer cancel()
			out, code, msg := b.do(ctx, caller, r.RemoteAddr, req, nil, http.MaxBytesReader(w, r.Body, maxValue+1))
			switch code {
			case exitOK:
				if verb == "write" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				io.WriteString(w, out)
			case exitDenied: // denied and missing are the same answer, as over SSH
				http.Error(w, msg, http.StatusNotFound)
			case exitUsage:
				http.Error(w, msg, http.StatusBadRequest)
			default:
				http.Error(w, msg, http.StatusBadGateway)
			}
		}
	}
	mux := http.NewServeMux()
	mux.Handle("GET /v1/{vault}", handle("list"))
	mux.Handle("GET /v1/{vault}/{item}/{field}", handle("read"))
	mux.Handle("PUT /v1/{vault}/{item}/{field}", handle("write"))
	return mux
}

// newHTTPServer binds the listener and loads the keys, so that a bad address,
// certificate or JWKS file stops the broker at startup.
func newHTTPServer(h *HTTP, b *Broker) (*http.Server, net.Listener, error) {
	v, err := newVerifier(h)
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{
		Handler:           newHTTPHandler(v, b),
		ReadHeaderTimeout: handshakeTimeout,
		ReadTimeout:       requestTimeout,
		WriteTimeout:      requestTimeout,
		IdleTimeout:       requestTimeout,
		MaxHeaderBytes:    16 << 10,
	}
	if h.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(h.TLSCert, h.TLSKey)
		if err != nil {
			return nil, nil, err
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	ln, err := net.Listen("tcp", h.Listen)
	if err != nil {
		return nil, nil, err
	}
	return srv, ln, nil
}

// serveHTTP serves until ctx is cancelled, then lets in-flight requests finish.
func serveHTTP(ctx context.Context, srv *http.Server, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()
		srv.Shutdown(shut)
	}()
	var err error
	if srv.TLSConfig != nil {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
