package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeStore is an in-memory Store with a single vault layout per name.
type fakeStore map[string][]*Item

func (s fakeStore) List(_ context.Context, vault string) ([]Item, error) {
	var out []Item
	for _, it := range s[vault] {
		out = append(out, Item{ID: it.ID, Title: it.Title, Tags: it.Tags})
	}
	return out, nil
}

func (s fakeStore) find(vault, id string) (*Item, error) {
	for _, it := range s[vault] {
		if it.ID == id {
			return it, nil
		}
	}
	return nil, fmt.Errorf("no item %s", id)
}

func (s fakeStore) Get(_ context.Context, vault, id string) (Item, error) {
	it, err := s.find(vault, id)
	if err != nil {
		return Item{}, err
	}
	return *it, nil
}

func (s fakeStore) SetField(_ context.Context, vault, id, field, value string) error {
	it, err := s.find(vault, id)
	if err != nil {
		return err
	}
	for i, f := range it.Fields {
		if f.ID == field || f.Title == field {
			it.Fields[i].Value = value
			return nil
		}
	}
	it.Fields = append(it.Fields, Field{ID: field, Title: field, Value: value})
	return nil
}

func (s fakeStore) Create(_ context.Context, vault, title, field, value string, tags []string) error {
	s[vault] = append(s[vault], &Item{ID: fmt.Sprint("new", len(s[vault])), Title: title, Tags: tags,
		Fields: []Field{{ID: field, Title: field, Value: value}}})
	return nil
}

const testRules = `
host_key: /dev/null
whitelist:
  - {fingerprint: "SHA256:x", principals: [nobody]}
rules:
  - {principals: [ci, ops], vault: prod, tags: [deploy], access: [list, read]}
  - {principals: [ops], vault: prod, tags: [db, deploy], access: [list, read, write]}
  - {principals: [dev], vault: staging, tags: [app], access: [read]}
`

func testBroker(t *testing.T) (*Broker, fakeStore, *bytes.Buffer) {
	t.Helper()
	cfg, err := parseConfig([]byte(testRules))
	if err != nil {
		t.Fatal(err)
	}
	store := fakeStore{
		"prod": {
			{ID: "1", Title: "api", Tags: []string{"deploy"}, Fields: []Field{{"password", "password", "s3cret-api"}}},
			{ID: "2", Title: "db", Tags: []string{"db", "other"}, Fields: []Field{{"f1", "password", "s3cret-db"}}},
			{ID: "3", Title: "payroll", Tags: []string{"finance"}, Fields: []Field{{"password", "password", "s3cret-pay"}}},
			{ID: "4", Title: "untagged", Fields: []Field{{"password", "password", "s3cret-none"}}},
		},
		"staging": {{ID: "5", Title: "app", Tags: []string{"app"}, Fields: []Field{{"password", "password", "s3cret-stg"}}}},
	}
	audit := &bytes.Buffer{}
	return &Broker{cfg: cfg, store: store, audit: slog.New(slog.NewJSONHandler(audit, nil))}, store, audit
}

func TestAuthorization(t *testing.T) {
	tests := []struct {
		name       string
		principals []string
		cmd        string
		code       int
		out        string
	}{
		{"read in scope", []string{"ci"}, "read prod/api/password", exitOK, "s3cret-api"},
		{"read by field title", []string{"ops"}, "read prod/db/password", exitOK, "s3cret-db"},
		{"read by field id", []string{"ops"}, "read prod/db/f1", exitOK, "s3cret-db"},
		{"any principal suffices", []string{"x", "ci"}, "read prod/api/password", exitOK, "s3cret-api"},
		{"tag out of scope", []string{"ci"}, "read prod/db/password", exitDenied, ""},
		{"no rule covers tag", []string{"ops"}, "read prod/payroll/password", exitDenied, ""},
		{"untagged item", []string{"ops"}, "read prod/untagged/password", exitDenied, ""},
		{"missing item", []string{"ops"}, "read prod/nope/password", exitDenied, ""},
		{"missing field", []string{"ops"}, "read prod/api/nope", exitDenied, ""},
		{"unknown principal", []string{"mallory"}, "read prod/api/password", exitDenied, ""},
		{"no principals", nil, "read prod/api/password", exitDenied, ""},
		{"wrong vault", []string{"ci"}, "read staging/app/password", exitDenied, ""},
		{"unknown vault", []string{"ops"}, "read nope/api/password", exitDenied, ""},
		{"verb not granted: list", []string{"dev"}, "list staging", exitDenied, ""},
		{"verb not granted: write", []string{"ci"}, "write prod/api/password", exitDenied, ""},
		{"list filters by tag", []string{"ci"}, "list prod", exitOK, "api\n"},
		{"list union of rules", []string{"ops"}, "list prod", exitOK, "api\ndb\n"},
		{"write out of scope item", []string{"ops"}, "write prod/payroll/password", exitDenied, ""},
		{"write empty value", []string{"ops"}, "write prod/api/password", exitUsage, ""},
		{"delete is not a verb", []string{"ops"}, "delete prod/api", exitUsage, ""},
		{"bad path", []string{"ops"}, "read prod/api", exitUsage, ""},
		{"empty", []string{"ops"}, "", exitUsage, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _, audit := testBroker(t)
			stdin := "v"
			if tt.code == exitUsage {
				stdin = ""
			}
			out, code, msg := b.Handle(context.Background(), Caller{Principals: tt.principals}, "r", tt.cmd, strings.NewReader(stdin))
			if code != tt.code || out != tt.out {
				t.Fatalf("got (%q, %d, %q), want (%q, %d)", out, code, msg, tt.out, tt.code)
			}
			// Every denial looks the same to the client.
			if code == exitDenied && msg != errDenied.Error() {
				t.Errorf("denial message leaks detail: %q", msg)
			}
			var rec map[string]any
			if err := json.Unmarshal(audit.Bytes(), &rec); err != nil {
				t.Fatalf("audit is not one JSON line: %v: %s", err, audit)
			}
			want := map[int]string{exitOK: "allow", exitDenied: "deny", exitUsage: "error"}[code]
			if rec["decision"] != want {
				t.Errorf("audit decision = %v, want %s", rec["decision"], want)
			}
			if strings.Contains(audit.String(), "s3cret") {
				t.Errorf("audit log contains a secret: %s", audit)
			}
		})
	}
}

func TestWrite(t *testing.T) {
	b, store, audit := testBroker(t)
	ops := Caller{Principals: []string{"ops"}}
	handle := func(cmd, stdin string) int {
		_, code, _ := b.Handle(context.Background(), ops, "r", cmd, strings.NewReader(stdin))
		return code
	}

	// Update: value changes, tags are untouched.
	if code := handle("write prod/db/password", "new-value\n"); code != exitOK {
		t.Fatalf("update: exit %d", code)
	}
	db := store["prod"][1]
	if db.Fields[0].Value != "new-value" || !slices.Equal(db.Tags, []string{"db", "other"}) {
		t.Errorf("after update: %+v", db)
	}

	// Create: the new item carries exactly the tags of the allowing rule.
	if code := handle("write prod/fresh/token", "tok"); code != exitOK {
		t.Fatalf("create: exit %d", code)
	}
	fresh := store["prod"][len(store["prod"])-1]
	if fresh.Title != "fresh" || fresh.Fields[0].Value != "tok" || !slices.Equal(fresh.Tags, []string{"db", "deploy"}) {
		t.Errorf("after create: %+v", fresh)
	}

	// An out-of-scope title is neither overwritten nor duplicated.
	n := len(store["prod"])
	if code := handle("write prod/payroll/password", "x"); code != exitDenied {
		t.Errorf("out of scope write: exit %d", code)
	}
	if len(store["prod"]) != n || store["prod"][2].Fields[0].Value != "s3cret-pay" {
		t.Error("out of scope write changed the store")
	}

	if code := handle("write prod/api/password", strings.Repeat("x", maxValue+1)); code != exitUsage {
		t.Errorf("oversized value: exit %d", code)
	}
	if strings.Contains(audit.String(), "new-value") || strings.Contains(audit.String(), "tok\"") {
		t.Errorf("audit log contains a written value: %s", audit)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := map[string]string{
		"unknown key":     testRules + "extra: 1\n",
		"unknown access":  strings.Replace(testRules, "[read]", "[delete]", 1),
		"no tags":         strings.Replace(testRules, "tags: [app]", "tags: []", 1),
		"no principals":   strings.Replace(testRules, "principals: [dev]", "principals: []", 1),
		"no vault":        strings.Replace(testRules, "vault: staging", `vault: ""`, 1),
		"no host key":     strings.Replace(testRules, "host_key: /dev/null", "", 1),
		"no auth":         "host_key: k\nrules:\n  - {principals: [a], vault: v, tags: [t], access: [read]}\n",
		"no rules":        "host_key: k\nwhitelist:\n  - {fingerprint: \"SHA256:x\", principals: [a]}\n",
		"bad CA":          "trusted_cas: [nonsense]\n" + testRules,
		"bad fingerprint": strings.Replace(testRules, "SHA256:x", "MD5:x", 1),
	}
	for name, data := range bad {
		if _, err := parseConfig([]byte(data)); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

// --- SSH layer ---

func newKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newCert(t *testing.T, ca ssh.Signer, key ssh.PublicKey, mod func(*ssh.Certificate)) *ssh.Certificate {
	t.Helper()
	now := uint64(time.Now().Unix())
	c := &ssh.Certificate{Key: key, Serial: 42, CertType: ssh.UserCert, KeyId: "test-cert",
		ValidPrincipals: []string{"ops"}, ValidAfter: now - 60, ValidBefore: now + 3600}
	if mod != nil {
		mod(c)
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAuthenticate(t *testing.T) {
	ca, otherCA, user, listed := newKey(t), newKey(t), newKey(t), newKey(t)
	cfg := &Config{
		cas:  [][]byte{ca.PublicKey().Marshal()},
		keys: map[string][]string{ssh.FingerprintSHA256(listed.PublicKey()): {"ci"}},
	}
	now := uint64(time.Now().Unix())
	tests := []struct {
		name       string
		key        ssh.PublicKey
		principals []string // nil means rejected
	}{
		{"valid cert", newCert(t, ca, user.PublicKey(), nil), []string{"ops"}},
		{"cert with source-address", newCert(t, ca, user.PublicKey(), func(c *ssh.Certificate) {
			c.CriticalOptions = map[string]string{"source-address": "10.0.0.0/8"}
		}), []string{"ops"}}, // accepted here; the address itself is enforced by the server, see TestEndToEnd
		{"whitelisted key", listed.PublicKey(), []string{"ci"}},
		{"unknown key", user.PublicKey(), nil},
		{"wrong CA", newCert(t, otherCA, user.PublicKey(), nil), nil},
		{"self-signed with whitelisted key", newCert(t, listed, user.PublicKey(), nil), nil},
		{"expired", newCert(t, ca, user.PublicKey(), func(c *ssh.Certificate) { c.ValidBefore = now - 10 }), nil},
		{"not yet valid", newCert(t, ca, user.PublicKey(), func(c *ssh.Certificate) { c.ValidAfter = now + 600 }), nil},
		{"host cert", newCert(t, ca, user.PublicKey(), func(c *ssh.Certificate) { c.CertType = ssh.HostCert }), nil},
		{"unknown critical option", newCert(t, ca, user.PublicKey(), func(c *ssh.Certificate) {
			c.CriticalOptions = map[string]string{"force-command": "x"}
		}), nil},
		{"tampered after signing", func() ssh.PublicKey {
			c := newCert(t, ca, user.PublicKey(), nil)
			c.ValidPrincipals = []string{"root"}
			return c
		}(), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms, err := cfg.authenticate(nil, tt.key)
			if tt.principals == nil {
				if err == nil {
					t.Fatal("accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var c Caller
			json.Unmarshal([]byte(perms.Extensions[callerExt]), &c)
			if !slices.Equal(c.Principals, tt.principals) {
				t.Errorf("principals = %v, want %v", c.Principals, tt.principals)
			}
		})
	}
}

func TestEndToEnd(t *testing.T) {
	b, _, audit := testBroker(t)
	ca, user, listed := newKey(t), newKey(t), newKey(t)
	b.cfg.cas = [][]byte{ca.PublicKey().Marshal()}
	b.cfg.keys = map[string][]string{ssh.FingerprintSHA256(listed.PublicKey()): {"ci"}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		serve(ctx, ln, newServerConfig(b.cfg, newKey(t), b.audit), b)
		close(done)
	}()

	dial := func(signer ssh.Signer) (*ssh.Client, error) {
		return ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
			User: "anything", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
		})
	}
	certSigner := func(mod func(*ssh.Certificate)) ssh.Signer {
		s, err := ssh.NewCertSigner(newCert(t, ca, user.PublicKey(), mod), user)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// run executes one command on a fresh connection.
	run := func(signer ssh.Signer, cmd, stdin string) (string, string, int) {
		t.Helper()
		client, err := dial(signer)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer client.Close()
		sess, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		sess.Stdout, sess.Stderr, sess.Stdin = &stdout, &stderr, strings.NewReader(stdin)
		code := 0
		if err := sess.Run(cmd); err != nil {
			exit, ok := err.(*ssh.ExitError)
			if !ok {
				t.Fatalf("run %q: %v", cmd, err)
			}
			code = exit.ExitStatus()
		}
		return stdout.String(), strings.TrimSpace(stderr.String()), code
	}

	ops := certSigner(nil)
	if out, _, code := run(ops, "read prod/api/password", ""); code != 0 || out != "s3cret-api" {
		t.Errorf("cert read: %q, exit %d", out, code)
	}
	if out, _, code := run(listed, "list prod", ""); code != 0 || out != "api\n" {
		t.Errorf("whitelist list: %q, exit %d", out, code)
	}
	if _, _, code := run(ops, "write prod/db/password", "rotated\n"); code != 0 {
		t.Errorf("write: exit %d", code)
	}
	if out, _, _ := run(ops, "read prod/db/password", ""); out != "rotated" {
		t.Errorf("read after write: %q", out)
	}
	// Denied and nonexistent are indistinguishable on the wire.
	_, e1, c1 := run(listed, "read prod/db/password", "")
	_, e2, c2 := run(listed, "read prod/nope/password", "")
	if c1 != exitDenied || c1 != c2 || e1 != e2 {
		t.Errorf("denied (%d %q) vs missing (%d %q)", c1, e1, c2, e2)
	}

	// Authentication failures.
	if _, err := dial(newKey(t)); err == nil {
		t.Error("unknown key was accepted")
	}
	if _, err := dial(certSigner(func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"source-address": "10.0.0.0/8"}
	})); err == nil {
		t.Error("cert was accepted from outside its source-address")
	}
	if client, err := dial(certSigner(func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"source-address": "127.0.0.0/8"}
	})); err != nil {
		t.Errorf("cert rejected from inside its source-address: %v", err)
	} else {
		client.Close()
	}

	// Only exec on a session channel is served.
	client, err := dial(ops)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Error("port forwarding was allowed")
	}
	if _, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		t.Error("remote forwarding was allowed")
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 24, 80, nil); err == nil {
		t.Error("pty was allowed")
	}
	if err := sess.Shell(); err == nil {
		t.Error("shell was allowed")
	}
	if err := sess.RequestSubsystem("sftp"); err == nil {
		t.Error("subsystem was allowed")
	}
	sess.Close()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("server did not shut down")
	}

	// Audit: one JSON object per line, identity recorded, no secret values.
	log, _ := io.ReadAll(audit)
	var sawCert, sawAuthDeny bool
	for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		sawCert = sawCert || (rec["cert_key_id"] == "test-cert" && rec["cert_serial"] == float64(42) &&
			rec["fingerprint"] == ssh.FingerprintSHA256(user.PublicKey()) && rec["decision"] == "allow")
		sawAuthDeny = sawAuthDeny || (rec["msg"] == "auth" && rec["decision"] == "deny")
	}
	if !sawCert || !sawAuthDeny {
		t.Errorf("audit log misses cert identity (%v) or failed auth (%v):\n%s", sawCert, sawAuthDeny, log)
	}
	if strings.Contains(string(log), "s3cret") || strings.Contains(string(log), "rotated") {
		t.Errorf("audit log contains a secret:\n%s", log)
	}
}
