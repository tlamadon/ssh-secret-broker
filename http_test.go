package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/voussh/voussh/httpcred"
)

const (
	testIssuer   = "https://auth.test"
	testAudience = "secret-broker"
)

// httpFixture is a broker behind a real HTTP listener, and a stand-in for
// voussh that can mint tokens for it.
type httpFixture struct {
	t      *testing.T
	url    string
	issuer *httpcred.Issuer
	key    ed25519.PrivateKey // the client's proof key
	store  fakeStore
	audit  *bytes.Buffer
}

const httpRules = `
host_key: /dev/null
http: {listen: ":0", origin: "http://x", issuer: "i", audience: "a", jwks: "f"}
rules:
  - {principals: ["role:reader"], vault: prod, tags: [deploy], access: [list, read]}
  - {principals: ["role:writer"], vault: prod, tags: [db, deploy], access: [list, read, write]}
  - {principals: ["bob@example.com"], vault: staging, tags: [app], access: [read]}
  - {principals: ["service:ci"], vault: prod, tags: [db], access: [read]}
`

func newHTTPFixture(t *testing.T) *httpFixture {
	t.Helper()
	b, store, audit := testBroker(t)
	cfg, err := parseConfig([]byte(httpRules))
	if err != nil {
		t.Fatal(err)
	}
	b.cfg = cfg

	_, signKey, _ := ed25519.GenerateKey(rand.Reader)
	issuer, err := httpcred.NewIssuer(testIssuer, signKey, "")
	if err != nil {
		t.Fatal(err)
	}
	jwks := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwks, issuer.JWKS(), 0o600); err != nil {
		t.Fatal(err)
	}

	// The verifier needs the server's origin, which is only known once the
	// server listens.
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	v, err := newVerifier(&HTTP{Issuer: testIssuer, Audience: testAudience, Origin: srv.URL, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	handler = newHTTPHandler(v, b)

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	return &httpFixture{t: t, url: srv.URL, issuer: issuer, key: key, store: store, audit: audit}
}

func (f *httpFixture) token(mod func(*httpcred.TokenRequest)) string {
	f.t.Helper()
	req := httpcred.TokenRequest{
		Subject: "alice@example.com", SubjectType: "user", Audience: testAudience, Role: "reader",
		Key: f.key.Public().(ed25519.PublicKey), Validity: 5 * time.Minute,
	}
	if mod != nil {
		mod(&req)
	}
	tok, _, err := f.issuer.Issue(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func (f *httpFixture) proof(method, path, token string) string {
	f.t.Helper()
	p, err := httpcred.NewProof(f.key, httpcred.ProofParams{Method: method, URL: f.url + path, AccessToken: token})
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

// send makes one request with the given headers (nil values are omitted).
func (f *httpFixture) send(method, path, body, authorization, proof string) (int, string) {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.url+path, strings.NewReader(body))
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// do makes a correctly authenticated request with the given token.
func (f *httpFixture) do(token, method, path, body string) (int, string) {
	f.t.Helper()
	return f.send(method, path, body, "DPoP "+token, f.proof(method, path, token))
}

func TestHTTPAuthorization(t *testing.T) {
	f := newHTTPFixture(t)
	as := func(sub, role string) string {
		return f.token(func(r *httpcred.TokenRequest) {
			r.Subject, r.Role = sub, role
			if strings.HasPrefix(sub, "service:") {
				r.SubjectType = "service"
			}
		})
	}
	reader, writer := as("alice@example.com", "reader"), as("alice@example.com", "writer")
	tests := []struct {
		name, token, method, path, body string
		status                          int
		out                             string
	}{
		{"list by role", reader, "GET", "/v1/prod", "", 200, "api\n"},
		{"read by role", reader, "GET", "/v1/prod/api/password", "", 200, "s3cret-api"},
		{"tag out of scope", reader, "GET", "/v1/prod/db/password", "", 404, ""},
		{"missing item", reader, "GET", "/v1/prod/nope/password", "", 404, ""},
		{"role without write", reader, "PUT", "/v1/prod/api/password", "x", 404, ""},
		{"other role, wider scope", writer, "GET", "/v1/prod/db/password", "", 200, "s3cret-db"},
		{"write by role", writer, "PUT", "/v1/prod/db/password", "rotated\n", 204, ""},
		{"read back", writer, "GET", "/v1/prod/db/password", "", 200, "rotated"},
		{"empty write", writer, "PUT", "/v1/prod/db/password", "", 400, ""},
		{"oversized write", writer, "PUT", "/v1/prod/db/password", strings.Repeat("x", maxValue+1), 400, ""},
		{"rule on the subject", as("bob@example.com", "none"), "GET", "/v1/staging/app/password", "", 200, "s3cret-stg"},
		{"subject without a rule", as("eve@example.com", "none"), "GET", "/v1/staging/app/password", "", 404, ""},
		{"service subject", as("service:ci", "none"), "GET", "/v1/prod/db/password", "", 200, "rotated"},
		// A user cannot become a service or a role by choosing a name.
		{"role named like a subject", as("eve@example.com", "bob@example.com"), "GET", "/v1/staging/app/password", "", 404, ""},
		{"escaped item name", reader, "GET", "/v1/prod/a%2Fb/password", "", 404, ""},
		{"unknown route", reader, "GET", "/v2/prod", "", 404, ""},
		{"unsupported method", writer, "DELETE", "/v1/prod/api/password", "", 405, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, out := f.do(tt.token, tt.method, tt.path, tt.body)
			if status != tt.status || (status == 200 && out != tt.out) {
				t.Errorf("got %d %q, want %d %q", status, out, tt.status, tt.out)
			}
		})
	}

	// Denied and missing are the same answer.
	s1, b1 := f.do(reader, "GET", "/v1/prod/db/password", "")
	s2, b2 := f.do(reader, "GET", "/v1/prod/nope/password", "")
	if s1 != s2 || b1 != b2 {
		t.Errorf("denied (%d %q) vs missing (%d %q)", s1, b1, s2, b2)
	}

	var sawIdentity bool
	for _, line := range strings.Split(strings.TrimSpace(f.audit.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		sawIdentity = sawIdentity || (rec["auth"] == "jwt" && rec["subject"] == "alice@example.com" &&
			rec["token_id"] != "" && rec["decision"] == "allow" &&
			rec["fingerprint"] == httpcred.Thumbprint(f.key.Public().(ed25519.PublicKey)))
	}
	if !sawIdentity {
		t.Errorf("audit log does not identify the token holder:\n%s", f.audit)
	}
	for _, secret := range []string{"s3cret", "rotated", reader, writer} {
		if strings.Contains(f.audit.String(), secret) {
			t.Errorf("audit log contains a secret or a token (%.12s...)", secret)
		}
	}
}

func TestHTTPAuthentication(t *testing.T) {
	f := newHTTPFixture(t)
	const path = "/v1/prod/api/password"
	good := f.token(nil)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	_, otherSigner, _ := ed25519.GenerateKey(rand.Reader)
	impostor, _ := httpcred.NewIssuer(testIssuer, otherSigner, "")
	forged, _, _ := impostor.Issue(httpcred.TokenRequest{Subject: "alice@example.com", SubjectType: "user",
		Audience: testAudience, Role: "reader", Key: f.key.Public().(ed25519.PublicKey), Validity: time.Minute})
	proofWith := func(key ed25519.PrivateKey, method, url, token string) string {
		p, err := httpcred.NewProof(key, httpcred.ProofParams{Method: method, URL: url, AccessToken: token})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	expired := f.token(func(r *httpcred.TokenRequest) { r.Now = time.Now().Add(-time.Hour) })
	wrongAud := f.token(func(r *httpcred.TokenRequest) { r.Audience = "something-else" })

	tests := []struct{ name, authorization, proof string }{
		{"no credentials", "", ""},
		{"token without proof", "DPoP " + good, ""},
		{"bearer scheme", "Bearer " + good, f.proof("GET", path, good)},
		{"garbage token", "DPoP not.a.token", f.proof("GET", path, good)},
		{"token from another issuer key", "DPoP " + forged, f.proof("GET", path, forged)},
		{"expired token", "DPoP " + expired, f.proof("GET", path, expired)},
		{"token for another audience", "DPoP " + wrongAud, f.proof("GET", path, wrongAud)},
		{"proof from another key", "DPoP " + good, proofWith(otherKey, "GET", f.url+path, good)},
		{"proof for another method", "DPoP " + good, f.proof("PUT", path, good)},
		{"proof for another path", "DPoP " + good, f.proof("GET", "/v1/prod/db/password", good)},
		{"proof for another host", "DPoP " + good, proofWith(f.key, "GET", "https://elsewhere.test"+path, good)},
		{"proof for another token", "DPoP " + good, f.proof("GET", path, f.token(nil))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := f.send("GET", path, "", tt.authorization, tt.proof)
			if status != http.StatusUnauthorized || strings.TrimSpace(body) != "unauthorized" {
				t.Errorf("got %d %q, want 401 with no detail", status, body)
			}
		})
	}

	// A proof is good for one request only.
	proof := f.proof("GET", path, good)
	if status, _ := f.send("GET", path, "", "DPoP "+good, proof); status != 200 {
		t.Fatalf("first use of a proof: %d", status)
	}
	if status, _ := f.send("GET", path, "", "DPoP "+good, proof); status != http.StatusUnauthorized {
		t.Errorf("replayed proof: %d, want 401", status)
	}

	if n := strings.Count(f.audit.String(), `"msg":"auth"`); n != len(tests)+1 {
		t.Errorf("%d rejected requests audited, want %d", n, len(tests)+1)
	}
	if strings.Contains(f.audit.String(), good) || strings.Contains(f.audit.String(), "s3cret") {
		t.Error("audit log contains a token or a secret")
	}
}

func TestHTTPConfigValidation(t *testing.T) {
	const base = "host_key: k\nrules:\n  - {principals: [a], vault: v, tags: [t], access: [read]}\n"
	ok := `http: {listen: ":8443", origin: "https://b.example", issuer: "https://a.example", audience: "secret-broker", jwks: /j`
	if _, err := parseConfig([]byte(base + ok + "}\n")); err != nil {
		t.Errorf("an http block alone should be enough to start: %v", err)
	}
	if _, err := parseConfig([]byte(base + ok + ", tls_cert: /c, tls_key: /k}\n")); err != nil {
		t.Errorf("TLS pair rejected: %v", err)
	}
	bad := map[string]string{
		"missing audience":      strings.Replace(ok, `audience: "secret-broker", `, "", 1) + "}",
		"missing jwks":          strings.Replace(ok, ", jwks: /j", "", 1) + "}",
		"origin with a path":    strings.Replace(ok, "https://b.example", "https://b.example/v1", 1) + "}",
		"origin without scheme": strings.Replace(ok, "https://b.example", "b.example", 1) + "}",
		"cert without key":      ok + ", tls_cert: /c}",
		"TLS with http origin":  strings.Replace(ok, "https://b.example", "http://b.example", 1) + ", tls_cert: /c, tls_key: /k}",
		"unknown key":           ok + ", extra: 1}",
	}
	for name, block := range bad {
		if _, err := parseConfig([]byte(base + block + "\n")); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}
