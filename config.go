package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var verbs = []string{"list", "read", "write"}

// Rule grants its principals the listed verbs on items of one vault that carry
// at least one of its tags.
type Rule struct {
	Principals []string `yaml:"principals"`
	Vault      string   `yaml:"vault"`
	Tags       []string `yaml:"tags"`
	Access     []string `yaml:"access"`
}

type Config struct {
	Listen     string   `yaml:"listen"`
	HostKey    string   `yaml:"host_key"`
	TrustedCAs []string `yaml:"trusted_cas"`
	Whitelist  []struct {
		Fingerprint string   `yaml:"fingerprint"`
		Principals  []string `yaml:"principals"`
	} `yaml:"whitelist"`
	Rules []Rule `yaml:"rules"`

	cas  [][]byte            // wire encoding of each trusted CA key
	keys map[string][]string // SHA256 fingerprint -> principals
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(data)
}

func parseConfig(data []byte) (*Config, error) {
	c := &Config{Listen: ":2222"}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, err
	}
	if c.HostKey == "" {
		return nil, errors.New("host_key is required")
	}
	if len(c.TrustedCAs) == 0 && len(c.Whitelist) == 0 {
		return nil, errors.New("need at least one of trusted_cas or whitelist")
	}
	for i, line := range c.TrustedCAs {
		ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("trusted_cas[%d]: %w", i, err)
		}
		c.cas = append(c.cas, ca.Marshal())
	}
	c.keys = map[string][]string{}
	for i, w := range c.Whitelist {
		if !strings.HasPrefix(w.Fingerprint, "SHA256:") || !nonEmpty(w.Principals) {
			return nil, fmt.Errorf("whitelist[%d]: need a SHA256: fingerprint and principals", i)
		}
		if _, dup := c.keys[w.Fingerprint]; dup {
			return nil, fmt.Errorf("whitelist[%d]: duplicate fingerprint", i)
		}
		c.keys[w.Fingerprint] = w.Principals
	}
	if len(c.Rules) == 0 {
		return nil, errors.New("no rules: nothing would be accessible")
	}
	for i, r := range c.Rules {
		if !nonEmpty(r.Principals) || r.Vault == "" || !nonEmpty(r.Tags) || len(r.Access) == 0 {
			return nil, fmt.Errorf("rules[%d]: principals, vault, tags and access are all required", i)
		}
		for _, a := range r.Access {
			if !slices.Contains(verbs, a) {
				return nil, fmt.Errorf("rules[%d]: unknown access %q (want list, read or write)", i, a)
			}
		}
	}
	return c, nil
}

func nonEmpty(l []string) bool {
	return len(l) > 0 && !slices.Contains(l, "")
}

func (c *Config) vaults() []string {
	var out []string
	for _, r := range c.Rules {
		if !slices.Contains(out, r.Vault) {
			out = append(out, r.Vault)
		}
	}
	return out
}

// rulesFor returns the indexes of the rules that grant verb on vault to any of
// the principals, ignoring tags.
func (c *Config) rulesFor(principals []string, verb, vault string) []int {
	var out []int
	for i, r := range c.Rules {
		if r.Vault == vault && slices.Contains(r.Access, verb) &&
			slices.ContainsFunc(principals, func(p string) bool { return slices.Contains(r.Principals, p) }) {
			out = append(out, i)
		}
	}
	return out
}

// covering returns the first of the given rules whose tags intersect the
// item's tags, or -1.
func (c *Config) covering(rules []int, tags []string) int {
	for _, i := range rules {
		if slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(c.Rules[i].Tags, t) }) {
			return i
		}
	}
	return -1
}

// Caller is an authenticated client. It travels from the SSH handshake to the
// session handler JSON-encoded in ssh.Permissions.
type Caller struct {
	Principals  []string `json:"principals"`
	Fingerprint string   `json:"fingerprint"`
	KeyID       string   `json:"key_id,omitempty"`
	Serial      uint64   `json:"serial,omitempty"`
}

const callerExt = "caller"

// authenticate is the SSH public key callback. The SSH username is ignored.
// The ssh package verifies possession of the private key and enforces the
// source-address critical option returned in the permissions.
func (c *Config) authenticate(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	perms := &ssh.Permissions{}
	caller := Caller{Fingerprint: ssh.FingerprintSHA256(key)}
	if cert, ok := key.(*ssh.Certificate); ok {
		caller.Fingerprint = ssh.FingerprintSHA256(cert.Key)
		if cert.CertType != ssh.UserCert {
			return nil, errors.New("not a user certificate")
		}
		ca := cert.SignatureKey.Marshal()
		if !slices.ContainsFunc(c.cas, func(t []byte) bool { return bytes.Equal(t, ca) }) {
			return nil, errors.New("certificate signed by untrusted CA")
		}
		if !nonEmpty(cert.ValidPrincipals) {
			return nil, errors.New("certificate has no principals")
		}
		// CheckCert verifies the signature, the validity window and that no
		// unsupported critical option is present.
		checker := ssh.CertChecker{SupportedCriticalOptions: []string{"source-address"}}
		if err := checker.CheckCert(cert.ValidPrincipals[0], cert); err != nil {
			return nil, err
		}
		caller.Principals, caller.KeyID, caller.Serial = cert.ValidPrincipals, cert.KeyId, cert.Serial
		perms.CriticalOptions = cert.CriticalOptions
	} else if p, ok := c.keys[caller.Fingerprint]; ok {
		caller.Principals = p
	} else {
		return nil, errors.New("key not in whitelist")
	}
	js, _ := json.Marshal(caller)
	perms.Extensions = map[string]string{callerExt: string(js)}
	return perms, nil
}
