package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

const maxValue = 64 << 10 // largest secret accepted by write

// Exit statuses reported to the client.
const (
	exitOK     = 0
	exitDenied = 1 // denied or not found: deliberately the same
	exitError  = 2
	exitUsage  = 64
)

const usage = `usage: list <vault> | read <vault>/<item>/<field> | write <vault>/<item>/<field> (value on stdin)`

// errDenied covers both "not permitted" and "does not exist"; the client must
// not be able to tell them apart. Wrap it to add detail for the audit log.
var errDenied = errors.New("not found or not permitted")

type usageError string

func (e usageError) Error() string { return string(e) }

type Field struct{ ID, Title, Value string }

type Item struct {
	ID, Title string
	Tags      []string
	Fields    []Field // only populated by Get
}

// Store is the secret backend. Vaults are addressed by name, items by ID.
type Store interface {
	List(ctx context.Context, vault string) ([]Item, error)
	Get(ctx context.Context, vault, id string) (Item, error)
	// SetField sets or adds one field and must leave everything else,
	// in particular the tags, untouched.
	SetField(ctx context.Context, vault, id, field, value string) error
	Create(ctx context.Context, vault, title, field, value string, tags []string) error
}

type Broker struct {
	cfg   *Config
	store Store
	audit *slog.Logger
}

type request struct{ verb, vault, item, field string }

func parse(cmd string) (request, error) {
	verb, arg, _ := strings.Cut(strings.TrimSpace(cmd), " ")
	parts := strings.Split(strings.TrimSpace(arg), "/")
	if !nonEmpty(parts) {
		return request{}, usageError(usage)
	}
	switch {
	case verb == "list" && len(parts) == 1:
		return request{verb: verb, vault: parts[0]}, nil
	case (verb == "read" || verb == "write") && len(parts) == 3:
		return request{verb, parts[0], parts[1], parts[2]}, nil
	}
	return request{}, usageError(usage)
}

// Handle runs one command for an authenticated caller, writes the audit
// record, and returns what to send back: stdout, exit status, stderr message.
func (b *Broker) Handle(ctx context.Context, c Caller, remote, cmd string, stdin io.Reader) (string, int, string) {
	start := time.Now()
	req, err := parse(cmd)
	out, rule := "", -1
	if err == nil {
		out, rule, err = b.run(ctx, c, req, stdin)
	}

	code, msg, decision := exitOK, "", "allow"
	var ue usageError
	switch {
	case err == nil:
	case errors.Is(err, errDenied):
		code, msg, decision = exitDenied, errDenied.Error(), "deny"
	case errors.As(err, &ue):
		code, msg, decision = exitUsage, err.Error(), "error"
	default:
		code, msg, decision = exitError, "internal error", "error"
	}
	attrs := []slog.Attr{
		slog.String("remote", remote),
		slog.String("fingerprint", c.Fingerprint),
		slog.String("cert_key_id", c.KeyID),
		slog.Uint64("cert_serial", c.Serial),
		slog.Any("principals", c.Principals),
		slog.String("verb", req.verb),
		slog.String("vault", req.vault),
		slog.String("item", req.item),
		slog.String("field", req.field),
		slog.String("decision", decision),
		slog.Int("rule", rule),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
	}
	if err != nil {
		attrs = append(attrs, slog.String("reason", err.Error()))
	}
	b.audit.LogAttrs(ctx, slog.LevelInfo, "access", attrs...)
	return out, code, msg
}

// run returns the output and the index of the rule that allowed the request.
func (b *Broker) run(ctx context.Context, c Caller, req request, stdin io.Reader) (string, int, error) {
	rules := b.cfg.rulesFor(c.Principals, req.verb, req.vault)
	if len(rules) == 0 {
		return "", -1, fmt.Errorf("%w: no rule grants %s on this vault", errDenied, req.verb)
	}
	items, err := b.store.List(ctx, req.vault)
	if err != nil {
		return "", -1, err
	}

	if req.verb == "list" {
		var out strings.Builder
		for _, it := range items {
			if b.cfg.covering(rules, it.Tags) >= 0 {
				out.WriteString(it.Title + "\n")
			}
		}
		return out.String(), rules[0], nil
	}

	// Find the item by title among those in the caller's scope.
	var found []Item
	exists := false
	for _, it := range items {
		if it.Title == req.item {
			exists = true
			if b.cfg.covering(rules, it.Tags) >= 0 {
				found = append(found, it)
			}
		}
	}
	if len(found) > 1 {
		return "", -1, usageError("several items in your scope have this title")
	}

	if req.verb == "write" {
		value, err := readValue(stdin)
		if err != nil {
			return "", -1, err
		}
		switch {
		case len(found) == 1:
			// Existing item: tags stay exactly as they are.
			_, rule, err := b.recheck(ctx, rules, req.vault, found[0].ID)
			if err != nil {
				return "", -1, err
			}
			return "", rule, b.store.SetField(ctx, req.vault, found[0].ID, req.field, value)
		case exists:
			// The title is taken by an item outside the caller's scope.
			return "", -1, fmt.Errorf("%w: item is out of scope", errDenied)
		default:
			// New item: it gets the tags of the rule that allowed the write,
			// so it lands inside the caller's scope and nowhere else.
			rule := rules[0]
			return "", rule, b.store.Create(ctx, req.vault, req.item, req.field, value, b.cfg.Rules[rule].Tags)
		}
	}

	// read
	if len(found) == 0 {
		return "", -1, fmt.Errorf("%w: no such item in scope", errDenied)
	}
	item, rule, err := b.recheck(ctx, rules, req.vault, found[0].ID)
	if err != nil {
		return "", -1, err
	}
	for _, match := range []func(Field) bool{
		func(f Field) bool { return f.ID == req.field },
		func(f Field) bool { return f.Title == req.field },
	} {
		for _, f := range item.Fields {
			if match(f) {
				return f.Value, rule, nil
			}
		}
	}
	return "", -1, fmt.Errorf("%w: no such field", errDenied)
}

// recheck fetches the item and authorizes against its current tags rather than
// the listing, so a tag change between the two calls cannot widen access.
func (b *Broker) recheck(ctx context.Context, rules []int, vault, id string) (Item, int, error) {
	item, err := b.store.Get(ctx, vault, id)
	if err != nil {
		return Item{}, -1, err
	}
	rule := b.cfg.covering(rules, item.Tags)
	if rule < 0 {
		return Item{}, -1, fmt.Errorf("%w: item left scope", errDenied)
	}
	return item, rule, nil
}

// readValue reads the secret from stdin, dropping one trailing newline so that
// `echo value | ssh broker write ...` stores "value".
func readValue(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxValue+1))
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(data), "\n")
	if value == "" || len(data) > maxValue {
		return "", usageError(fmt.Sprintf("value on stdin must be 1..%d bytes", maxValue))
	}
	return value, nil
}
