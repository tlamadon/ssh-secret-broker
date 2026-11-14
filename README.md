# ssh-secret-broker

A minimal, stateless SSH server that brokers access to 1Password. Clients
authenticate with an SSH certificate or a whitelisted key; a config file maps
their principals to tagged items in a vault.

```sh
ssh -p 2222 broker list prod                              # item titles, one per line
ssh -p 2222 broker read prod/api/password                 # raw value on stdout
echo -n "$NEW" | ssh -p 2222 broker write prod/api/password   # value on stdin
```

Exit status: `0` ok, `1` not found or not permitted (deliberately the same),
`2` backend error, `64` usage error.

## How access is decided

1. **Who.** A user certificate signed by one of `trusted_cas` yields the
   certificate's principals. A plain key listed in `whitelist` yields the
   principals configured there. Anything else is rejected. The SSH username is
   ignored.
2. **What.** A request is allowed if some rule matches one of the caller's
   principals, the vault, the verb (`list`, `read`, `write`) and at least one
   tag of the item. No match means denied. Items without tags are unreachable.
3. **Writes cannot change scope.** Updating a field leaves the item's tags
   untouched. A new item gets exactly the tags of the rule that allowed the
   write. A title already used by an item outside the caller's scope is denied.

See [config.example.yaml](config.example.yaml). The config is read once at
startup; unknown keys and invalid rules stop the broker from starting. Restart
to apply changes.

## Running

```sh
docker build -t ssh-secret-broker .
ssh-keygen -t ed25519 -N "" -f host_key

docker run -d --read-only --cap-drop ALL -p 2222:2222 \
  -e OP_SERVICE_ACCOUNT_TOKEN \
  -v ./config.yaml:/etc/ssh-secret-broker/config.yaml:ro \
  -v ./host_key:/run/secrets/host_key:ro \
  ssh-secret-broker
```

The container runs as uid 65532, so the host key must be readable by that user.
The token can also come from a file via `OP_SERVICE_ACCOUNT_TOKEN_FILE`.

The 1Password service account is the outer bound: give it access only to the
vaults named in the rules, read-only unless a rule grants `write`. The broker
refuses to start if a vault in the rules is not visible to the account.

## Issuing a certificate

```sh
ssh-keygen -t ed25519 -f ca                       # once; ca.pub goes into trusted_cas
ssh-keygen -s ca -I alice@laptop -n ops,ci-deploy -V +8h -z 1 \
  -O source-address=10.0.0.0/8 ~/.ssh/id_ed25519.pub
```

`-n` sets the principals, `-I` and `-z` (key ID and serial) appear in the audit
log, `-O source-address` is optional and enforced. Certificates carrying any
other critical option, such as `force-command`, are rejected.

## Audit log

One JSON line per request on stdout; operational messages go to stderr.

```json
{"time":"2026-11-14T17:38:52Z","level":"INFO","msg":"access","remote":"10.1.2.3:46900",
 "fingerprint":"SHA256:2UoF...","cert_key_id":"alice@laptop","cert_serial":9,
 "principals":["ops"],"verb":"read","vault":"prod","item":"api","field":"password",
 "decision":"allow","rule":0,"duration_ms":212}
```

`decision` is `allow`, `deny` or `error`; `rule` is the index of the matching
rule; denials and errors carry a `reason`. Rejected keys are logged with
`"msg":"auth"`. Secret values and the token are never logged.

## Details and limits

- Items are addressed by title and fields by ID or label. `/` separates the
  path, so titles and field names containing `/` are not addressable.
- If several items in the caller's scope share a title, the request fails
  rather than picking one.
- `write` drops one trailing newline from stdin and accepts up to 64 KiB. New
  items are created as Login items; fields other than `username` and `password`
  go into a section.
- Exec only: shell, PTY, subsystems and all forwarding are refused. One command
  per connection, 10 s handshake timeout, 30 s per connection.
- Not implemented: delete, certificate revocation lists (use short validity),
  config hot reload, rate limiting. 1Password service accounts are rate limited
  and every request costs two to four API calls.

## Threat model

- The broker holds a token that can read everything the service account can.
  Compromise of the broker host is compromise of those vaults: scope the
  account narrowly.
- The CA key mints identities. Whoever holds it can claim any principal.
- Anyone who can edit tags in 1Password directly can move items in and out of
  scopes; the broker only guarantees that its own clients cannot.
- Clients must verify the broker's host key (`known_hosts`), otherwise a
  man-in-the-middle can receive the values they write.
- The audit log names vaults, items and fields. Treat it as sensitive metadata.

## Development

```sh
go test -race ./...
```

The tests use an in-memory store, including an end-to-end test over a real SSH
connection with a generated CA.
