# NixOS module: build files from secrets read through ssh-secret-broker.
#
#   services.secretBrokerClient = {
#     host = "broker.example.net";
#     hostPublicKey = "ssh-ed25519 AAAA...";
#     vault = "fleet";
#     files.caddy-cloudflare = {
#       path = "/var/lib/caddy-secrets/cloudflare.env";
#       env.CF_API_TOKEN = "caddy-cloudflare/password";   # <item>/<field>
#       units = [ "caddy.service" ];
#     };
#   };
#
# Each file gets a oneshot unit, secret-broker-fetch-<name>, that runs before
# the listed units start and again on a timer. The host authenticates with its
# SSH host key, so the broker must whitelist that key's fingerprint.
#
# A failed fetch never costs a working secret: see fetch.sh. Consumers pull the
# fetch in with Wants=, not Requires=, so they start on the last good copy and
# the failed fetch unit is what reports the problem.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.secretBrokerClient;

  fetch = pkgs.callPackage ./fetch.nix { };

  hostPattern = "[${cfg.host}]:${toString cfg.port}";

  # The fetch units use their own known_hosts rather than the system one, so
  # nothing else on the host can change which key they accept.
  knownHosts = pkgs.writeText "secret-broker-known-hosts" "${hostPattern} ${cfg.hostPublicKey}\n";

  unitName = name: "secret-broker-fetch-${name}";
in
{
  options.services.secretBrokerClient = {
    host = lib.mkOption {
      type = lib.types.str;
      example = "broker.example.net";
      description = "Name the broker is reached at.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 2222;
    };

    hostPublicKey = lib.mkOption {
      type = lib.types.str;
      example = "ssh-ed25519 AAAA...";
      description = ''
        The broker's SSH host key (the public half of its `host_key`). Pinned:
        a client that trusts on first use can be pointed at an impostor.
      '';
    };

    vault = lib.mkOption {
      type = lib.types.str;
      description = "Vault the items are read from.";
    };

    identityFile = lib.mkOption {
      type = lib.types.path;
      default = "/etc/ssh/ssh_host_ed25519_key";
      description = "Private key this host authenticates with.";
    };

    refresh = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "hourly";
      description = ''
        How often to fetch again, as a systemd OnCalendar expression, so a
        rotated value reaches the host without a deploy. null fetches only when
        a consumer starts. Every value costs the broker two to four backend API
        calls per fetch.
      '';
    };

    after = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "tailscaled.service" "docker-secret-broker.service" ];
      description = ''
        Extra units the fetch is ordered after, such as the VPN the broker is
        reached over, or the broker itself when it runs on this host. Ordering
        only; a broker that is not listening yet is retried for about ten
        seconds.
      '';
    };

    files = lib.mkOption {
      default = { };
      description = "Files to build, keyed by a short name.";
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          path = lib.mkOption {
            type = lib.types.path;
            description = ''
              Where to write the file. Use persistent storage, not /run: the
              previous copy is the fallback when a fetch fails.
            '';
          };
          env = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = { };
            example = { CF_API_TOKEN = "caddy-cloudflare/password"; };
            description = "Environment file: variable name to `<item>/<field>`.";
          };
          value = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "grafana/password";
            description = "Instead of `env`: one `<item>/<field>` written as the whole file.";
          };
          owner = lib.mkOption { type = lib.types.str; default = "root"; };
          group = lib.mkOption { type = lib.types.str; default = "root"; };
          mode = lib.mkOption { type = lib.types.str; default = "0400"; };
          units = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            example = [ "caddy.service" ];
            description = ''
              Units that read the file. The fetch runs before each of them
              starts, and they are restarted when the content changes.
            '';
          };
        };
      });
    };
  };

  config = lib.mkIf (cfg.files != { }) {
    assertions = lib.mapAttrsToList (name: f: {
      assertion = (f.env != { }) != (f.value != null);
      message = "services.secretBrokerClient.files.${name}: set exactly one of `env` and `value`.";
    }) cfg.files;

    # For people running `ssh -p 2222 <broker> list <vault>` by hand.
    programs.ssh.knownHosts.secret-broker = {
      extraHostNames = [ hostPattern ];
      publicKey = cfg.hostPublicKey;
    };

    systemd.services = lib.mapAttrs' (name: f: lib.nameValuePair (unitName name) {
      description = "Fetch ${f.path} from the secret broker";

      wantedBy = f.units;
      before = f.units;
      after = [ "network-online.target" ] ++ cfg.after;
      wants = [ "network-online.target" ];

      environment = {
        SECRET_BROKER_HOST = cfg.host;
        SECRET_BROKER_PORT = toString cfg.port;
        SECRET_BROKER_VAULT = cfg.vault;
        SECRET_BROKER_KNOWN_HOSTS = "${knownHosts}";
        SECRET_BROKER_IDENTITY = toString cfg.identityFile;
      };

      # A fetch that fails is tried again by systemd rather than by waiting
      # longer in the script. The script only waits about ten seconds for a
      # broker that is not listening, because the consumers are ordered after
      # this unit and a longer wait would hold up their start whenever the
      # broker is really down. A failed attempt releases them at once, onto the
      # last good copy, and the retries then happen behind their back: five
      # starts, thirty seconds apart, which covers a broker being upgraded or a
      # host still booting. After that the unit stays failed, so an outage shows
      # up in `systemctl --failed`, until the next timer run.
      #
      # The interval has to stay well under the refresh period: while the limit
      # is in force every start is refused, the timer's included.
      startLimitIntervalSec = 300;
      startLimitBurst = 5;

      serviceConfig = {
        Type = "oneshot";
        Restart = "on-failure";
        RestartSec = "30s";
        ExecStart = lib.escapeShellArgs ([
          (lib.getExe fetch)
          f.path f.owner f.group f.mode
          (lib.concatStringsSep " " f.units)
        ] ++ (if f.value != null
              then [ "=${f.value}" ]
              else lib.mapAttrsToList (k: ref: "${k}=${ref}") f.env));
      };
    }) cfg.files;

    systemd.timers = lib.mkIf (cfg.refresh != null) (lib.mapAttrs' (name: _:
      lib.nameValuePair (unitName name) {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = cfg.refresh;
          RandomizedDelaySec = "10m";
        };
      }) cfg.files);
  };
}
