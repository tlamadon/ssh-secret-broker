{
  description = "ssh-secret-broker: the NixOS client module and its fetch script";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      nixosModules.client = ./nix/client.nix;
      nixosModules.default = self.nixosModules.client;

      packages = forAllSystems (pkgs: {
        secret-broker-fetch = pkgs.callPackage ./nix/fetch.nix { };
      });

      checks = forAllSystems (pkgs: {
        # Building it runs shellcheck over fetch.sh.
        fetch = self.packages.${pkgs.stdenv.hostPlatform.system}.secret-broker-fetch;

        # The script's behaviour against a stubbed broker, the failure paths
        # above all.
        fetch-behaviour = pkgs.runCommand "secret-broker-fetch-test"
          { nativeBuildInputs = [ pkgs.bash pkgs.coreutils pkgs.diffutils pkgs.findutils pkgs.gnugrep pkgs.gnused ]; }
          ''
            export TMPDIR=$PWD
            bash ${./nix/fetch-test.sh} ${./nix/fetch.sh}
            touch $out
          '';

        # The module evaluates and produces the units.
        module =
          let
            sys = nixpkgs.lib.nixosSystem {
              inherit (pkgs.stdenv.hostPlatform) system;
              modules = [
                self.nixosModules.client
                {
                  services.secretBrokerClient = {
                    host = "broker.example.net";
                    hostPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO9ecACXQh05BOhEZ+xwjexmFYg1GZhl/yKqnEAH5GIt"; # throwaway
                    vault = "fleet";
                    files.env-file = {
                      path = "/var/lib/example/secrets.env";
                      env.TOKEN = "example/password";
                      units = [ "example.service" ];
                    };
                    files.bare = {
                      path = "/var/lib/example/password";
                      value = "example/password";
                    };
                    files.odd-names = {
                      path = "/var/lib/example/100%.env";
                      env.TOKEN = "pa$$word %n/pass word";
                    };
                  };
                  fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
                  boot.loader.grub.enable = false;
                  system.stateVersion = nixpkgs.lib.trivial.release;
                }
              ];
            };
            units = sys.config.systemd.units;
          in
          pkgs.runCommand "secret-broker-client-units" { } ''
            unit=${units."secret-broker-fetch-env-file.service".unit}/secret-broker-fetch-env-file.service
            timer=${units."secret-broker-fetch-env-file.timer".unit}/secret-broker-fetch-env-file.timer
            bare=${units."secret-broker-fetch-bare.service".unit}/secret-broker-fetch-bare.service
            odd=${units."secret-broker-fetch-odd-names.service".unit}/secret-broker-fetch-odd-names.service
            want() { grep -qxF -- "$2" "$1" || { echo "$1: missing line: $2"; cat "$1"; exit 1; }; }
            want "$unit" "Type=oneshot"
            want "$unit" "Before=example.service"
            want "$unit" "Restart=on-failure"
            want "$unit" "RestartSec=30s"
            want "$unit" "RestartPreventExitStatus=78"
            want "$unit" "StartLimitBurst=5"
            want "$unit" "StartLimitIntervalSec=300"
            want "$timer" "OnCalendar=hourly"
            want "$bare" "Restart=on-failure"
            grep -qF '"=example/password"' "$bare" || { echo "bare unit does not pass a bare spec"; cat "$bare"; exit 1; }

            # % and $ reach the script literally: systemd must not expand them.
            exec_start=$(grep '^ExecStart=' "$odd")
            echo "$exec_start"
            [[ $exec_start == *'"/var/lib/example/100%%.env"'* ]]
            [[ $exec_start == *'"TOKEN=pa$$$$word %%n/pass word"'* ]]
            touch $out
          '';
      });
    };
}
