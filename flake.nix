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
        fetch = self.packages.${pkgs.system}.secret-broker-fetch;

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
              inherit (pkgs) system;
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
                  };
                  fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
                  boot.loader.grub.enable = false;
                  system.stateVersion = nixpkgs.lib.trivial.release;
                }
              ];
            };
            units = sys.config.systemd.units;
          in
          pkgs.linkFarm "secret-broker-client-units" [
            { name = "env-file.service"; path = units."secret-broker-fetch-env-file.service".unit; }
            { name = "env-file.timer"; path = units."secret-broker-fetch-env-file.timer".unit; }
            { name = "bare.service"; path = units."secret-broker-fetch-bare.service".unit; }
          ];
      });
    };
}
