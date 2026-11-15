{ writeShellApplication, openssh, coreutils, diffutils, systemd }:

writeShellApplication {
  name = "secret-broker-fetch";
  runtimeInputs = [ openssh coreutils diffutils systemd ];
  text = builtins.readFile ./fetch.sh;
}
