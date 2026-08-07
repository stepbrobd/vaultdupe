{ pkgs ? import <nixpkgs> {} }:

let
  # checks are skipped in the dev shell, run pytest directly instead
  vaultdupe = (import ./default.nix { inherit pkgs; }).overridePythonAttrs (_: {
    doCheck = false;
  });
in
pkgs.mkShell {
  packages = [
    pkgs.bitwarden-cli
    vaultdupe
    (pkgs.python3.withPackages (ps: [ ps.pytest ps.tldextract ]))
  ];
}
