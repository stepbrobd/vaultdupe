{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  packages = [
    pkgs.bitwarden-cli
    (pkgs.python3.withPackages (ps: [ ps.pytest ps.tldextract ]))
  ];
}
