{ pkgs ? import <nixpkgs> {} }:

let
  fs = pkgs.lib.fileset;
in
pkgs.python3Packages.buildPythonApplication {
  pname = "vaultdupe";
  version = "0.1.0";
  pyproject = true;

  src = fs.toSource {
    root = ./.;
    fileset = fs.unions [
      ./pyproject.toml
      ./readme.md
      ./vaultdupe
      ./tests
    ];
  };

  build-system = [ pkgs.python3Packages.hatchling ];
  dependencies = [ pkgs.python3Packages.tldextract ];

  makeWrapperArgs = [
    "--prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.bitwarden-cli ]}"
  ];

  nativeCheckInputs = [ pkgs.python3Packages.pytestCheckHook ];

  disabledTestPaths = [ "tests/test_serve.py" ];
}
