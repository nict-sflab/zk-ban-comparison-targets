{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = with pkgs; [ rustup clang gcc cvc4 zsh ];
  shellHook = ''
    cd alpaca/
    git apply ../alpaca.patch
    cd circ-alpaca
    git apply ../../circ.patch
    cargo build --release --features r1cs,zok,spartan --example zk
    cargo build --release --features r1cs,zok,spartan --example circ
    cd ../
  '';
  }
