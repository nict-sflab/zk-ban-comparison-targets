{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = with pkgs; [ rustc cargo gcc cvc4 zsh ];
  NIX_ENFORCE_PURITY = "0";
  shellHook = ''
    git clone https://github.com/jiwonkimpark/alpaca
    git clone https://github.com/jiwonkimpark/circ-alpaca alpaca/circ-alpaca
    cd alpaca/
    git apply ../alpaca.patch
    cd circ-alpaca
    git apply ../../circ.patch
    cargo build --release --features r1cs,zok,spartan --example zk
    cargo build --release --features r1cs,zok,spartan --example circ
    cd ../
  '';
  }
