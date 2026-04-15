{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = with pkgs; [ rustup clang cvc4 zsh ];
  shellHook = ''
    ROOT_DIR="$(pwd)"
    CIRC_DIR="$ROOT_DIR/circ-alpaca"

    # `alpaca` (git dependency) expects `<checkout>/circ-alpaca/...` at runtime.
    # Cargo checkouts do not include that subdir here, so link our local one.
    for checkout in "$HOME"/.cargo/git/checkouts/alpaca-*/*; do
      if [ -d "$checkout" ]; then
        ln -sfn "$CIRC_DIR" "$checkout/circ-alpaca"
        # These artifacts are generated in $ROOT_DIR, but some alpaca code reads
        # them via root_abs_path() inside the checkout directory.
        ln -sfn "$ROOT_DIR/IVC_R1CS" "$checkout/IVC_R1CS"
        ln -sfn "$ROOT_DIR/IVC_PRECOMPUTE" "$checkout/IVC_PRECOMPUTE"
      fi
    done
    
    cd circ-alpaca
    cargo build --release --features r1cs,zok,spartan --example zk
    cargo build --release --features r1cs,zok,spartan --example circ
    cd ..
  '';
  }
