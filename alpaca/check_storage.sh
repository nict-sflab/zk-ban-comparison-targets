#!/usr/bin/env bash

ALPACA_DIR="${1:-./alpaca}"
echo "Checking prover storage files in ALPACA: $ALPACA_DIR"
ls -lah "$ALPACA_DIR"/P "$ALPACA_DIR"/IVC_P 
