#!/bin/bash

RUSTFLAGS="-C target-feature=+bmi2,+adx" cargo bench -- --sample-size 10