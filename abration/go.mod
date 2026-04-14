module github.com/akakou/zk-ban-comparisons/abration

go 1.26.1

replace github.com/akakou/zk-ban => ../../zk-ban

replace github.com/akakou/gnark-precomputes => ../../gnark-precomputes

require (
	github.com/akakou/zk-ban v0.0.0-00010101000000-000000000000
	github.com/consensys/gnark v0.14.0
)

require (
	github.com/akakou/gnark-precomputes v0.0.0-00010101000000-000000000000 // indirect
	github.com/bits-and-blooms/bitset v1.24.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/gnark-crypto v0.19.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/google/pprof v0.0.0-20250820193118-f64d9cf942d6 // indirect
	github.com/ingonyama-zk/icicle-gnark/v3 v3.2.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)
