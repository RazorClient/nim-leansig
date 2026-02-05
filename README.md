# nim-leansig
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Nim](https://img.shields.io/badge/Nim-2.2.0+-yellow.svg)](https://nim-lang.org/)

Nim bindings for the **leanSig** post-quantum signature library and its XMSS multisig prover/aggregator. The Rust code compiles to a C ABI (`leansig_ffi`) that the Nim layer wraps.

## Overview
leanSig delivers hash-based, quantum-resistant signatures tuned for Ethereum validators. The Nim layer keeps the API ergonomic while preserving the Rust safety guarantees.

**Key features**
- Quantum-resistant (hash-based XMSS)
- Validator-focused performance and epochs
- Stateful design prevents key reuse
- Backed by peer-reviewed research and production-grade Rust

## Architecture
```
┌────────────────────────────┐
│ Nim API (src/)             │
└──────────────┬─────────────┘
               ▼
┌────────────────────────────┐
│ FFI shims (leansig_bindings│
│ + C headers)               │
└──────────────┬─────────────┘
               ▼
┌────────────────────────────┐
│ Rust C ABI (rust/ffi,      │
│ leansig_ffi)               │
└──────────────┬─────────────┘
               ▼
┌────────────────────────────┐
│ Core crates                │
│ • rust/leansig             │
│ • rust/Multisig/xmss       │
│ • rust/Multisig/rec_aggr   │
└────────────────────────────┘
```
- **Layers**: Nim API (`src/`) → FFI shims (`leansig_bindings.nim`) → Rust C ABI (`rust/ffi`, `leansig_ffi`) → core Rust crates.
- **Core crates**: `rust/leansig` (XMSS keys/sign/verify), `rust/Multisig/crates/xmss` (single-signer prover), `rust/Multisig/crates/rec_aggregation` (recursive aggregation + proof plumbing).
- **Proof stack**: Plonky3 forks (`whir-p3`, `p3-koala-bear`) supply Poseidon2, KoalaBear field ops, and circuit gadgets consumed by `rec_aggregation`.
- **Artifacts**: `make ffi` emits `libleansig_ffi.a`/`.so` into `lib/`; Nim loads dynamically when present, otherwise links static.
- **State & safety**: Rust owns key material and epoch counters; Nim wrappers expose explicit alloc/free and keep XMSS stateful usage aligned. The C ABI stays plain C—callers serialize mutable access if they share handles across threads.

## Signature Scheme
| Property | Value |
|----------|-------|
| Security | Post-quantum, hash-based |
| Type | Stateful (epoch-synchronized) |
| Key lifetime | 2^18 epochs (configurable) |
| Hash | Poseidon2 over KoalaBear field |
| Encoding | Target-sum incomparable |
| Tree | Two-level Merkle (top + bottom) |

## Requirements
- Nim ≥ 2.2.0
- Rust (stable toolchain) and Cargo
- Git (used to pull the vendored Rust submodules)

## Build & Test
```bash
# Fetch/update Rust submodules (leansig core + multisig)
make update   # optional; run explicitly if you prefer to do this step first

# Build Rust FFI artifacts into ./lib (automatically runs `make update`)
make ffi

# Run Nim tests (depends on ffi build)
make test

# Alternative: nimble test (also builds ffi)
make nimble-test

# Run performance benchmarks
make bench

# See detailed benchmark results
cat BENCHMARK_RESULTS.md
```

## Performance

Sub-millisecond signing and verification with post-quantum security:
- **Signing:** ~0.56 ms average
- **Verification:** ~0.36 ms average
- **Throughput:** >1,700 ops/s for signing, >2,700 ops/s for verification

See [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md) for complete performance analysis.

## Usage (Nim)
```nim
import leansig

var kp = newLeanSigKeyPair("seed phrase", 0, 100)
defer: kp.free()

let msgLen = messageLength()
var msg = newSeq[byte](msgLen)
let sig = kp.sign(msg, 0)
defer: sig.free()
doAssert sig.verify(msg, kp, 0)
```

## Project Layout
- `src/` – Nim APIs (`leansig.nim`, `multisig.nim`) and FFI bindings.
- `rust/ffi/` – Rust C-ABI crate (`leansig_ffi`).
- `rust/leansig/` – leanSig core library (git submodule).
- `tests/` – Nim test suites.
- `benches/` – Comprehensive performance benchmarks (see [benches/README.md](benches/README.md)).
- `build/` – helper scripts (e.g., `build_rust.sh`).

## Notes
- The leanSig core and multisig prover are vendored as git submodules under `rust/leansig` and `rust/Multisig`. `make ffi` runs `git submodule update --init --recursive` automatically; run `make update` yourself if you want to refresh them without rebuilding.
- The build produces static and dynamic libraries under `lib/`.

## References
- DKKW25a: "Hash-Based Multi-Signatures for Post-Quantum Ethereum" – https://eprint.iacr.org/2025/055.pdf
- DKKW25b: "LeanSig for Post-Quantum Ethereum" – https://eprint.iacr.org/2025/1332.pdf
- Related code: leanSig (https://github.com/leanEthereum/leanSig), Plonky3 (https://github.com/Plonky3/Plonky3)
- Spec: RFC 8391 (XMSS) – https://datatracker.ietf.org/doc/html/rfc8391

## License
MIT (see `LICENSE`).
