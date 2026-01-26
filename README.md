# nim-leansig

Nim bindings for post-quantum signature schemes from [leanSig](https://github.com/leanEthereum/leanSig).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Nim](https://img.shields.io/badge/Nim-2.2.0+-yellow.svg)](https://nim-lang.org/)

## Overview

Nim bindings for the **leanSig** cryptographic library, implementing post-quantum signature schemes designed for Ethereum's proof-of-stake consensus. Based on hash-based cryptography (XMSS), these signatures remain secure against both classical and quantum computers.

**Key Features:**
- Quantum-resistant security based on hash functions
- Optimized for Ethereum validator signing
- Stateful design prevents key reuse attacks
- Production-ready implementation from peer-reviewed research

## Architecture

Stack overview:

```
┌──────────────────────────────────────────────────────────────┐
│                      Nim Application                         │
│                    (Your Code Here)                          │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                  nim-leansig (This Library)                  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  High-Level Nim API                                    │  │
│  │  • Type-safe wrappers                                  │  │
│  │  • Memory management                                   │  │
│  │  • Nim idioms                                          │  │
│  └──────────────────────┬─────────────────────────────────┘  │
│                         │                                    │
│  ┌──────────────────────▼─────────────────────────────────┐  │
│  │  FFI Bindings Layer (leansig_bindings.nim)             │  │
│  │  • C ABI interface                                     │  │
│  │  • Dynamic library loading                             │  │
│  └──────────────────────┬─────────────────────────────────┘  │
└─────────────────────────┼─────────────────────────────────  ─┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────┐
│              Rust FFI (leansig_ffi - C ABI)                  │
│  • Exports C-compatible functions                            │
│  • Type marshalling                                          │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│              leanSig Core (Rust Library)                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Generalized XMSS Implementation                       │  │
│  │  • Key generation                                      │  │
│  │  • Signing algorithm                                   │  │
│  │  • Verification                                        │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Cryptographic Primitives                              │  │
│  │  • Poseidon2 hash (Plonky3)                            │  │
│  │  • Target-sum encoding                                 │  │
│  │  • Merkle tree operations                              │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Features

- Key generation with configurable lifetime
- Epoch-based signature creation
- Public key verification
- Memory-safe with automatic resource management
- Zero-configuration builds
- Type-safe cryptographic operations

### Signature Scheme

| Property | Value |
|----------|-------|
| **Security Level** | Post-quantum (hash-based) |
| **Signature Type** | Stateful (epoch-synchronized) |
| **Key Lifetime** | 2^18 epochs (configurable) |
| **Hash Function** | Poseidon2 over KoalaBear field |
| **Encoding** | Target-sum incomparable encoding |
| **Tree Structure** | Two-level Merkle tree (top + bottom) |

## Quick Start

**Prerequisites:** Nim ≥ 2.2.0, Rust (latest stable), Git

### Installation

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/leanEthereum/nim-leansig
cd nim-leansig

# Build and test (static linking by default)
nimble test

# Build and test (dynamic linking)
nimble testDynamic
```

### Linking Options

The library uses **static linking by default** for maximum portability.

**Static linking (default):**
- No runtime dependencies
- Fully self-contained executable
- Larger binary size (~23MB additional)

```bash
nim c -r your_app.nim
```

**Dynamic linking (opt-in):**
- Runtime dependency on shared library (.so/.dylib/.dll)
- Smaller binary size
- Use standard `--dynlibOverride` flag

```bash
nim c -r --dynlibOverride your_app.nim
# or
nim c -r -d:dynlibOverride your_app.nim
```

## Usage

```nim
import leansig

proc main() =
  var ls = initLeanSig()
  defer: ls.close()
  echo "Lifetime: ", ls.lifetime(), " epochs"

when isMainModule:
  main()
```

## Technical Details

### Parameters

```
Configuration: lifetime_2_to_the_18
├── LOG_LIFETIME: 18 (2^18 = 262,144 epochs)
├── DIMENSION: 64
├── BASE: 8
├── TARGET_SUM: 375
└── Hash Function: Poseidon2 over KoalaBear field
    ├── Field: p3-koala-bear
    ├── Width: 16 (tree hashing)
    ├── Width: 24 (top-level hashing)
    └── Capacity: 9
```

### Tree Structure

```
                    Top Tree
                  (√L = 2^9 leaves)
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
   Bottom Tree 0   Bottom Tree 1   ... Bottom Tree k
   (2^9 leaves)    (2^9 leaves)        (2^9 leaves)
        │               │               │
        ▼               ▼               ▼
   Hash Chains     Hash Chains     Hash Chains
   (OTS Keys)      (OTS Keys)      (OTS Keys)
```

Each hash chain represents a one-time signature key for a specific epoch.

## Development

### Project Structure

```
nim-leansig/
├── src/
│   ├── leansig.nim              # High-level API
│   ├── leansig_bindings.nim     # FFI declarations
│   └── nim_leansig/
│       └── submodule.nim
├── rust/
│   ├── leansig/                 # Git submodule (core library)
│   └── ffi/                     # C ABI wrapper
│       ├── src/lib.rs
│       └── Cargo.toml
├── tests/
│   └── test_basic.nim
├── build/
│   └── build_rust.sh            # Rust build script
├── lib/                         # Compiled .so/.dll/.dylib
└── nim_leansig.nimble           # Package definition
```

### Building

```bash
# Build Rust library (creates both .a and .so)
./build/build_rust.sh

# Test with static linking (default)
nimble test

# Test with dynamic linking
nimble testDynamic

# Clean build artifacts
rm -rf lib/ nimcache/ tests/test_basic
cargo clean --manifest-path=rust/ffi/Cargo.toml
```

**Library files generated:**
- `lib/libleansig_ffi.a` - Static library (~23MB, includes all dependencies)
- `lib/libleansig_ffi.so` - Shared library (~400KB, requires runtime linking)

## References

**Research:**
- [DKKW25a] "Hash-Based Multi-Signatures for Post-Quantum Ethereum" (https://eprint.iacr.org/2025/055.pdf)
- [DKKW25b] "LeanSig for Post-Quantum Ethereum" (https://eprint.iacr.org/2025/1332.pdf)

**Related Projects:**

- [leanSig](https://github.com/leanEthereum/leanSig) - Core Rust implementation
- [Plonky3](https://github.com/Plonky3/Plonky3) - Cryptographic primitives
- [RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391) - XMSS specification

## License

MIT - see [LICENSE](LICENSE) file.
