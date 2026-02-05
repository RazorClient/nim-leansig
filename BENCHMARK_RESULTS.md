# nim-leansig Benchmark Results

**Date:** February 5, 2026

## System Specifications

- **OS:** Linux 6.8.0-87-generic #88-Ubuntu SMP PREEMPT_DYNAMIC
- **CPU:** 12th Gen Intel(R) Core(TM) i7-1255U
- **Cores:** 12 cores (6P+4E), 2 threads per core
- **Max Frequency:** 1700 MHz
- **Memory:** 38 GiB
- **Nim Version:** 2.2.6 (Linux amd64)
- **Rust Version:** 1.87.0 (nightly)

## Benchmark Methodology

- **Compiler:** Nim 2.2.6 with `-d:release` optimization
- **Warmup:** 3 iterations per benchmark to stabilize JIT and caching
- **Measurement:** Each benchmark repeats the operation N times (varies by operation cost)
- **CPU Frequency:** 1700 MHz (used for cycle calculations)
- **Metrics:**
  - **Average:** Mean execution time across all iterations
  - **Min:** Best-case execution time (fastest single iteration)
  - **Max:** Worst-case execution time (slowest single iteration, may include OS scheduling delays)
  - **CPU Cycles/Op:** Estimated CPU cycles per operation (time × frequency)

## LeanSig Performance

Post-quantum signature operations using hash-based XMSS scheme.

### Keypair Generation (100 epochs)
- Average: 204.13 ms
- Min: 197.47 ms
- Max: 221.36 ms
- CPU Cycles/Op: ~347,021,000 cycles
- Iterations: 10

### Message Signing
- Average: 0.56 ms
- Min: 0.43 ms
- Max: 0.95 ms
- CPU Cycles/Op: ~952,000 cycles
- Iterations: 30

### Signature Verification
- Average: 0.36 ms
- Min: 0.35 ms
- Max: 0.37 ms
- CPU Cycles/Op: ~612,000 cycles
- Iterations: 30

## XMSS Multisig Performance

Multi-signature aggregation with zero-knowledge proofs.

### Keypair Generation (log=3, 8 slots)
- Average: 1.23 ms
- Min: 1.17 ms
- Max: 1.38 ms
- CPU Cycles/Op: ~2,091,000 cycles
- Iterations: 5

### Signing
- Average: 3.61 ms
- Min: 3.28 ms
- Max: 4.64 ms
- CPU Cycles/Op: ~6,137,000 cycles
- Iterations: 20

### Verification
- Average: 0.26 ms
- Min: 0.26 ms
- Max: 0.27 ms
- CPU Cycles/Op: ~442,000 cycles
- Iterations: 20

### Aggregate 2 Signatures
- Average: 401.18 ms
- Min: 378.85 ms
- Max: 422.46 ms
- CPU Cycles/Op: ~682,006,000 cycles
- Iterations: 5

Note: Aggregation involves proof generation using recursive SNARK composition, which is computationally expensive.

### Verify Aggregated Proof (2 signers)
- Average: 34.54 ms
- Min: 33.45 ms
- Max: 36.21 ms
- CPU Cycles/Op: ~58,718,000 cycles
- Iterations: 5

## Throughput Analysis

Operations per second at average execution time:

| Operation | Throughput |
|-----------|------------|
| LeanSig Keypair Gen | 4.9 ops/s |
| LeanSig Signing | 1,785 ops/s |
| LeanSig Verification | 2,777 ops/s |
| XMSS Keypair Gen | 813 ops/s |
| XMSS Signing | 277 ops/s |
| XMSS Verification | 3,846 ops/s |
| Aggregate 2 Sigs | 2.5 ops/s |
| Verify Aggregated | 29 ops/s |

## Performance Characteristics

### LeanSig
- Keypair generation: O(n) where n is number of epochs, dominated by tree construction
- Signing: O(log n) tree traversal with hash operations
- Verification: O(log n) Merkle path verification

### XMSS Multisig
- Keypair generation: O(2^h) where h is tree height (log parameter)
- Aggregation: O(n * m) where n is number of signers, m is proof circuit complexity
- Aggregate verification: O(log n) for proof verification, independent of number of signers

## Build Configuration

- **Rust Toolchain:** Nightly (required for `let_chains` feature)
- **Optimization:** `-d:release` (Nim), `--release` (Rust)
- **FFI:** libleansig_ffi (Rust C-ABI)
- **Memory Management:** Nim ORC garbage collector
- **Target:** x86_64-unknown-linux-gnu

## Environmental Factors

- Laptop system with dynamic CPU frequency scaling
- Background OS processes present
- No CPU affinity or real-time scheduling configured
- Results include minor variations from thermal throttling and OS scheduling

## Reproducibility

```bash
make ffi   # Build Rust FFI library
make bench # Run benchmarks
```

Or using nimble:
```bash
nimble bench
```

## Implementation Notes

- Single-threaded execution (no parallelization)
- FFI overhead is negligible (<1% of operation time)
- Memory allocations are deterministic (no garbage collection during measurement)
- Cryptographic operations use constant-time implementations where applicable
