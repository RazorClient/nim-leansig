# Benchmarks

Performance benchmarks for nim-leansig.

## Usage

```bash
make bench
```

Or:

```bash
nimble bench
```

## What's Tested

- **LeanSig**: Keypair generation, signing, verification
- **XMSS Multisig**: Keypair generation, signing, verification, aggregation

## Output

Each benchmark reports:
- Average execution time
- Min/max times

Example:
```
==================================================
Keypair Gen (100 epochs)
==================================================
Avg: 198.14 ms
Min: 196.01 ms | Max: 200.93 ms
```
