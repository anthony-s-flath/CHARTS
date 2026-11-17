# CHARTS: Compute-efficient Homomorphic Anonymous Routing with Tag Sums

Go research prototype implementing CHARTS routing with multiparty BFV, using Lattigo v6.2.0’s scale-invariant BGV evaluator and coefficient encoding.

The prototype covers collective key generation, request encryption, routing, collective opening, and message recovery in one process. Receiver registration, outer public-key encryption, and network transport are excluded.

## Protocols

Each of `n` senders supplies an `N`-coefficient message and a random tag.

- **Original (`b=n`):** Each sender encrypts a power-sum header and `n` tag-weighted payloads. The router aggregates them using addition alone.
- **Factorized (`b<n`):** Each sender encrypts a header, a sparse control polynomial, and `b` weighted payloads. The router expands the control, multiplies and accumulates payloads, then relinearizes each aggregate once.

Requests contain `n+1` ciphertexts in the original protocol and `b+2` in the factorized protocol. Both produce `n+1` output ciphertexts and require `n+1` partial-decryption shares per sender.

Recovery uses Newton identities, tag-polynomial factorization, and inverse Vandermonde rows. Distinct tags are required; the per-batch collision probability is at most `n(n-1)/(2t)`.

Requirements: `2 <= n < min(N,t)`, `b | n`, and `L=n/b` must be a power of two dividing `N`.

## Quick start

Requires Go 1.24+, GNU Make, and Bash. Benchmark summaries also require Python 3.

```bash
go mod download

# Small, insecure examples of both protocols.
make demo CHARTS_PROFILE=trivial CHARTS_N=8 CHARTS_B=n CHARTS_THREADS=1
make demo CHARTS_PROFILE=trivial CHARTS_N=8 CHARTS_B=2 CHARTS_THREADS=1
```

See [`cmd/demo/main.go`](cmd/demo/main.go) for the API sequence.

## Configuration

Tests, benchmarks, diagnostics, and commands share `internal/config.Load()`.

| Setting | Original: paper, b=n | Factorized: paper, b<n |
| --- | --- | --- |
| N | 8192 | 16384 |
| LogQ | 54,50,50 | 60,60,55,55 |
| LogP | none | 60 |
| t | 9007199255019521 | 9007199255019521 |
| Routed-noise exponent | 18 | 88 |

Default dimensions are `n=256,b=256` for `paper` and `n=8,b=2` for `trivial`. Smudging uses 146 security bits, with `sigma=2^(146/2 + routed-noise exponent)` and bound `6*sigma`.

| Variable | Controls |
| --- | --- |
| `CHARTS_PROFILE` | `paper` or `trivial` |
| `CHARTS_N`, `CHARTS_B` | Sender count and payload count; `CHARTS_B=n` selects the original protocol |
| `CHARTS_LOGN`, `CHARTS_LOGQ`, `CHARTS_LOGP`, `CHARTS_T` | Ring degree and moduli |
| `CHARTS_SMUDGING_SECURITY_BITS`, `CHARTS_LOG2_ROUTED_NOISE` | Smudging distribution |
| `CHARTS_THREADS` | Worker limit for make targets; default 4 |

Set both `n` and `b` when changing batch dimensions. Modulus bit sizes are comma-separated; `CHARTS_LOGP=none` removes P. Direct Go commands use `GOMAXPROCS` for worker control.

The presets use different message capacities because N differs. Account for this when comparing throughput or communication. Parameter overrides require separate correctness, noise, and security checks.

## Tests

```bash
make test
make test-short
make test-expand CHARTS_THREADS=1
make test-protocol CHARTS_N=128 CHARTS_B=n CHARTS_THREADS=1
make test-protocol CHARTS_N=128 CHARTS_B=16 CHARTS_THREADS=1
make test-noise CHARTS_N=128 CHARTS_B=n CHARTS_THREADS=1
make test-noise CHARTS_N=128 CHARTS_B=16 CHARTS_THREADS=1
```

`test-short` skips the full noise diagnostic. `test-expand` compares sparse expansion against Lattigo’s generic expansion. Use identical settings for benchmarks and their correctness/noise checks.

## Benchmarks

```bash
# One configuration.
make benchmark CHARTS_N=128 CHARTS_B=n CHARTS_THREADS=1

# Full sweep.
./scripts/benchmark.sh

# Custom sweep.
CONFIGS="32:32 64:64 128:128 128:16" REPETITIONS=1 CHARTS_THREADS=1 \
  ./scripts/benchmark.sh
```

The default sweep uses 50 repetitions, `BENCHTIME=1x`, four workers, and:

```text
32:32 64:64 128:128 256:256 128:1 128:16 128:32 128:64
```

Request benchmarks and `Opening/PartialDecrypt` measure one sender. Routing, share aggregation, and decoding measure an entire batch. Divide `Routing/Complete` by `n` for amortized router time per message.

Each sweep saves raw output, per-configuration logs, and arithmetic means in milliseconds under `benchmark-results-YYYYMMDD-HHMMSS/`.

Recorded results are in [`benchmark-results-20261024-132917/`](benchmark-results-20261024-132917/). Those logs record an Intel Core i5-14400F and four workers, but omit resolved modulus/noise settings.

## License

Apache License 2.0. Sparse expansion derives from Lattigo’s coefficient-expansion procedure; see [NOTICE](NOTICE).
