# Performance

Numbers from `cargo run -p egoc-bench --release` on the demo parameter sets. They
measure the current, correctness-first implementation; the obvious optimisations
(an NTT for the lattice ring, SIMD field arithmetic, seed-tree proof compression)
are deliberately not done yet, so read these as a floor, not a ceiling.

## Field and matrix algebra over `E` (`q = 4099`)

| Operation | Time |
|---|---|
| `Fp2` invert | 0.53 µs |
| `Mat` 8×9 · 9×9 multiply | 6.6 µs |
| two-sided `S·M·T` (8×9) | 12 µs |
| `GL₈(E)` invertible sample | 6.7 µs |
| `Mat` 8×9 rank | 7.5 µs |

## Matrix-code backend (demo: `mr=8, mc=9, k=16, λ=32`)

| Operation | Time |
|---|---|
| commit (`C = S·M·T`) | 42 µs |
| opening prove | 1.2 ms |
| opening verify | 3.6 ms |

## Lattice backend (tuned params)

| Operation | Time |
|---|---|
| commit (BDLOP) | 0.72 ms |
| opening prove (Fiat–Shamir-with-aborts) | 1.7 ms |
| opening verify | 0.52 ms |

The lattice commit is dominated by schoolbook negacyclic polynomial multiplication;
an NTT (the ring and prime already support it) would cut it by roughly an order of
magnitude. The `λ = 32` proof timings are demo soundness — production `λ = 128`
scales the proof work and size by 4×, which a seed-tree would claw back.

## Sizes

The end-to-end auction demo (`cargo run -p egoc-auction --release`) publishes a
sealed bid — a code-mode commitment plus a `λ = 32` opening proof — of roughly 90–100
KB. Proof size is linear in `λ` and in the number of rounds; compressing it with
fixed-weight challenges and a seed tree, as MEDS does, is the natural next step and
is listed in [`ROADMAP.md`](ROADMAP.md).
