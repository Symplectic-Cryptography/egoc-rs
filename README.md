# egoc-rs — post-quantum commitments with zero-knowledge openings

A from-scratch Rust library of post-quantum commitment schemes with zero-knowledge
openings, with almost no external cryptographic dependencies. Two interchangeable
backends sit behind one API: a lattice commitment whose security rests on
module-LWE/MSIS, and a matrix-code commitment whose security rests on Matrix Code
Equivalence, the problem behind the NIST candidate MEDS. The design grew out of a
structural idea borrowed from Itzhak Bars' two-time physics; its security stands on
studied post-quantum hardness, not on the analogy.

- **84 tests, zero warnings, 12 crates.** Only `blake3`, `rand`, `subtle`, and
  `zeroize` are pulled in; every field, group, code, and proof primitive is
  in-house.
- **Two backends, one trust choice.** Pick the assumption you are willing to rely
  on.
- **Honest security accounting.** Every claim is labelled *proven*, *assumed*, or
  *needs external review*, and every bit figure is traced to the tool that produced
  it.

## The two backends

| Backend | Hardness | Cheapest attack | Binding | Status |
|---|---|---|---|---|
| **`lattice`** (SHADOW-SIS-FIX) | module-LWE / MSIS (BDLOP) | hiding ≥ 2¹⁸⁶ classical, ≈ 2¹⁴⁶ quantum | statistical | estimator-confirmed (`lattice-estimator`) |
| **`mce`** (EGOC-MCE-R) | Matrix Code Equivalence (MEDS family) | binding-algebraic ≈ 2²⁰⁸ (rank ≥ 2¹⁰⁶⁴) | computational (MCE) / message-injective | bit estimate via the MEDS methodology, validated against MEDS L1/L3/L5 |

The lattice backend is the conservative choice, with a number you can defend today.
The matrix-code backend carries the `sl(2)` block structure inherited from two-time
physics and reduces to a problem in the Tensor-Isomorphism class. See
[`docs/SECURITY.md`](docs/SECURITY.md) for the full accounting and
[`docs/CRYPTANALYSIS.md`](docs/CRYPTANALYSIS.md) for how the numbers were obtained.

### How it compares

| Scheme | Primitive | Assumption | Classical / quantum | Status |
|---|---|---|---|---|
| e-goc `lattice` | commitment + ZK | module-LWE / MSIS | ≥ 2¹⁸⁶ / ≈ 2¹⁴⁶ | estimator-confirmed here |
| e-goc `mce` | commitment + ZK | Matrix Code Equivalence | ≈ 2²⁰⁸ (estimate) | validated reproduction of the MEDS method |
| MEDS | signature | Matrix Code Equivalence | NIST L1/L3/L5 | NIST additional-signatures round |
| Dilithium / BDLOP | signature / commitment | module-LWE / MSIS | NIST L2–L5 | standardised (ML-DSA) lineage |

e-goc is a commitment library, not a signature scheme; the rows are for assumption
and security-level orientation, not feature parity.

## Quick start

```bash
git clone https://github.com/Symplectic-Cryptography/egoc-rs.git && cd egoc-rs

cargo test --workspace          # 84 tests
cargo run -p egoc-auction --release   # end-to-end sealed-bid auction demo
cargo run -p egoc-bench   --release   # micro-benchmarks
```

The auction and benchmarks run small DEMO parameters for speed. The security sets
(for example the matrix-code candidate `mr = 22, mc = 28, k = 40, ℓ = 8`) live in
[`docs/SPEC.md`](docs/SPEC.md) and are not the demo sizes.

Using the library:

```rust
use egoc::lattice::{
    commit, prove_opening, verify, verify_opening,
    CommitKey, Params, Poly, ProofParams,
};
use rand::{rngs::StdRng, SeedableRng};

let mut rng = StdRng::seed_from_u64(0);
let ck = CommitKey::expand(&[0u8; 32], Params::DEMO);   // public key (DEMO: not a security size)

// the message is k_msg polynomials in R_q; here a single one for DEMO
let m = vec![Poly::zero(); ck.params.k_msg];

// commit to `m`, get a binding+hiding commitment and its opening
let (com, opening) = commit(&ck, m, &mut rng);
assert!(verify(&ck, &com, &opening).is_ok());

// prove knowledge of the opening in zero knowledge
let proof = prove_opening(&ck, &com, &opening, &ProofParams::DEMO, &mut rng).unwrap();
assert!(verify_opening(&ck, &com, &proof, &ProofParams::DEMO));
```

The `egoc::mce` module exposes the matrix-code backend with the same shape
(`commit` / `verify` / `prove_opening`).

## Where it came from

Bars' two-time physics reads ordinary 3+1 space-time as a gauge-fixed *shadow* of a
4+2 parent, with one time direction hidden by an `Sp(2,ℝ)` gauge symmetry. The first
version of this project tried to turn that picture directly into cryptography and a
review panel found it broken in seven distinct ways — most fatally, the "gauge"
element was effectively public, so the message fell out by linear algebra.

This rewrite keeps the one piece of the analogy that is real — the symmetric,
traceless `sl(2)` block `[[m, r], [r, −m]]` as a message encoder — and rebuilds the
hardness on problems cryptographers already study. The full story, including each
fixed flaw, is in [`docs/DESIGN.md`](docs/DESIGN.md).

## Workspace layout

```
crates/
  egoc-field     F_q and the quadratic extension E = F_q[t]/(t²+1)
  egoc-sl2       the sl(2) message encoder (structure only, zero hardness)
  egoc-linalg    dense matrix algebra over E: GL sampling, S·M·T, rank, inverse, hull
  egoc-code      public matrix code + message embedding (EGOC-MCE-R)
  egoc-commit    MCE hash-mode commitment and opening
  egoc-proof     code-equivalence Σ-protocol + message-hiding ZK opening
  egoc-mlwe      lattice backend: BDLOP commitment + Fiat-Shamir-with-aborts ZK
  egoc-aggregate batch opening proofs (per-commitment, not folding)
  egoc-auction   sealed-bid auction built on the MCE backend
  egoc           top-level facade re-exporting both backends
  egoc-attack    adversarial regression suite + MCE cryptanalysis harness
  egoc-bench     micro-benchmarks
docs/            DESIGN, SPEC, SECURITY, CRYPTANALYSIS, PERFORMANCE, ROADMAP, FAQ,
                 formal/ (EasyCrypt proof skeletons, hard steps marked `admit`)
research/        runnable estimator and Gröbner scripts behind the security numbers
```

## Documentation

Read in this order:

1. [`docs/DESIGN.md`](docs/DESIGN.md) — the two-time-physics origin, the
   predecessor's flaws, and what the rewrite changes.
2. [`docs/SPEC.md`](docs/SPEC.md) — the precise construction of both backends.
3. [`docs/SECURITY.md`](docs/SECURITY.md) — the security accounting and threat model.
4. [`docs/CRYPTANALYSIS.md`](docs/CRYPTANALYSIS.md) — parameter calibration and the
   attack analysis behind every number, each tied to a `research/` script.
5. [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) and
   [`docs/ROADMAP.md`](docs/ROADMAP.md) — benchmarks, and what is done versus open.
6. [`docs/FAQ.md`](docs/FAQ.md) — quick answers and a physics/crypto glossary.

## Status and caveats

The lattice backend is production-candidate: its parameters are confirmed by the
standard `lattice-estimator`. The matrix-code backend has a concrete, methodology-
backed bit estimate, but that estimate is a faithful reproduction of the MEDS
analysis rather than a run of the MEDS team's own tooling, and the
decisional variant it relies on still wants external cryptanalytic review. Nothing
here has been through a third-party audit. Treat it as serious research-grade code,
not a deployed standard.

## How to cite

If you use egoc-rs in academic work, cite the repository (see
[`CITATION.cff`](CITATION.cff)):

```bibtex
@software{egoc_rs,
  title  = {egoc-rs: post-quantum commitments with zero-knowledge openings},
  author = {nzengi},
  year   = {2026},
  note   = {SHADOW-SIS-FIX (module-LWE/MSIS) and EGOC-MCE-R (Matrix Code Equivalence)}
}
```

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.
