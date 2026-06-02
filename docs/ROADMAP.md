# Roadmap

An honest record of what is built and what is open. The library is research-grade:
the lattice backend is estimator-confirmed, the matrix-code backend has a validated
bit estimate, and neither has had a third-party audit.

## Done

- **Arithmetic core.** `F_q` and `E = F_q[t]/(t²+1)` with a compile-time
  `q ≡ 3 (mod 4)` guard; matrix algebra over `E` (rank, determinant, inverse, `GL`
  sampling, two-sided product, hull, code membership).
- **Matrix-code backend.** `sl(2)` encoder, public NUMS code with a hull-genericity
  keygen check, hash-mode and code-mode commitments, and a message-hiding
  zero-knowledge opening proof (extractor and simulator included).
- **Lattice backend.** Correct-shape BDLOP commitment and a Fiat–Shamir-with-aborts
  opening proof; parameters tuned and confirmed by `lattice-estimator`.
- **Aggregation.** Honest batch opening proofs that attest each individual opening.
- **Application.** An end-to-end sealed-bid auction demo.
- **Packaging.** A top-level facade, serialization with round-trip tests, and
  micro-benchmarks.
- **Security work.** A regression suite reproducing the predecessor's breaks and
  confirming they fail here; parameter calibration backed by `lattice-estimator`,
  msolve, CryptographicEstimators, and a validated reimplementation of the MEDS
  algebraic cost; EasyCrypt proof skeletons.

## Open

- **Independent MCE confirmation.** Reproduce the ≈ 2²⁰⁸ algebraic figure with the
  MEDS team's own Magma estimator and check the candidate's `d_reg = (4, 9, 0)`
  direction directly.
- **Decisional-MCE-with-planted-structure.** A reduction or external cryptanalytic
  review; this is the weakest link in MCE hiding.
- **Formal proofs.** The paper proofs are complete and their algebra is
  machine-checked ([`formal/PROOFS.md`](formal/PROOFS.md)); what remains is
  mechanizing them in EasyCrypt (turning the `admit`-marked skeletons into checked
  scripts).
- **Proof-size compression.** Fixed-weight challenges and a seed tree for the MCE
  opening, as in MEDS.
- **Performance.** An NTT for the lattice ring and SIMD field arithmetic.
- **Audit.** A third-party security review before any production use.
