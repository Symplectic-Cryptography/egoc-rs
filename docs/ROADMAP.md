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

- **Reparameterization to OPT1 (DONE).** The candidate is now `(mr,mc,k,ℓ) =
  (22,31,46,8)` (`CodeParams::L1`), chosen to clear 128 on the optimistic-quantum axis.
  The earlier `22×28`, `k = 40` shape had `cod = 7` (`2¹⁶⁸` classical but only `2¹¹²`
  under an optimistic free-QRAM claw); widening `mc` to 31 lifts `cod` to 10, giving
  `2²⁴⁰` classical / `2¹⁶⁰` optimistic-quantum. Remaining: expose a high-level path that
  selects `L1` for real use (the demo/auction still use `CodeParams::DEMO` by design).
- **Binding rank floor needs an independent derivation.** The `2²⁴⁰` corank-1 figure is
  the codimension/2 balance and stays **ASSUMED**: reading the NQT primary (ePrint
  2024/368) showed its corank-1 invariant attack is square-only and gives no rectangular
  exponent — so the rectangular candidate is *outside* the MEDS-breaking attack (a
  genuine positive), but `2²⁴⁰` is not sourced from it. Derive (or have reviewed) the
  codimension→cost mapping for a true rectangular MCE instance.
- **Algebraic figure is NEEDS-REVIEW (the binding classical attack).** The tri-Hilbert
  estimate gives `≈ 2²⁰²` for the L1 shape but overshoots MEDS's published L1/L3/L5
  floors by 15–40 bits and msolve degrees come in `≈ 2` below its predicted face, so the
  algebraic surface is a band `≈ 180–202`. At the reparameterized shape this is *below*
  the `2²⁴⁰` rank floor, i.e. the cheapest classical attack on the MCE backend.
  Reproduce with the MEDS Magma estimator and a mid-scale direct solve to settle it.
- **Decisional-MCE-with-planted-structure.** A reduction to search-MCE or external
  review; this is the weakest link in MCE hiding.
- **Low-rank / special-orbit resistance (DONE, regression-protected).** The two 2024
  TI-commitment attacks were re-run against the candidate: ePrint 2024/337 is proven
  inapplicable ([`formal/PROOFS.md`](formal/PROOFS.md) Lemma 9, machine-checked in
  `egoc-attack`); ePrint 2024/368 (NQT) is square-only and does not bind the rectangular
  shape.
- **Formal proofs.** The paper proofs are complete and their algebra is
  machine-checked ([`formal/PROOFS.md`](formal/PROOFS.md)); what remains is
  mechanizing them in EasyCrypt (turning the `admit`-marked skeletons into checked
  scripts).
- **Proof-size compression.** Fixed-weight challenges and a seed tree for the MCE
  opening, as in MEDS.
- **Performance.** An NTT for the lattice ring and SIMD field arithmetic.
- **Audit.** A third-party security review before any production use.
