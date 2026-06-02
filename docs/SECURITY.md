# Security

This is the single, current security statement for egoc-rs. Every property is
marked **proven**, **assumed**, or **needs review**, and every bit figure names the
tool that produced it. Numbers in [`CRYPTANALYSIS.md`](CRYPTANALYSIS.md) are the
working; this file is the summary.

## At a glance

| Property | Lattice (SHADOW-SIS-FIX) | Matrix-code (EGOC-MCE-R) |
|---|---|---|
| Hiding | decision-MLWE, **≥ 2¹⁸⁶ classical / ≈ 2¹⁴⁶ quantum** | MCE (the cheapest attack is the binding-algebraic one below) |
| Binding | statistical (MSIS), no short collision | computational (MCE-collision) + injective encoder; cheapest attack is algebraic, band **≈ 180–202** (NEEDS-REVIEW); rank-collision floor **2²⁴⁰ classical / 2¹⁶⁰ optimistic-quantum** |
| Tooling | `lattice-estimator` | MEDS-methodology estimate (validated) + CryptographicEstimators |
| Confidence | estimator-confirmed | bit estimate; needs external review |

## Threat model

- **Adversary.** Probabilistic polynomial-time, classical or quantum. Bit figures
  are given in both metrics.
- **Goals.** Computationally hiding and statistically/computationally binding
  commitments, with honest-verifier zero-knowledge openings.
- **Trust assumptions.** The public parameters come from a published
  nothing-up-my-sleeve seed and are assumed honestly generated; the Fiat–Shamir
  transcript binds the full statement; in the matrix-code backend the pushed basis
  `{S·Gₗ·T}` is never published.
- **Out of scope.** A maliciously generated public seed; timing and other side
  channels beyond the constant-time field inversion at the lowest layer; and any
  guarantee absent a third-party audit (none has been done).

## Lattice backend — SHADOW-SIS-FIX

This is the conservative line; its security is textbook BDLOP over module-LWE/MSIS.

**Proven.** Hiding reduces to decision-MLWE by the BDLOP18 hybrid argument, which
applies because the commitment uses the correct shape `c1 = A1·r`, `c2 = A2·r + m`
with `l_rand > k_bind + k_msg`. Binding is statistical: a second short opening would
be a short vector in `ker(A1)`, and the shortest such vector exceeds twice the
opening norm, so none exists.

**Confirmed by `lattice-estimator`** on the tuned parameters
(`N = 256, q = 8380417, k_bind = 3, k_msg = 1, l_rand = 5, η = 2`):

| Attack | Classical cost |
|---|---|
| dual-hybrid (lowest) | **2¹⁸⁶·⁷** (β = 550) |
| BDD | 2¹⁸⁹·⁸ |
| primal uSVP | 2¹⁹²·³ |
| dual | 2¹⁹⁷·⁹ |

Hiding is therefore at least 2¹⁸⁶ classical and about 2¹⁴⁶ quantum (core-SVP at
β = 550); binding is statistical (`rop = ∞` in the estimator — no feasible short
collision). The set is comfortably above the 128-bit target in both metrics, with
room to shrink for efficiency.

## Matrix-code backend — EGOC-MCE-R (Matrix Code Equivalence, MEDS family)

Candidate parameters (`CodeParams::L1`): `q = 16777259` (`|E| ≈ 2⁴⁸`), `mr = 22,
mc = 31, k = 46, ℓ = 8`. Hiding rests on Matrix Code Equivalence, the problem behind
the NIST candidate MEDS.

**Assumed (named, studied).** MCE / decisional-MCE-with-planted-structure. MCE is
Tensor-Isomorphism-complete and believed hard, including against quantum
adversaries; the planted-structure decisional variant is the part that wants
external review.

**Attack-cost summary** (full derivation in [`CRYPTANALYSIS.md`](CRYPTANALYSIS.md)):

| Attack surface | Cost | Source |
|---|---|---|
| Algebraic / bilinear Gröbner (cheapest classical) | band **≈ 180–202**, NEEDS-REVIEW | MEDS §4.3.1 methodology, reimplemented and validated |
| Corank-1 rank collision | 2²⁴⁰ classical / 2¹⁶⁰ optimistic-quantum (`|E|^{cod/2}`, `cod = 10`) | analytical codimension model (ASSUMED) |
| MinRank / Support-Minors | ≥ 2¹⁰⁶⁴ | CryptographicEstimators |
| NQT corank-1 invariant (ePrint 2024/368) | not applicable (square-only; rectangular shape is outside it) | primary source |
| Brute force on `(S, T)` | 2⁶⁹³⁶⁰ | `|GL_mr × GL_mc|` |
| Witness (planted-coordinate) search | 2³⁸⁴ classical, 2¹⁹² quantum | `q^{2ℓ}` / Grover |

The cheapest classical attack is the algebraic one, a band **≈ 180–202** (NEEDS-REVIEW:
the estimator overshoots MEDS's own published floors by 15–40 bits and msolve degrees
come in ~2 low, so the true cost is plausibly lower). The rank-collision floor is higher
(`2²⁴⁰` classical, `2¹⁶⁰` under an optimistic free-QRAM quantum claw) after the `mc = 31`
reparameterization lifted the codimension to 10. So the candidate is **≥ 128-bit on the
MCE surface on every axis under the realistic model**, with the algebraic band the figure
to pin down. The MEDS paper notes the algebraic attack has no quantum speedup. The
single MCE figure that is not yet sourced from a primary paper is the corank-1 `2²⁴⁰`
codimension model; see the open items in [`CRYPTANALYSIS.md`](CRYPTANALYSIS.md).

**How the algebraic number was obtained, and why to trust it.** The cost formula is
the tri-Hilbert-series estimate from the MEDS submission (§4.3.1), reimplemented in
`research/meds_algebraic_estimator.py`. The reimplementation reproduces all three
MEDS NIST levels — L1 → 2¹⁴⁵ (≥ 128), L3 → 2²¹⁵ (≥ 192), L5 → 2²⁹⁵ (≥ 256) — with a
consistent, slightly conservative margin, which is the validation. Independent
empirical evidence agrees: msolve shows the solving degree rising (3 → 4 → …) and
the Gröbner cost exhausting memory at sizes as small as 5×6, and the rank surface is
authoritatively `≥ 2¹⁰⁶⁴`.

## What still needs external work

- **Independent confirmation of the MCE algebraic number** with the MEDS team's own
  Magma tooling (we have a validated reproduction, not their original tool), and a
  check of the candidate's `d_reg = (4, 9, 0)` large-`k` solving direction.
- **A formal hardness argument for decisional-MCE-with-planted-structure** — the
  weakest link in the MCE hiding claim.
- **Discharging the EasyCrypt proof skeletons** in [`formal/`](formal/) (the
  reductions are sketched with their hard steps marked `admit`).
- **A third-party audit.** None has been performed.

## Honesty policy

The `sl(2)`/two-time structure contributes no hardness and is documented as such
everywhere. Aggregation proves each individual opening, not a sum. Hiding is
computational, not perfect. No bit figure is stated without naming the tool behind
it, and the matrix-code figures are labelled estimates until independently
confirmed.
