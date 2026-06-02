# Cryptanalysis and parameter calibration

This is the working behind the figures in [`SECURITY.md`](SECURITY.md): how the
parameters were chosen and how each attack cost was computed. Every number here is
reproducible with a script in [`../research/`](../research/).

## The instance an attacker actually sees

For the matrix-code backend, only one of two objects is public:

- *hash mode* publishes `com = BLAKE3(C)`. Before opening, hiding is just BLAKE3
  hiding; MCE is not invoked.
- *code mode* (and the zero-knowledge opening) publishes `C = S·M·T`. Recovering the
  message means recovering the secret equivalence, i.e. solving Matrix Code
  Equivalence between the public code `C₀ = span{Gₗ}` and `C`.

The pushed basis `{S·Gₗ·T}` is never published, so the calibration below treats the
*harder-for-us* pessimistic case where it would be — exposing more to the attacker
than the scheme actually does.

## How the parameters were chosen

| Choice | Value | Reason |
|---|---|---|
| field | `q = 16777259 ≡ 3 (mod 4)`, `|E| = q² ≈ 2⁴⁸` | anisotropic norm; large enough to push rank/brute surfaces far past 2¹²⁸ |
| shape | `mr = 22`, `mc = 28` (rectangular) | a square code has cheapest-rank-drop codimension 1; `mc − mr = 6` lifts it to 7 |
| code dim | `k = 40` (`fill = k/(mr·mc) = 0.065`) | far below the easy near-full-rank regime, and below the threshold that would force low-rank codewords |
| witness | `ℓ = 8` pairs | witness search is `q^{2ℓ} = 2³⁸⁴` classical, `2¹⁹²` under Grover |

The rectangular choice deserves a note. MEDS uses *square* codes (`m = n`) and is
still 128-bit, which shows the cheapest-rank-drop collision is not the binding
attack there — the algebraic one is. Choosing a rectangular code is therefore extra
conservative, not necessary, and `egoc-attack::mce::rank_drop_codim` encodes the
fact: `rank_drop_codim(14,14,13) = 1` (weak square) versus
`rank_drop_codim(22,28,21) = 7`.

## Algebraic attack — the binding cost

The dominant attack on MCE is algebraic: the bilinear system `C = S·M·T` solved by
Gröbner methods. Its cost is the tri-Hilbert-series estimate from the MEDS
submission (MEDS.pdf §4.3.1), and crucially it is **field-independent** — it depends
only on `(mr, mc, k)`.

`research/meds_algebraic_estimator.py` reimplements that formula. It is validated by
reproducing all three MEDS NIST levels:

The matrix dimensions below are `(mr, mc, k)`, matching SPEC and SECURITY; the MEDS
sets are square so `mr = mc`. The algebraic cost is symmetric in `mr` and `mc`.

| Set | `(mr, mc, k)` | this estimate | MEDS level |
|---|---|---|---|
| MEDS L1 | 14,14,14 | 2¹⁴⁵ | ≥ 128 |
| MEDS L3 | 22,22,22 | 2²¹⁵ | ≥ 192 |
| MEDS L5 | 30,30,30 | 2²⁹⁵ | ≥ 256 |
| **EGOC candidate** | 22,28,40 | **2²⁰⁸** | — |

The estimate sits a consistent 15–40 bits above each MEDS floor, so it is faithful
(and mildly conservative). The candidate lands at ≈ 2²⁰⁸, just under the L3
estimate — on a par with MEDS L3 (192-bit) and comfortably above the 128-bit floor.
We classify it conservatively as 180–192, rounding the point estimate down to
account for its uncertainty and the still-missing Magma confirmation. The MEDS paper
records that this attack has no quantum speedup, so the quantum cost is comparable.

(`research/meds_algebraic_estimator.py` also reports ≈ 2¹⁹⁰ for an alternative
denser-`k` set `(24, 30, 56)`; it is not part of the security claim and is omitted
here to keep this table to the validated sets and the chosen candidate.)

The empirical picture from msolve agrees. On a gauge-fixed ladder
(`research/groebner_mce.sage`, systems from `egoc-attack`'s exporter), the solving
degree rises with size — 3 at 3×4, 4 at 4×5 — and does not collapse toward 2–3; the
degree-4 Macaulay matrix already exhausts memory at 5×6 (≈ 400k × 450k). The cost
grows steeply exactly as the formula predicts.

## Rank-based attacks — not a threat

Leon-like and MinRank attacks need low-rank codewords. In the rank-generic regime
(`k = 40 ≪ mr·mc = 616`) the minimum rank is `min(mr,mc) = 22`, and codewords below
that are absent. CryptographicEstimators (Support-Minors) on the candidate returns
**≥ 2¹⁰⁶⁴** at the smallest existing rank (r = 18), rising further for higher ranks.
`research/run_mce_estimator.py` reproduces this. The Leon-collision floor, even read
pessimistically for the rectangular code, is `|E|^{7/2} = 2¹⁶⁸`.

## Brute force and the MEDS dimension comparison

Exhaustive search over `(S, T)` costs `|GL_mr(E) × GL_mc(E)| ≈ 2⁶⁰⁸⁶⁴` — a sanity
floor, never the bottleneck. As an independent cross-check,
`research/meds_compare.py` places the candidate against the vetted MEDS sets: its
matrix area `mr·mc = 616` exceeds MEDS-L3's 484 (192-bit), its field is about 4×
larger in bits, and its `k·log₂(q) = 40 × 24 = 960` is roughly 3× MEDS-L5's
`30 × 11 = 330`. The Weil-restricted view (`44 × 56, k = 80`) dominates MEDS-L5
(`30 × 30, k = 30`, 256-bit) on every dimension.

## Lattice calibration

The lattice backend was deliberately tuned down from an over-provisioned set. The
original `k_bind = 4, l_rand = 8` measured at ≈ 2³⁰⁹ classical — far beyond target.
The tuned set `k_bind = 3, k_msg = 1, l_rand = 5, η = 2` (`N = 256, q = 8380417`)
was confirmed by `lattice-estimator` (`research/run_lattice_estimator.py`): the
lowest attack is dual-hybrid at 2¹⁸⁶·⁷ (β = 550), binding is statistical
(`rop = ∞`), and the change cut proof size by a third and commitment size by a
fifth. `research/estimate_mlwe_coresvp.py` gives a dependency-free core-SVP ballpark
that tracks the authoritative run.

## Reproducing the numbers

| Figure | Script | Tool needed |
|---|---|---|
| MCE algebraic ≈ 2²⁰⁸ (+ MEDS validation) | `research/meds_algebraic_estimator.py` | python3 |
| MCE comparison to MEDS sets | `research/meds_compare.py` | python3 |
| MinRank ≥ 2¹⁰⁶⁴ | `research/run_mce_estimator.py` | CryptographicEstimators |
| MCE solving-degree ladder | `research/groebner_mce.sage`, `export_msolve.py` | Sage / msolve |
| Lattice ≥ 2¹⁸⁶, statistical binding | `research/run_lattice_estimator.py` | Sage + lattice-estimator |
| Lattice core-SVP ballpark | `research/estimate_mlwe_coresvp.py` | python3 |

## Open items

- Confirm the MCE algebraic number with the MEDS team's own Magma estimator; check
  the candidate's `d_reg = (4, 9, 0)` direction (an artifact of the large-`k`
  asymmetry, plausibly real but worth a direct solve).
- Settle decisional-MCE-with-planted-structure by reduction or external review.
- Re-run the lattice estimator after any parameter change.
