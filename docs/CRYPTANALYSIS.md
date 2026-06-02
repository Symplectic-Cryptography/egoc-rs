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
| shape | `mr = 22`, `mc = 31` (rectangular) | a square code has cheapest-rank-drop codimension 1; `mc − mr = 9` lifts it to 10 (floor `2²⁴⁰`) |
| code dim | `k = 46` (`fill = k/(mr·mc) = 0.067`) | far below the easy near-full-rank regime; low rate |
| witness | `ℓ = 8` pairs | witness search is `q^{2ℓ} = 2³⁸⁴` classical, `2¹⁹²` under Grover |

This is the `OPT1` reparameterization (`CodeParams::L1`). It replaces an earlier
`22 × 28`, `k = 40` candidate whose cheapest rank-drop codimension was only `7`
(`2¹⁶⁸` classical, `2¹¹²` under an optimistic free-QRAM quantum claw — below 128).
Widening `mc` to `31` lifts the codimension to `10`, raising both the classical
(`2²⁴⁰`) and the optimistic-quantum (`2¹⁶⁰`) floors past 128. The rectangular choice
is the lever here: MEDS uses *square* codes (`m = n`) where the cheapest-rank-drop
codimension is `1`, and `egoc-attack::mce::rank_drop_codim` encodes the difference —
`rank_drop_codim(14,14,13) = 1` (weak square) versus `rank_drop_codim(22,31,21) = 10`.

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
| **EGOC candidate** | 22,31,46 | **2²⁰²** | — |

The candidate lands at a point estimate of `≈ 2²⁰²`. This number is **NEEDS-REVIEW
and must not be quoted as a hard floor**, for two reasons that came out of a direct
audit. First, the same estimator *overshoots* MEDS's own published floors: it returns
`2¹⁴⁵ / 2²¹⁵ / 2²⁹⁵` for L1 / L3 / L5 against the published `128 / 192 / 256`, i.e. it
is 15–40 bits high, so it is a loose upper heuristic rather than a faithful estimate.
Second, on rectangular downscale ladders `msolve` measures solving degrees about two
below the degree the estimator's boundary face predicts (here `d_reg = (5, 7, 0)`, the
`γ = 0` face that the symmetric MEDS sets never select) — the same over-prediction
direction that cost ALTEQ more than 20 bits. The true algebraic cost is therefore
plausibly *lower* than `2²⁰²`, and the decisive candidate-sized Gröbner solve is out of
reach here, so the candidate's true solving degree is unmeasured. We quote the
algebraic surface as a **band `≈ 180–202`, NEEDS-REVIEW**, pending a Magma/msolve solve
near the candidate shape. With the reparameterized shape the corank-1 rank-collision
floor (`2²⁴⁰`, below) is now *higher* than this algebraic band, so the **algebraic
attack is the cheapest classical attack on the matrix-code backend**, and the lattice
backend (`≈ 2¹⁸⁶`) is the independent cross-check at a comparable level. The MEDS paper
records no quantum speedup for the algebraic attack.

(`research/meds_algebraic_estimator.py` also reports ≈ 2¹⁹⁰ for an alternative
denser-`k` set `(24, 30, 56)`; it is not part of the security claim and is omitted
here to keep this table to the validated sets and the chosen candidate.)

The empirical picture from msolve agrees. On a gauge-fixed ladder
(`research/groebner_mce.sage`, systems from `egoc-attack`'s exporter), the solving
degree rises with size — 3 at 3×4, 4 at 4×5 — and does not collapse toward 2–3; the
degree-4 Macaulay matrix already exhausts memory at 5×6 (≈ 400k × 450k). The cost
grows steeply exactly as the formula predicts.

## Rank-based attacks and the corank-1 surface

Leon-like and MinRank attacks, and the corank-1 invariant/birthday attack of
Narayanan–Qiao–Tang (ePrint 2024/368, the analysis that forced a MEDS parameter
revision), all exploit low-rank codewords. Reading 2024/368 directly settles one thing
in egoc's favour: their corank-1 invariant attack is analysed **only for the square
case** `m = n` — the tripartite walk `u → v → w → u` and the corank-1 point count
(Theorem 1) require all three legs of the trilinear form to have equal dimension, and
the paper gives no cost exponent for a rectangular shape. The square formula
`q^{(n−2)/2}(q·n³+n⁴)(log q)²` is faithful (it reproduces the MEDS Table 1 figures
`102.59 / 152.55 / 186.57` to within 0.006 bit), but it is undefined for the egoc
`(22, 31, 46)` shape, and plugging the candidate's sides into it over base `|E| = 2⁴⁸`
gives `≥ 2⁴⁸⁰`. So the very attack that re-parametrised MEDS does not bind the
rectangular candidate; the binding rank figure comes from the codimension model below,
not from 2024/368.

A correction to an earlier version of this document is needed here. It is **not**
true that the minimum code rank is `min(mr,mc) = 22` with no codewords below it.
Rank-`21` codewords *do* exist: the determinantal variety `{rank ≤ 21}` has
codimension `(mr−r)(mc−r) = mc−mr+1 = 10 < k = 46`, so it meets the code, and a single
such codeword is even found in polynomial time by left-kernel planting. This
findability is generic to any matrix code with `k > mc` and is not a security
regression on its own: corank-1 codewords form a `≈ |E|^{k−1−10} = 2¹⁶⁸⁰` family, the
opposite of the rigid minimum-rank anchor set that breaks structured schemes, so one
codeword does not pin the equivalence `(S, T)`.

What governs the rank attacks is the **cheapest rank-drop codimension**,
`cod = mc − mr + 1 = 10`. The corank-1 collision/birthday floor is the standard
`|E|^{cod/2} = 2²⁴⁰` classical balance; `egoc-attack::mce::rank_drop_codim(22,31,21)`
returns `10` and the test `rectangular_geometry_lifts_the_collision_codim` pins it.
Deeper rank drops (`r ≤ 18`, codimension `≥ 39`) sit on the hard MinRank /
Support-Minors surface — CryptographicEstimators returns **≥ 2¹⁰⁶⁴** there
(`research/run_mce_estimator.py`). At the reparameterized shape this `2²⁴⁰` rank figure
is *higher* than the algebraic band (`≈ 180–202`), so the rank surface is no longer the
cheapest classical attack — the algebraic one is — but it is what the rectangular
geometry was widened to control.

Two honesty caveats. The `2²⁴⁰` exponent is the codimension/2 birthday balance, and it
stays **ASSUMED**. An attempt to source it from the NQT primary (ePrint 2024/368)
*failed*: as noted above that paper analyses only the square case and supplies no
rectangular exponent, so it cannot be promoted to proven from it — it is the separate
Leon/min-rank codimension model (`cod = 10`, `|E| = 2⁴⁸`), whose mapping to a cost for a
genuine rectangular MCE instance is not yet derived from any primary source and is a
NEEDS-REVIEW item. On the quantum axis, an optimistic free-QRAM BHT claw gives
`|E|^{cod/3} = 2¹⁶⁰` (itself a codimension extrapolation, *not* the NQT Tani-claw
`q^{n/3}`, which is square-only and needs exponential QRAM that NIST does not credit);
the realistic no-QRAM figure is `2²⁴⁰`. Both clear 128 — which is the point of the
reparameterization: the earlier `22 × 28`, `k = 40` shape had `cod = 7`, giving `2¹⁶⁸`
classical but only `2¹¹²` under the optimistic free-QRAM model, below 128. Widening
`mc` to `31` (`cod = 10`) lifts the optimistic-quantum floor to `2¹⁶⁰` (see
[`ROADMAP.md`](ROADMAP.md)).

## Resistance to the low-rank special-orbit attack (ePrint 2024/337)

Gilchrist, Marco, Petit, and Tang (CRYPTO 2024) broke an Asiacrypt-2023
tensor-isomorphism commitment in polynomial time. Their attack needs two structural
properties of the committed object, both orbit invariants: a *rigid* set of
minimum-rank points to anchor a target-rank-1 MinRank, and a *nontrivial stabilizer*
of the special orbit. Their committed object is a unit tensor
`t_b = Σ_{i=1}^{n−b} e_i ⊗ e_i ⊗ e_i`, which has a guaranteed `b`-dimensional space of
rank-0 points, exactly `n` rank-1 points, and a large stabilizer. Their own Remark 3
states the distinguisher "is not expected to have any impact" on random tensors.

EGOC-MCE-R commits a generic code element, not a unit tensor, so neither precondition
holds. This was checked at the real candidate shape (`22 × 28`, `k = 40`, over
`E` with `q = 2²⁴+43`), not extrapolated from a small surrogate:

- **No rank-0 point.** The generators are `E`-linearly independent (the keygen
  Frobenius-hull reject already enforces genericity), so the only codeword that is the
  zero matrix is the trivial one; the 2024/337 rank-0 distinguisher returns
  dimension 0.
- **No rigid low-rank anchor.** Rank-21 codewords exist and are findable, but they are
  a `≈ 2¹⁵³⁶` generic family (above), the opposite of the rigid `n`-element anchor set
  the attack needs, and search does not descend to corank 2; the exploitable low ranks
  sit on the `≥ 2¹⁰⁶⁴` MinRank surface.
- **Trivial stabilizer.** The stabilizer Lie algebra
  `{(X, Y) ∈ gl_mr(E) × gl_mc(E) : X·G_l + G_l·Y ∈ span{G_m} ∀ l}` equals exactly the
  scalar gauge `{(aI, bI)}` (`E`-dimension 2, non-scalar excess 0); no nontrivial
  permutation stabilizer exists. This was solved to completion at the production shape
  (2536 unknowns) and corroborated by testing 2609 permutation pairs.
- **Full-rank commitment image.** With the mask coordinates uniform over `E`,
  `Pr[rank(M) < min(mr,mc)] ≤ |E|^{−(mc−mr+1)} = 2⁻⁴⁸⁰`, so the opening proof's
  full-rank-orbit assumption (the simulator in [`SPEC.md`](SPEC.md)) holds with
  overwhelming probability.

So 2024/337's break does not apply, and recovery reduces to general Matrix Code
Equivalence. This is **PROVEN-outside-the-2024/337-regime**, not a proof of MCE
hardness in general. The four facts above are stated as a lemma in
[`formal/PROOFS.md`](formal/PROOFS.md) and machine-checked by
`egoc-attack::mce` (`stabilizer_is_scalar_gauge_only`, `commitment_image_is_full_rank`,
`corank_one_codewords_exist_but_do_not_anchor`).

## Brute force and the MEDS dimension comparison

Exhaustive search over `(S, T)` costs `|GL_mr(E) × GL_mc(E)| ≈ 2⁶⁹³⁶⁰` — a sanity
floor, never the bottleneck. As an independent cross-check,
`research/meds_compare.py` places the candidate against the vetted MEDS sets: its
matrix area `mr·mc = 682` exceeds MEDS-L3's 484 (192-bit), its field is about 4×
larger in bits, and its `k·log₂(q) = 46 × 24 = 1104` is roughly 3× MEDS-L5's
`30 × 11 = 330`. The Weil-restricted view (`44 × 62, k = 92`) dominates MEDS-L5
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
| MCE algebraic ≈ 2²⁰² (+ MEDS validation) | `research/meds_algebraic_estimator.py` | python3 |
| MCE comparison to MEDS sets | `research/meds_compare.py` | python3 |
| MinRank ≥ 2¹⁰⁶⁴ | `research/run_mce_estimator.py` | CryptographicEstimators |
| MCE solving-degree ladder | `research/groebner_mce.sage`, `export_msolve.py` | Sage / msolve |
| Lattice ≥ 2¹⁸⁶, statistical binding | `research/run_lattice_estimator.py` | Sage + lattice-estimator |
| Lattice core-SVP ballpark | `research/estimate_mlwe_coresvp.py` | python3 |

## Open items

- **Binding rank floor needs an independent derivation.** The `2²⁴⁰` corank-1 figure is
  the codimension/2 birthday balance, and reading NQT (ePrint 2024/368) showed it cannot
  be sourced from there — that paper's invariant attack is square-only and gives no
  rectangular exponent. Re-derive the codimension→cost mapping for a genuine rectangular
  MCE instance (or have it reviewed) to promote `2²⁴⁰` from ASSUMED to proven.
- **Algebraic band.** Run a Magma/Sage MEDS estimator and a mid-scale msolve solve on
  the asymmetric candidate shape to close the measured-vs-predicted solving-degree gap
  (`≈ −2`) and replace the `≈ 180–202` band with a single number; until then the
  algebraic surface is NEEDS-REVIEW. It is currently the cheapest classical attack on
  the matrix-code backend, so this is the most important MCE number to pin down.
- **Decisional hiding.** Settle decisional-MCE with the planted `2ℓ = 16` witness
  coordinates on the `F_q`-subline by reduction to search-MCE or external review; no
  rank/stabilizer/orbit invariant distinguishes it in experiments, but
  indistinguishability is unproven.
- **Shipped parameters.** `CodeParams::L1` (`22 × 31`, `k = 46`, with `Q_MCE_L1`) is the
  security-calibrated set; the demo binary and auction still use `CodeParams::DEMO`
  (`q = 4099`) by design, so a high-level path that selects `L1` for real use remains to
  be exposed.
- Re-run the lattice estimator after any parameter change (the lattice backend is
  unchanged by this MCE reparameterization).
