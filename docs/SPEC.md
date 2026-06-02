# Specification

Precise construction of both backends. Notation follows the code: `Fp<Q>` is the
prime field, `Fp2<Q>` the extension, `Mat<Q>` a matrix over the extension.

## 1. Arithmetic foundation (`egoc-field`, `egoc-linalg`)

**Prime field.** `Fp<Q>` is `Z/QZ` with the prime fixed as a compile-time constant,
so `Fp<101>` and `Fp<4099>` are distinct types and mixing them is a compile error.
Inversion uses Fermat's little theorem with a fixed-length ladder, so its running
time does not depend on the input.

**Quadratic extension.** `E = Fp2<Q> = F_q[t]/(t² + 1)`, with elements `c0 + c1·t`.
A compile-time guard rejects any `Q ≢ 3 (mod 4)`, because `t² + 1` is irreducible
exactly when `−1` is a non-residue. Then the norm `N(c0 + c1·t) = c0² + c1²` is
anisotropic — zero only at the origin — which is the property the predecessor's
`q = 257 ≡ 1 (mod 4)` lacked. The MCE backend uses `q = 16777259 = 2²⁴ + 43`
(`Q_MCE_L1`), giving `|E| = q² ≈ 2⁴⁸`; the demo/test field is `q = 4099`.

**Matrices over `E`.** `Mat<Q>` provides multiplication, rank, determinant, inverse
(Gauss–Jordan), the two-sided product `S·M·T`, uniform-invertible (`GLₙ`) rejection
sampling, the Frobenius hull dimension `k − rank(Gram)`, and code-membership
`in_span`.

## 2. The `sl(2)` encoder (`egoc-sl2`)

A witness is `w = (m, r) ∈ F_q^ℓ × F_q^ℓ`, zeroized on drop. The encoder packs it
into the coordinate vector `x(w) = (m₀, r₀, …, m_{ℓ−1}, r_{ℓ−1})`, the entries of
the `sl(2)` blocks `Bᵢ = [[mᵢ, rᵢ], [rᵢ, −mᵢ]]`. The map is injective and
`F_q`-linear; the block determinant `−(mᵢ² + rᵢ²)` is never exported. This crate
contributes no hardness — it only fixes the message layout.

## 3. Matrix-code backend — EGOC-MCE-R: a Matrix Code Equivalence commitment

**Public code.** A nothing-up-my-sleeve generator set `{G₀, …, G_{k−1}}`,
`Gₗ ∈ E^{mr×mc}`, is expanded from a published seed with a BLAKE3 XOF
(`GenSet::expand`). The code dimension is kept far below the ambient dimension,
`k ≪ mr·mc`. Keygen rejects any seed whose code has a non-trivial Frobenius hull
(`expand_checked`), a defence against hull/CDG attacks.

**Message embedding.** `M = Σₗ cₗ Gₗ`, where the first `2ℓ` coefficients are the
witness coordinates `x(w)` (each `F_q` value lifted to `E`) and the remaining
`k − 2ℓ` are fresh uniform masking randomness `ρ ∈ E` (`GenSet::embed`).

**Commitment.** Sample secret `S ∈ GL_mr(E)`, `T ∈ GL_mc(E)` and form `C = S·M·T`.
Two presentations:

- *hash mode* (`egoc-commit`): publish `com = BLAKE3(dom ‖ q,ℓ,k,mr,mc ‖ C)`. The
  pushed basis `{S·Gₗ·T}` is never published. Hiding before opening is BLAKE3
  hiding; binding is BLAKE3 collision resistance plus the injectivity of the
  encoder. Opening reveals `(w, ρ, seed_S, seed_T)` and the verifier recomputes.
- *code mode* (`egoc-proof::opening`): publish `C` itself. Hiding of `w` rests on
  Matrix Code Equivalence — recovering `(m, r)` from `C` and the public code is the
  MCE problem. This is the mode the zero-knowledge opening uses.

**Hardness (MCE).** Given the public code `C₀ = span{Gₗ}` and the pushed code
`C = span{S·Gₗ·T}`, recover `(S, T) ∈ GL_mr × GL_mc`. The only orbit invariant of
the two-sided `GL × GL` action is matrix rank, and the rank-generic regime
(`k ≪ mr·mc`) carries no low-rank codewords for rank attacks to exploit.

**Zero-knowledge opening (`prove_opening`).** A binary-challenge Σ-protocol over `λ`
rounds proving knowledge of `(S, T)` with `S⁻¹·C·T⁻¹ ∈ span{Gₗ}` — that `C` is a
well-formed commitment the prover can open — without revealing the message. Per
round, commit `D = Ŝ·C·T̂` for a fresh equivalence and send `H(D)`; on challenge 0
reveal `(Ŝ, T̂)`, on challenge 1 reveal `(Ŝ·S, T·T̂, D)` and check
`(Ŝ·S)⁻¹·D·(T·T̂)⁻¹ ∈ span{Gₗ}`. Soundness is `2⁻λ`; the extractor recovers `(S, T)`
from two transcripts that differ on one round; the simulator is exact because the
`GL × GL` orbit of a full-rank `M` is message-independent (anisotropy makes `M`
full-rank with overwhelming probability).

**Code-equivalence identification (`egoc-proof::{keygen,prove,verify}`).** The same
Σ shape also proves a secret equivalence between two *public* codes — the MEDS
identification scheme — used when the pushed code is itself the public object.

**Batch aggregation (`egoc-aggregate`).** One Fiat–Shamir challenge derived from the
whole batch transcript drives a `λ`-round opening sub-proof per commitment, proving
knowledge of *each* opening. Soundness is `2⁻λ` per commitment; this is not folding
and not a sum, and proof size is linear in the number of commitments.

## 4. Lattice backend — SHADOW-SIS-FIX: a module-LWE / MSIS (BDLOP) commitment

**Ring.** `R_q = Z_q[X]/(X²⁵⁶ + 1)`, `q = 8380417` (the Dilithium prime).
Multiplication is schoolbook negacyclic; an NTT is a deferred performance item.

**BDLOP commitment.** With public matrices `A1 ∈ R_q^{k_bind×l_rand}`,
`A2 ∈ R_q^{k_msg×l_rand}` and short randomness `r` (`‖r‖∞ ≤ η`):

```
c1 = A1·r            (binding part)
c2 = A2·r + m        (message added in the clear)
```

The shape invariant `l_rand > k_bind + k_msg` makes `[A1; A2]·r` a genuine MLWE
sample, which is what hides `m`. The tuned parameters are
`k_bind = 3, k_msg = 1, l_rand = 5, η = 2`. Hiding reduces to decision-MLWE; binding
is statistical (the shortest vector of `ker(A1)` exceeds twice the opening norm, so
no two short openings collide). Verification rejects any opening whose randomness is
not short.

**Zero-knowledge opening.** A Fiat–Shamir-with-aborts Σ in the Lyubashevsky style:
mask `y`, send `w = A1·y`, take a sparse-ternary challenge `c` from the full
transcript, respond `z = y + c·r`, and accept only when `‖z‖∞ ≤ B_z` (bounded-
uniform rejection makes the accepted `z` independent of `r`, giving honest-verifier
zero knowledge). Verification checks the norm bound and `A1·z = w + c·c1`.

## 5. Parameters and sizes

| | MCE candidate | lattice (tuned) |
|---|---|---|
| field | `E`, `q = 16777259`, `|E| ≈ 2⁴⁸` | `R_q`, `q = 8380417`, `N = 256` |
| dimensions | `mr = 22, mc = 28, k = 40, ℓ = 8` | `k_bind = 3, k_msg = 1, l_rand = 5, η = 2` |
| commitment | hash 32 B, or `C ≈ mr·mc·6` B in code mode | `(c1, c2) ≈ (k_bind + k_msg)·N·⌈log₂q⌉` |

The demo/test parameter sets are smaller and exist only for fast tests and the
auction example; they are not security sizes. `CodeParams::DEMO` is
`mr = 8, mc = 9, k = 16` (the auction runs it at `λ = 32`); `Params::DEMO` is the
lattice set above.
Serialization (`to_bytes`/`from_bytes`) is provided for `Fp2`, `Mat`, the BDLOP
`Commitment`, and the MCE `OpeningProof`, each with round-trip tests.
