# Proofs

Complete proofs for the lemmas the EasyCrypt skeletons (`Hiding.ec`, `Binding.ec`,
`OpeningSigma.ec`) abbreviate with `admit`. These are paper proofs; the algebraic
and finite-instance content is additionally machine-checked by the Rust tests noted
at the end of each section. EasyCrypt mechanization remains the external step.

Notation as in [`../SPEC.md`](../SPEC.md): `E = F_q[t]/(t²+1)` with `q ≡ 3 (mod 4)`
(so the norm `N(a+bt)=a²+b²` is anisotropic); `Mat`/`GL` over `E`; the lattice ring
`R_q = Z_q[X]/(X²⁵⁶+1)`.

## 1. Encoder injectivity (binding base case) — unconditional

**Lemma 1.** Let `{G₀,…,G_{k-1}} ⊂ E^{mr×mc}` be `E`-linearly independent and
`Encode(c) = Σ_l c_l G_l`. Then `Encode` is injective on `E^k`. In particular the
EGOC-MCE-R message map `(w, ρ) ↦ Encode(x(w) ‖ ρ)` is injective.

*Proof.* `Encode` is `E`-linear, so it suffices that `ker = {0}`. If
`Σ_l c_l G_l = 0` then by linear independence every `c_l = 0`. The witness packing
`x(w) = (m₀,r₀,…)` is the identity coordinate map (injective), and the generators
are sampled in general position with `k < mr·mc`, hence independent except on a
measure-zero set that keygen rejects. ∎

*Machine-checked:* `egoc-sl2::encoder_is_injective`, `egoc-code::embed_is_linear`.

## 2. Lattice hiding ≤ Decision-MLWE

**Lemma 2.** Let the BDLOP commitment be `c1 = A1·r`, `c2 = A2·r + m` with
`B = [A1; A2] ∈ R_q^{(k_bind+k_msg)×l_rand}` public uniform, `r ← χ` short, and
`l_rand > k_bind + k_msg`. For every adversary `A`,
`Adv^{hiding}(A) ≤ Adv^{MLWE}(B(A))`, where Module-LWE is in knapsack form
`{(B, B·r) : r←χ} ≈_c {(B, u) : u←U}`.

*Proof.* Game₀ is the real hiding game. Game₁ replaces `B·r` by a uniform
`u = (u1, u2)`; the two games differ by exactly one decisional-MLWE sample on `B`
(a single sample is well-formed because `B` is wider than it is tall, `l_rand >`
height, so `r` is a genuine length-`l_rand` MLWE secret), giving
`|Pr[Game₀]−Pr[Game₁]| ≤ Adv^{MLWE}`. In Game₁, `c2 = u2 + m` with `u2` uniform and
independent of `m`, so `(c1, c2)` is independent of the challenge bit and
`Pr[Game₁] = 1/2`. Hence `Adv^{hiding} ≤ Adv^{MLWE}`. ∎

This is BDLOP18's hiding lemma; the shape `c2 = A2·r + m` (message in the clear,
`l_rand >` height) is what makes Game₁ valid — the property the predecessor's
SHADOW-SIS shape lacked.

*Machine-checked (structural):* `egoc-mlwe::message_added_in_the_clear`
(`Commit(m;r) − Commit(0;r) = (0, m)`), `message_is_masked_not_readable`,
`params_enforce_bdlop_shape`.

## 3. Lattice binding — statistical (stronger than computational MSIS)

**Lemma 3.** If `λ₁(Λ_q^⊥(A1)) > 2η·√(l_rand·N)`, where
`Λ_q^⊥(A1) = {v ∈ R_q^{l_rand} : A1·v ≡ 0}`, then the BDLOP commitment is perfectly
binding: no two distinct short openings of the same commitment exist.

*Proof.* Suppose `(r, m) ≠ (r', m')` both open `(c1, c2)`. Then
`A1·(r−r') = c1 − c1 = 0` and `m − m' = A2·(r'−r)`. The randomness is short
(`‖r‖∞, ‖r'‖∞ ≤ η`), so `‖r−r'‖₂ ≤ 2η·√(l_rand·N)`. If `r ≠ r'`, then `r−r'` is a
nonzero lattice vector of norm below `λ₁`, contradiction; so `r = r'`, whence
`m = m'`. ∎

For the tuned parameters `lattice-estimator` reports `rop = ∞` (no feasible short
collision), confirming `λ₁ ≫ 2η·√(l_rand·N)`. Absent the gap, binding still holds
computationally under Search-MSIS (a collision is a short MSIS solution for `A1`).

*Machine-checked:* `egoc-mlwe::non_short_randomness_rejected`,
`tampered_message_rejected`.

## 4. MCE binding ≤ MCE-collision (+ encoder injectivity)

**Lemma 4.** A code-mode opening of `C = S·M(c)·T` to a *different* message yields a
solver for MCE-collision. With the keys fixed, binding is unconditional by Lemma 1.

*Proof.* Two openings `(S, c)`, `(S', c')` of the same `C` give
`S·M(c)·T = S'·M(c')·T'`, hence `M(c') = (S'⁻¹S)·M(c)·(T T'⁻¹)`. If `c ≠ c'` this is
a nontrivial `GL×GL` equivalence carrying one structured codeword to another with
different planted coordinates — an MCE-collision instance, assumed hard. If instead
the keys are fixed (`S=S', T=T'`) then `M(c) = M(c')`, and Lemma 1 forces `c = c'`. ∎

## 5. Opening Σ — completeness

**Lemma 5.** The honest prover holding `(S, T)` with `M := S⁻¹·C·T⁻¹ ∈ span{Gₗ}`
makes the verifier accept on both challenges.

*Proof.* Per round the prover sends `D = Ŝ·C·T̂` (fresh `Ŝ, T̂ ← GL`) and `cmt =
H(D)`. On `b=0` it reveals `(Ŝ, T̂)`; the verifier recomputes `Ŝ·C·T̂ = D` and checks
`H(D) = cmt`. On `b=1` it reveals `(U', V', D) = (Ŝ·S, T·T̂, D)`; the verifier checks
`H(D) = cmt` and
`U'⁻¹·D·V'⁻¹ = (Ŝ·S)⁻¹(Ŝ·C·T̂)(T·T̂)⁻¹ = S⁻¹·C·T⁻¹ = M ∈ span{Gₗ}`. Both accept. ∎

## 6. Opening Σ — special soundness (2-extractor)

**Lemma 6.** From two accepting transcripts with the same `cmt` and different
challenges, an extractor recovers a witness, under collision resistance of `H`.

*Proof.* The `b=0` transcript gives `(Ŝ, T̂)` with `H(Ŝ·C·T̂) = cmt`; the `b=1`
transcript gives `(U', V', D)` with `H(D) = cmt` and `U'⁻¹·D·V'⁻¹ ∈ span{Gₗ}`. By
collision resistance, `D = Ŝ·C·T̂`. Substituting,
`(U'⁻¹·Ŝ)·C·(T̂·V'⁻¹) ∈ span{Gₗ}`. Output `(S̄, T̄) = ((U'⁻¹·Ŝ)⁻¹, (T̂·V'⁻¹)⁻¹)`;
then `S̄⁻¹·C·T̄⁻¹ = (U'⁻¹·Ŝ)·C·(T̂·V'⁻¹) ∈ span{Gₗ}`, a valid opening witness. A
prover that cannot extract answers at most one challenge per `cmt`, so per-round
cheating probability ≤ 1/2 and λ-round soundness error ≤ `2⁻λ` (plus the negligible
collision term; under Fiat–Shamir, via the standard forking/RO argument). ∎

*Machine-checked:* `egoc-proof::opening::special_soundness_extracts_opening`
(the extracted `(S̄, T̄)` reproduces a codeword), and `…::tampered_opening_rejected`.

## 7. Opening Σ — honest-verifier zero knowledge

**Lemma 7 (full-rank orbit).** `GL_mr(E) × GL_mc(E)` acts transitively on the set of
rank-`min(mr,mc)` matrices in `E^{mr×mc}` by `(U,V)·X = U·X·V`. Hence for any full-
rank `X`, the law of `U·X·V` with `(U,V) ← GL×GL` uniform is the uniform law on
full-rank matrices, independent of `X`.

**Lemma 8 (HVZK).** The simulator's transcripts are statistically indistinguishable
from honest ones; in particular the message leaks nothing.

*Proof.* On `b=0` the simulator picks `(Ŝ, T̂) ← GL`, sets `D = Ŝ·C·T̂`, `cmt = H(D)`
— identical to the honest distribution. On `b=1` the honest transcript reveals
`(U', V') = (Ŝ·S, T·T̂)`; as `(Ŝ, T̂)` range uniformly over `GL × GL`, so do
`(U', V')` (left/right translation is a bijection of `GL`), and `D = U'·M·V'` with
`M = S⁻¹·C·T⁻¹` the fixed message codeword. The simulator instead picks
`(U', V') ← GL` and a uniform codeword `W`, and sets `D = U'·W·V'`. Because `ρ` is
uniform and the norm is anisotropic, `M` is full rank except with negligible
probability, and so is a uniform `W`; by Lemma 7 both `U'·M·V'` and `U'·W·V'` are
uniform on full-rank matrices. The two transcripts therefore have statistical
distance `≤ Pr[M not full rank] + Pr[W not full rank] = negl`, and `D` (hence the
whole transcript) is independent of the message. Composition over `λ` rounds is the
standard hybrid; the Fiat–Shamir NIZK is zero-knowledge by programming the random
oracle. ∎

*Machine-checked:* `egoc-proof::opening::hvzk_simulated_rounds_verify`,
`egoc-proof::special_soundness_extracts_secret` (code-equivalence variant).

## Status

The reductions and Σ-protocol properties above are complete paper proofs, and their
algebraic/finite content is machine-checked by the cited Rust tests. What remains is
**mechanization in EasyCrypt** — turning these arguments into checked `.ec` scripts
(the skeletons in this directory hold the game/lemma structure with `admit` at the
steps these proofs discharge). That is tracked in [`../ROADMAP.md`](../ROADMAP.md).
The one genuinely assumed step is the hardness of MCE / decisional-MCE-with-planted-
structure (Lemma 4's premise), which no proof assistant settles — it needs the
cryptanalysis in [`../CRYPTANALYSIS.md`](../CRYPTANALYSIS.md) and external review.
