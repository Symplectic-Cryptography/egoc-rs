# Design

This document explains where egoc-rs comes from, what survived from the original
idea, and why the current construction looks the way it does. It is the "why"
companion to [`SPEC.md`](SPEC.md) (the "what") and [`SECURITY.md`](SECURITY.md)
(the "how safe").

## The two-time-physics inspiration, and what is real about it

Itzhak Bars' two-time physics reinterprets 3+1 space-time as a gauge-fixed shadow
of a 4+2 parent. The worldline theory carries an `Sp(2,ℝ)` gauge symmetry acting on
the phase-space pair `(X, P)`, and its three first-class constraints — `X·X`,
`X·P`, `P·P` — assemble into a single symmetric, traceless 2×2 matrix. Different
gauge fixings of the same parent produce physically different 3+1 systems; one time
direction is "hidden" by the gauge.

Exactly one piece of that picture transfers cleanly to cryptography. Encode a
message pair `(m, r)` as the block

```
B = [ m   r ]
    [ r  −m ]
```

This is the symmetric, traceless 2×2 matrix — the same algebraic object as the
`Sp(2,ℝ)` constraint triplet — and `Sp(2,Fq) ≅ SL(2,Fq)` is its finite-field
symmetry group. Its determinant `det(B) = −(m² + r²)` is the gauge invariant: the
Casimir, equivalently the norm of `m + r·t` in `F_q[t]/(t² + 1)`.

egoc-rs keeps `B` as a message **encoder** and nothing more. The block contributes
no hardness; it is an injective `F_q`-linear map from the witness into a matrix.
The security comes from elsewhere. Saying this plainly is deliberate: the previous
version's central mistake was to expect the physics analogy to carry cryptographic
weight.

## Why the predecessor (a public SL(2) gauge) failed

The first attempt (`egoc-rs`, the project this one replaces) committed as
`C = L(m, r)·g` with `g ∈ SL(2, F₂₅₇)` and published `g` alongside the commitment.
A review identified seven distinct problems; the first three are fatal on their own.

1. **The gauge was public.** With `g` known and invertible, `C·g⁻¹` recovers
   `(m, r)` by one 2×2 solve per index. Hiding was zero, for any randomness.
2. **A secret `g` would not have helped.** Publishing `H(g)` turns the hash into a
   confirmation oracle, and `|SL(2, F₂₅₇)| ≈ 2²⁴` is brute-forceable. Security would
   have collapsed to about 24 bits regardless of message length.
3. **The Casimir leaked.** `det` of each commitment block equals `−(m² + r²)`, an
   invariant of any determinant-one action — readable from the commitment with no
   secret at all.
4. **"Non-abelian, therefore Shor-proof" is a category error.** The secret entered
   only through right-multiplication and additive responses, both linear. The
   group's non-commutativity protected nothing.
5. **Perfect binding and strong hiding were claimed from the same public, invertible
   map** — a contradiction.
6. **The zero-knowledge proof was vacuous**, because the statement leaked its own
   witness.
7. **The aggregation, Fiat–Shamir, and field choice were all wrong**: the "IVC"
   re-committed the *sum* of witnesses (proving far less than advertised), the
   challenge sampling was biased, and `q = 257 ≡ 1 (mod 4)` makes `t² + 1` split, so
   `m² + r² = 0` has nontrivial solutions and blocks can be singular.

## What the rewrite changes: a two-sided GL action and Matrix Code Equivalence

Each fix targets a specific failure above.

- **Two secret keys, a two-sided action.** Commit as `C = S·M·T` with
  `S ∈ GLₘ(E)`, `T ∈ GLₙ(E)` secret. Recovering `(m, r)` becomes an instance of
  Matrix Code Equivalence, the problem behind MEDS — there is no public `g` to
  invert and the relation no longer leaks its witness, so (1), (4), and (6) are
  gone.
- **Keys are never hashed or published, and the group is large**
  (`|GLₘ(E) × GLₙ(E)| ≫ 2²⁵⁶`), which removes the confirmation oracle of (2).
- **Equivalence, not similarity.** A two-sided `GLₘ × GLₙ` action leaves only rank
  as an orbit invariant, and the rectangular shape (`mc − mr ≥ 6`, lifting the
  cheapest rank-collision codimension from 1 to 7) randomises even that — so the
  determinant/Casimir leak (3) disappears.
- **Named hardness, honest properties.** Hiding reduces to MCE (matrix-code backend)
  or decision-MLWE (lattice backend); binding is computational under MCE-collision
  or statistical under MSIS. No property is drawn from a contradictory source,
  resolving (5).
- **A non-vacuous, message-hiding opening proof** that proves knowledge of the
  secret equivalence `(S, T)` opening `C` without revealing the message
  (`egoc-proof`) — the proper fix for (6).
- **Honest aggregation, hardened Fiat–Shamir, anisotropic field**, against (7):
  batch proofs attest each individual opening rather than a sum; the challenge is
  bound to the full transcript and sampled without bias; and `q ≡ 3 (mod 4)` makes
  `E = F_q[t]/(t² + 1)` a field with an anisotropic norm.

## Two backends, and why

Two independent constructions share the in-house field, sampling, and transcript
code:

- **`mce` (EGOC-MCE-R)** keeps the `sl(2)`/two-time structure as the message
  encoder and reduces to Matrix Code Equivalence. It is the construction the project
  was built around, and the one with the more delicate parameter story — MEDS itself
  was re-tuned across NIST rounds — so its bit figure is an estimate rather than a
  settled standard.
- **`lattice` (SHADOW-SIS-FIX)** is a textbook BDLOP commitment over module-LWE and
  MSIS. The `sl(2)` skin plays no security role here. It exists so that a deployer
  who needs a number backed by the standard lattice estimator has one, while the
  MCE line matures.

They are not merged into a single security story. A deployer picks the assumption
they trust.

## How the design was vetted

The redesign was driven by an adversarial process rather than a single pass: a
panel proposed candidate constructions, a red team tried to break each, and a chair
selected and repaired the survivor. Every load-bearing claim was then checked
against runnable code — the regression suite in `egoc-attack` reproduces the old
breaks and confirms they fail against the new scheme, and the parameter analysis in
[`CRYPTANALYSIS.md`](CRYPTANALYSIS.md) is backed by `lattice-estimator`, msolve,
CryptographicEstimators, and a validated reimplementation of the MEDS algebraic
cost.
