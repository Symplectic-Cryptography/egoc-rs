# Formal methods

The mathematics is done on paper and machine-checked where it is algebraic; the
remaining step is mechanization in a proof assistant.

- **[`PROOFS.md`](PROOFS.md) — complete paper proofs** for every lemma the EasyCrypt
  skeletons abbreviate: encoder injectivity, lattice hiding ≤ Decision-MLWE,
  statistical MSIS binding, MCE binding ≤ MCE-collision, and the opening Σ's
  completeness / special-soundness / HVZK (including the full-rank-orbit lemma).
  Each proof cites the Rust test that machine-checks its algebraic content.
- **EasyCrypt skeletons** (`Hiding.ec`, `Binding.ec`, `OpeningSigma.ec`) hold the
  game and lemma structure, with `admit` at exactly the steps `PROOFS.md`
  discharges. They are **not yet machine-checked** — no EasyCrypt in this
  environment — so a formal-methods engineer turns the paper proofs into checked
  scripts and runs `easycrypt` to certify.

| Lemma (in `PROOFS.md`) | Claim | Paper proof | Machine-checked algebra | EasyCrypt |
|---|---|---|---|---|
| 1 | encoder injectivity ⇒ message-binding | ✅ | ✅ | skeleton |
| 2 | lattice hiding ≤ Decision-MLWE (BDLOP) | ✅ | ✅ (structural) | skeleton |
| 3 | lattice binding statistical / ≤ MSIS | ✅ | ✅ | skeleton |
| 4 | MCE binding ≤ MCE-collision | ✅ | — | skeleton |
| 5–8 | opening Σ: completeness, soundness, HVZK | ✅ | ✅ | skeleton |

## Proven / assumed / open

- **PROVEN on paper, algebra machine-checked:** the reductions and the Σ properties
  (Lemmas 1–8). EasyCrypt mechanization of these is the remaining formal step.
- **ASSUMED (hardness, not provable by any tool):** Decision-MLWE, Search-MSIS, and
  MCE / decisional-MCE-with-planted-structure; BLAKE3 as a random oracle /
  collision-resistant.
- **OPEN (cryptanalysis, not formal methods):** the concrete MCE bit cost — see
  [`../CRYPTANALYSIS.md`](../CRYPTANALYSIS.md) — and a third-party audit.

## How to check

```
easycrypt docs/formal/Hiding.ec
easycrypt docs/formal/Binding.ec
easycrypt docs/formal/OpeningSigma.ec
```

Cross-references the Rust: `egoc-sl2` (lift injectivity), `egoc-mlwe` (BDLOP shape,
`l_rand > height`), `egoc-proof::opening` (the Σ this file models).
