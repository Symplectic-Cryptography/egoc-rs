# FAQ and glossary

### Does the two-time-physics structure provide any security?

No. The `sl(2)` block `[[m, r], [r, −m]]` is an injective message encoder and
nothing more; it contributes zero hardness. Security comes from Matrix Code
Equivalence (matrix-code backend) or module-LWE/MSIS (lattice backend). The physics
is where the construction *came from*, not where its security *rests*. The
predecessor's central error was to confuse the two.

### Which backend should I use?

If you need a security level you can defend with standard tooling today, use the
**lattice** backend — its parameters are confirmed by `lattice-estimator`
(≥ 2¹⁸⁶ classical, ≈ 2¹⁴⁶ quantum). If you want the matrix-code construction and can
accept that its bit figure is an estimate pending independent confirmation, use the
**matrix-code** backend.

### Why two backends at all?

They rest on different assumptions. Module-LWE/MSIS is battle-tested; Matrix Code
Equivalence is younger but actively studied (it is the basis of the NIST candidate
MEDS). Offering both lets a deployer pick the assumption they trust without giving
up the work that went into either.

### Is the matrix-code bit number from the MEDS Magma estimator?

No. It is a faithful reimplementation of the MEDS algebraic-attack methodology
(`research/meds_algebraic_estimator.py`), validated by reproducing the three MEDS
NIST levels (L1 → 2¹⁴⁵, L3 → 2²¹⁵, L5 → 2²⁹⁵). An independent run with the MEDS
team's own tooling is listed as open work in [`ROADMAP.md`](ROADMAP.md).

### Has it been audited?

No. There has been no third-party security review. Treat it as research-grade.

### Is it constant-time?

Field inversion uses a fixed-length ladder and secret comparisons go through
`subtle`, so the lowest layer avoids data-dependent branches. A full side-channel
review of the higher layers has not been done.

## Glossary

The project mixes physics and cryptography vocabulary. The terms you will meet:

| Term | Meaning here |
|---|---|
| two-time physics | Bars' framework reading 3+1 space-time as a gauge-fixed shadow of 4+2; the source of the `sl(2)` block |
| `Sp(2,ℝ)` / `SL(2)` | the gauge group whose finite analogue acts on the block; structural only |
| Casimir | the gauge invariant `det(B) = −(m² + r²)`; here the norm of `m + r·t` |
| module-LWE / MSIS | the lattice assumptions behind the `lattice` backend |
| BDLOP | the lattice commitment construction (Baum–Damgård–Lyubashevsky–Oechsner–Peikert) |
| Matrix Code Equivalence (MCE) | given two matrix codes, find the two-sided equivalence between them; the `mce` backend's assumption |
| MEDS | the NIST signature candidate built on MCE; the source of the parameter methodology |
| Frobenius hull | `code ∩ dual`; a non-trivial hull enables Highway-to-Hull/CDG attacks, so keygen rejects it |
| NUMS | "nothing up my sleeve" — public parameters derived from a published seed |
