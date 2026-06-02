# Security-analysis scripts

These scripts produce and reproduce the numbers in
[`../docs/CRYPTANALYSIS.md`](../docs/CRYPTANALYSIS.md) and
[`../docs/SECURITY.md`](../docs/SECURITY.md). Some run with only `python3`; others
need SageMath, msolve, or CryptographicEstimators.

| Script | Produces | Needs |
|---|---|---|
| `meds_algebraic_estimator.py` | MCE algebraic cost ≈ 2²⁰⁸ (and the MEDS L1/L3/L5 validation) | python3 |
| `meds_compare.py` | comparison of the candidate to the vetted MEDS sets | python3 |
| `estimate_mlwe_coresvp.py` | dependency-free core-SVP ballpark for the lattice backend | python3 |
| `run_mce_estimator.py` | MinRank / Support-Minors cost (≥ 2¹⁰⁶⁴) | CryptographicEstimators |
| `run_lattice_estimator.py` | authoritative lattice cost (hiding ≥ 2¹⁸⁶, statistical binding) | SageMath + lattice-estimator |
| `groebner_mce.sage`, `export_msolve.py` | empirical MCE solving-degree ladder | SageMath / msolve |
| `mce_systems/*.txt`, `*.ms` | pre-generated bilinear MCE instances for the ladder | — |

## The headline numbers, and how to get them

**MCE algebraic cost (the binding attack).** `python3 meds_algebraic_estimator.py`
reimplements the tri-Hilbert-series estimate from the MEDS submission (§4.3.1) and
validates it by reproducing all three MEDS levels (L1 → 2¹⁴⁵, L3 → 2²¹⁵,
L5 → 2²⁹⁵). The candidate `(28, 22, 40)` lands at ≈ 2²⁰⁸. The cost is
field-independent, so `|E| ≈ 2⁴⁸` does not enter here.

**Rank surface.** `pip install cryptographic_estimators && python3
run_mce_estimator.py` gives MinRank/Support-Minors ≥ 2¹⁰⁶⁴ at the candidate. (The
pip-2.1.1 package has no MCE module; the script auto-detects one if a newer build
adds it.)

**Lattice backend.** Inside the lattice-estimator repository under Sage,
`sage run_lattice_estimator.py` confirms hiding ≥ 2¹⁸⁶ classical (dual-hybrid) and
statistical MSIS binding. `python3 estimate_mlwe_coresvp.py` is a quick offline
sanity check.

**Empirical solving degree.** `cargo run -p egoc-attack --example
export_mce_system` writes the bilinear systems; `python3 export_msolve.py` converts
them to msolve syntax; `msolve -f mce_systems/<name>.ms -v 2` shows the solving
degree rising (3 → 4 → …) and the cost exhausting memory at small sizes.

## What is still external

A run of the MEDS team's own Magma estimator would confirm the ≈ 2²⁰⁸ figure with
their tooling rather than our validated reimplementation, and external review of
decisional-MCE-with-planted-structure remains open. Both are tracked in
[`../docs/ROADMAP.md`](../docs/ROADMAP.md).
