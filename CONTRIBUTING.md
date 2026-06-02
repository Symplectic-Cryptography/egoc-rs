# Contributing

Build and test:

```bash
cargo test --workspace     # 84 tests must pass
cargo build --workspace    # must be warning-free
```

Two norms carried over from how this library was built:

- **Adversarial review.** Security-relevant changes are expected to come with a
  way to attack them. The `egoc-attack` crate is the home for regression attacks;
  a new claim should add a gate there (or to the `research/` scripts) that would
  fail if the claim were false.
- **Honesty labelling.** Every security statement is marked *proven*, *assumed*,
  or *needs review* in [`docs/SECURITY.md`](docs/SECURITY.md), and no bit figure is
  quoted without naming the tool that produced it. Keep new claims to that bar.

Please keep the documentation voice concrete and specific, and update the relevant
`docs/` file in the same change rather than appending to it.
