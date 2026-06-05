# Provably Fair Audit

**NIST SP 800-22 Statistical Fairness Verification for Crypto Casino Games**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=node.js)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/Verification-56%2F56%20passed-brightgreen)]()
[![NIST SP 800-22](https://img.shields.io/badge/Standard-NIST%20SP%20800--22-blue)]()
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Node.js%20crypto%20only)-orange)]()

> Most "provably fair" verification tools check a single hash.
> This tool runs **100,000+ outcomes** through **8 NIST-grade statistical tests** to determine if the RNG is genuinely random — not just hash-correct.

**Live audits:** [fairplayaudit.com](https://fairplayaudit.com)

---

## Why This Exists

"Provably fair" means you can verify the hash. It does **not** mean the outcomes are statistically fair.

A casino can use a valid HMAC-SHA256 implementation and still produce biased results through:
- Manipulated seed selection
- Non-uniform byte-to-float conversion
- Correlated nonce sequences
- House edge higher than advertised

This tool catches all of that. It generates 100,000+ outcomes from a seed pair, then runs the same statistical battery that NIST uses to certify random number generators.

## Supported Casinos

| Casino | Algorithm | Games | Status |
|--------|-----------|-------|--------|
| **Stake.com** | HMAC-SHA256 seed pairs | Dice, Limbo, Crash, CoinFlip, Roulette | Verified |
| **BC.Game** | HMAC-SHA256 (variant) | CoinFlip | Verified |
| **Roobet** | SHA256 hash chain | Crash | Verified |

Adding a new casino requires only implementing its byte-to-outcome mapping in `collector.js`.

## Quick Start

```bash
# Clone
git clone https://github.com/GuidoHam/provably-fair-audit.git
cd provably-fair-audit

# Run full audit (Stake, 100k outcomes per game, sample seeds)
node src/index.js

# Audit a specific casino with your own seeds
node src/index.js --casino "Stake" --server-seed "YOUR_REVEALED_SEED" --client-seed "YOUR_CLIENT_SEED" --count 250000

# Audit BC.Game
node src/index.js --casino-type bcgame --casino "BC.Game" --server-seed "SEED" --client-seed "CLIENT"

# Audit Roobet (hash chain)
node src/index.js --casino-type roobet --casino "Roobet" --start-hash "TERMINAL_HASH"

# Run only specific games
node src/index.js --games dice,crash --count 500000
```

**No dependencies to install.** Uses only Node.js built-in `crypto` module.

## Statistical Tests

All tests use **significance level alpha = 0.01** (99% confidence). A casino passes if **>= 75% of tests pass** per NIST recommendation.

### NIST SP 800-22 Rev. 1a Tests

| Test | What It Detects | Section |
|------|-----------------|---------|
| **Monobit (Frequency)** | Overall bias toward 0 or 1 | SP 800-22 Section 2.1 |
| **Runs Test** | Repeating patterns (e.g., 0-0-0-0-1-1-1-1) | SP 800-22 Section 2.3 |
| **Block Frequency** | Local bias within 128-bit blocks | SP 800-22 Section 2.2 |
| **Cumulative Sums** | Drift — outcomes trending in one direction | SP 800-22 Section 2.13 |

### Additional Statistical Tests

| Test | What It Detects |
|------|-----------------|
| **Chi-Square Goodness of Fit** | Distribution not matching expected uniform (100 bins) |
| **Kolmogorov-Smirnov** | Any deviation from uniform distribution (Stephens correction) |
| **Serial Correlation** | Lag-1 autocorrelation (sequential dependence) |
| **Runs Up/Down** | Trending sequences (Wald-Wolfowitz) |

### Game-Specific Tests

| Test | Applied To |
|------|-----------|
| **Dice Distribution** | Uniform across 0.00-99.99 |
| **Crash Instant-Bust Rate** | ~3.03% for Stake, ~5% for Roobet |
| **Coin Fairness** | ~50/50 within statistical tolerance |
| **Roulette Distribution** | Uniform across 0-36 |

## Architecture

```
src/
  index.js           # CLI + pipeline orchestrator
  collector.js       # HMAC-SHA256 outcome generation (Stake, BC.Game, Roobet)
  rng-tester.js      # 8 NIST + custom statistical tests, pure math
  report-generator.js # Professional HTML scorecard output

tests/
  verification-suite.js  # 56 assertions proving mathematical correctness

data/                # Generated outcome files (JSON)
reports/             # Generated HTML scorecards
```

### Pipeline

```
Seeds → Collector → 100k+ Raw Outcomes → RNG Tester → p-values → Report Generator → HTML Scorecard
```

Every step is deterministic. Given the same seeds, you get the exact same results. This is the whole point — reproducibility is proof.

## Verification Suite

The tool includes a comprehensive self-test that proves mathematical correctness:

```bash
node tests/verification-suite.js
```

**56 assertions** covering:
- Algorithm correctness (Stake, BC.Game, Roobet implementations match known outputs)
- NIST tests correctly pass on genuine random data
- NIST tests correctly **fail** on rigged data (all-constant, biased, alternating)
- Mathematical helper precision (erfc, lgamma, chiSquareCDF)
- bytesToFloat boundary conditions
- House edge rates match advertised values
- End-to-end pipeline integrity

If this suite passes, the tool is mathematically correct. Share these results with casinos as proof of methodology.

## Example Output

```
╔══════════════════════════════════════════════════════════╗
║        FAIRPLAY AUDIT — FAIRNESS SCORECARD GENERATOR    ║
╚══════════════════════════════════════════════════════════╝

Casino:      Stake
Sample Size: 100,000 per game
Games:       dice, limbo, crash, coinFlip, roulette
Total:       500,000 outcomes

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2/3: RUNNING STATISTICAL TESTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Running test suite for: DICE
✅ Chi-Square Goodness of Fit      p-value: 0.6821
✅ Kolmogorov-Smirnov (Uniformity) p-value: 0.9142
✅ NIST Monobit (Frequency)        p-value: 0.4210
✅ NIST Runs Test                  p-value: 0.3312
✅ NIST Block Frequency            p-value: 0.2891
✅ NIST Cumulative Sums            p-value: 0.5543
✅ Serial Correlation              p-value: 0.7821
✅ Runs Up/Down (Trend)            p-value: 0.1923

Score: 8/8 tests passed (100%)

═══════════════════════════════════════════════════════════
SCORECARD COMPLETE
═══════════════════════════════════════════════════════════
Casino:        Stake
Score:         10.0 / 10.0
Rating:        EXCELLENT
Tests:         37/37 passed
Outcomes:      500,000
```

## How Seeds Work

For the audit to be valid:

1. **Before playing:** You set a client seed. The casino shows you a SHA256 hash of the server seed (but not the seed itself).
2. **After playing:** The casino reveals the server seed. You verify: `SHA256(revealed_server_seed) === hash_they_showed_before`.
3. **This tool:** Takes the revealed server seed + your client seed, regenerates all outcomes, and tests them statistically.

The casino cannot change the server seed after the fact because the hash was committed upfront. This tool verifies they didn't just pass the hash check but also produced genuinely random outcomes.

## Reproducibility

Every audit is fully reproducible. To verify our published results:

```bash
# Example: Reproduce the Stake audit
node src/index.js \
  --casino "Stake" \
  --server-seed "THE_EXACT_SEED_FROM_OUR_REPORT" \
  --client-seed "fairplayaudit-2026" \
  --count 100000
```

You should get **identical** test results, p-values, and scores. If you don't, something is wrong — and that's a finding.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. We welcome:

- New casino algorithm implementations
- Additional statistical tests
- Bug reports with reproducible seed pairs
- Translations of audit reports

## License

[MIT](LICENSE) — Use it, fork it, audit your favorite casino.

## About

Built by [FairPlay Audit](https://fairplayaudit.com) — independent statistical auditing for provably fair crypto casinos. No casino pays us to audit them. We receive no compensation for favorable results. Affiliate links are only placed for casinos that pass the full test suite.

**Contact:** pitboss@fairplayaudit.com
