# Provably Fair Audit

**NIST SP 800-22 Statistical Fairness Verification for Crypto Casino Games**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=node.js)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/Verification-167%2F167%20passed-brightgreen)]()
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

## Statistical Tests (Community Edition)

This open-source tool includes **8 foundational tests** — enough to catch obvious manipulation, but not the full picture.

All tests use **significance level alpha = 0.01** (99% confidence). A casino passes if **>= 75% of tests pass** per NIST recommendation.

### Included: NIST SP 800-22 Core Tests

| Test | What It Detects | Section |
|------|-----------------|---------|
| **Monobit (Frequency)** | Overall bias toward 0 or 1 | SP 800-22 Section 2.1 |
| **Runs Test** | Repeating patterns (e.g., 0-0-0-0-1-1-1-1) | SP 800-22 Section 2.3 |
| **Block Frequency** | Local bias within 128-bit blocks | SP 800-22 Section 2.2 |
| **Cumulative Sums** | Drift — outcomes trending in one direction | SP 800-22 Section 2.13 |
| **Chi-Square Goodness of Fit** | Distribution not matching expected uniform (100 bins) | — |
| **Kolmogorov-Smirnov** | Any deviation from uniform distribution (Stephens correction) | — |
| **Serial Correlation** | Lag-1 autocorrelation (sequential dependence) | — |
| **Runs Up/Down** | Trending sequences (Wald-Wolfowitz) | — |

### Not Included: What the Full Audit Adds

Our published audits on [fairplayaudit.com](https://fairplayaudit.com) use an **extended proprietary suite of 30+ tests** that goes far beyond basic RNG verification:

| Category | What It Catches | Why It Matters |
|----------|-----------------|----------------|
| **Advanced NIST Tests** | Approximate Entropy, Linear Complexity, Maurer's Universal, Non-overlapping Templates, Longest Run | Detects subtle non-randomness that basic tests miss — patterns a casino could exploit without failing simple checks |
| **Cross-Game Correlation** | Same seed producing correlated outcomes across Dice, Crash, Roulette simultaneously | A casino could pass per-game tests while leaking information between games |
| **Seed Rotation Analysis** | Suspicious timing of seed changes, unusually short seed lifespans after big wins | If a casino rotates seeds only after players win, that's a red flag no single-seed test catches |
| **Time-Series Drift** | Outcomes shifting over time — fair for 10k rounds, then gradually biased | A slow drift is invisible in aggregate statistics but devastates long-term players |
| **Crash Normalization** | Non-standard multiplier distributions, hidden house edge above advertised rate | Many crash games claim 1-3% edge but the actual math shows 5-8% |
| **Behavioral Triggers** | Outcome patterns changing after deposits, after win streaks, after VIP tier changes | The most sophisticated manipulation — personalized unfairness |
| **Multi-Session Persistence** | Whether randomness degrades across sessions with the same player | Tests if the casino "remembers" winning players |

**Why this matters:** A casino that passes all 8 tests in this tool is *probably* fair — but "probably" isn't good enough when real money is on the line. The [full audit reports](https://fairplayaudit.com) test deeper, across more dimensions, with proprietary detection methods we don't publish.

> **Think of it this way:** This tool is a breathalyzer. Our full audit is a blood test. Both detect alcohol — but only one holds up in court.

### Game-Specific Tests (included)

| Test | Applied To |
|------|-----------|
| **Dice Distribution** | Uniform across 0.00-100.00 |
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
  verification-suite.js  # 94 assertions proving mathematical correctness
  cross-validation.js    # 73 assertions: audit tool ↔ verifier consistency

data/                # Generated outcome files (JSON)
reports/             # Generated HTML scorecards
```

### Pipeline

```
Seeds → Collector → 100k+ Raw Outcomes → RNG Tester → p-values → Report Generator → HTML Scorecard
```

Every step is deterministic. Given the same seeds, you get the exact same results. This is the whole point — reproducibility is proof.

## Verification Suite

The tool includes two comprehensive test suites that prove mathematical correctness:

```bash
# Verify all algorithms and statistical tests (94 assertions)
node tests/verification-suite.js

# Cross-validate audit tool ↔ blog verifier consistency (73 assertions)
node tests/cross-validation.js
```

**167 total assertions** covering:

### verification-suite.js (94 tests)
- Stake/BC.Game/Roobet algorithm correctness against known reference values
- RFC 4231 HMAC-SHA256 test vectors (OpenSSL standard compliance)
- NIST tests correctly pass on genuine random data
- NIST tests correctly **fail** on rigged data (constant, biased, alternating, patterned)
- Mathematical helper precision (erfc, lgamma, chiSquareCDF, normalCDF)
- bytesToFloat boundary conditions and precision proofs
- House edge rates match advertised values (statistical z-tests)
- NaN/Infinity robustness on all edge cases
- Adversarial inputs: empty seeds, Unicode, 10k-char seeds, extreme nonces
- Cross-game determinism and reproducibility proofs
- End-to-end pipeline integrity

### cross-validation.js (73 tests)
- **Crash**: 10,000 nonces — audit tool vs verifier produce identical results
- **Dice**: 10,000 nonces — audit tool vs verifier produce identical results
- **Crash formula algebraic proof**: proves `floor((100*e-h)/(e-h))/100` is not equivalent to `floor(e/(e-h)*100)/100`
- **bytesToFloat precision**: 9 reference value checks
- **Range proofs**: 100,000 outcomes each for Crash (≥1.00, no NaN) and Dice ([0,100])
- **House edge statistical test**: z-test against 1/33 expected rate (within 3σ)
- **RFC 4231**: 3 HMAC-SHA256 test vectors
- **NIST battery on 50,000 HMAC outcomes**: 8/8 tests pass
- **Rigged data detection**: 4/4 core tests catch constant sequences
- **Mines permutation validity**: 5,000 checks across all mine counts
- **Roobet hash chain**: progression + house edge rate
- **Determinism**: 20,000 duplicate runs with zero differences

If both suites pass, the tool is mathematically correct and consistent with the live verifier at [fairplayaudit.com/verify](https://blog.fairplayaudit.com/verify/).

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

## Community Edition vs. Full Audit

| | This Tool (Free) | Full Audit (fairplayaudit.com) |
|---|---|---|
| **Tests** | 8 core NIST tests | 30+ tests incl. proprietary |
| **Scope** | Single seed pair | Multiple sessions, time-series, cross-game |
| **Output** | Pass/Fail + p-values | Detailed report with risk assessment |
| **Detection** | Basic RNG manipulation | Behavioral triggers, drift, correlation |
| **Casino coverage** | DIY (bring your own seeds) | Pre-audited with published results |
| **Updates** | Community-driven | Continuously improved |

**Want the full picture?** Read our published audits at [fairplayaudit.com](https://fairplayaudit.com) — or submit your own seeds for a professional assessment.

## About

Built by [FairPlay Audit](https://fairplayaudit.com) — independent statistical auditing for provably fair crypto casinos. Run by an ex-pit boss with 10+ years of casino operations experience.

No casino pays us to audit them. We receive no compensation for favorable results. Affiliate links are only placed for casinos that pass the full 30+ test suite.

**Full audits:** [fairplayaudit.com](https://fairplayaudit.com)
**Contact:** pitboss@fairplayaudit.com
**Telegram:** Coming soon
