# Contributing to Provably Fair Audit

Thanks for your interest in improving casino fairness verification.

## How to Contribute

### Report a Bug
Open an issue with:
- The casino and game type
- Server seed + client seed (so we can reproduce)
- Expected vs. actual behavior
- Node.js version (`node --version`)

### Add a New Casino
1. Fork this repo
2. Add the casino's algorithm to `src/collector.js`
3. Add verification test cases to `tests/verification-suite.js` with known seed/outcome pairs
4. Submit a PR with a sample audit run

**Required for new casino support:**
- Link to the casino's official provably fair documentation
- At least one known seed pair with verified outcomes
- Algorithm implementation matching the casino's specification

### Add a Statistical Test
1. Implement in `src/rng-tester.js`
2. Add verification: test must PASS on uniform random data and FAIL on rigged data
3. Include academic reference (paper, NIST section, etc.)

### Improve Documentation
- Translations of the README
- Clearer explanations of statistical concepts
- Audit report templates

## Code Style

- ES Modules (`import`/`export`)
- No external dependencies (Node.js `crypto` only)
- All math functions must handle edge cases without producing NaN
- Every new feature needs a verification test

## Running Tests

```bash
node tests/verification-suite.js
```

All 56+ assertions must pass before submitting a PR.

## Code of Conduct

- Be constructive
- Back claims with data
- No casino promotion or affiliate spam in issues/PRs
