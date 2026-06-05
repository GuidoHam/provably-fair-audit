/**
 * FairPlay Audit — RNG Statistical Tester
 *
 * Runs NIST SP 800-22 tests + custom gaming-specific tests
 * on collected casino outcomes. Returns p-values and pass/fail.
 *
 * Tests included:
 * - NIST Monobit Test (frequency balance)
 * - NIST Runs Test (pattern detection)
 * - NIST Block Frequency Test (local balance)
 * - NIST Cumulative Sums Test (drift detection)
 * - Chi-Square Goodness of Fit (distribution uniformity)
 * - Runs-Up/Down Test (trend detection)
 * - Serial Correlation Test (sequential dependence)
 * - Kolmogorov-Smirnov Test (distribution fit)
 */

import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHmac } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================
// STATISTICAL TEST FUNCTIONS
// ============================================================

/**
 * Chi-Square Goodness of Fit Test
 * Tests if observed frequencies match expected uniform distribution
 */
function chiSquareTest(outcomes, categories) {
  const n = outcomes.length;
  const observed = new Array(categories).fill(0);

  for (const val of outcomes) {
    const bin = Math.min(Math.floor(val * categories), categories - 1);
    observed[bin]++;
  }

  const expected = n / categories;

  // Guard: Chi-Square requires expected frequency >= 5 per bin
  if (expected < 5) {
    return {
      name: 'Chi-Square Goodness of Fit',
      statistic: 0,
      degreesOfFreedom: categories - 1,
      pValue: 0,
      pass: false,
      details: { reason: `Expected per bin (${expected.toFixed(1)}) < 5 — increase sample size or reduce categories` }
    };
  }

  let chiSq = 0;
  for (let i = 0; i < categories; i++) {
    chiSq += Math.pow(observed[i] - expected, 2) / expected;
  }

  const df = categories - 1;
  let pValue = 1 - chiSquareCDF(chiSq, df);

  // Clamp NaN/Infinity to 0 (extreme chi-square = clearly not uniform)
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;
  pValue = Math.max(0, Math.min(1, pValue));

  return {
    name: 'Chi-Square Goodness of Fit',
    statistic: parseFloat(chiSq.toFixed(4)),
    degreesOfFreedom: df,
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: {
      categories,
      sampleSize: n,
      expectedPerBin: parseFloat(expected.toFixed(2)),
      observedRange: [Math.min(...observed), Math.max(...observed)]
    }
  };
}

/**
 * Monobit Test (NIST SP 800-22 Section 2.1)
 * Converts outcomes to bits and checks proportion of 0s vs 1s
 */
function monobitTest(outcomes) {
  const bits = outcomesToBits(outcomes);
  const n = bits.length;
  const sum = bits.reduce((s, b) => s + (b === 1 ? 1 : -1), 0);
  const sObs = Math.abs(sum) / Math.sqrt(n);
  let pValue = erfc(sObs / Math.sqrt(2));
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;

  return {
    name: 'NIST Monobit (Frequency)',
    statistic: parseFloat(sObs.toFixed(6)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: {
      totalBits: n,
      ones: bits.filter(b => b === 1).length,
      zeros: bits.filter(b => b === 0).length,
      sum
    }
  };
}

/**
 * Runs Test (NIST SP 800-22 Section 2.3)
 * Counts uninterrupted sequences of identical bits
 */
function runsTest(outcomes) {
  const bits = outcomesToBits(outcomes);
  const n = bits.length;
  const pi = bits.filter(b => b === 1).length / n;

  // Pre-test: check if monobit passes
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(n)) {
    return {
      name: 'NIST Runs Test',
      statistic: 0,
      pValue: 0,
      pass: false,
      details: { reason: 'Monobit prerequisite failed', proportion: pi }
    };
  }

  let runs = 1;
  for (let i = 1; i < n; i++) {
    if (bits[i] !== bits[i - 1]) runs++;
  }

  const expected = 2 * n * pi * (1 - pi);
  const denominator = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
  const zObs = Math.abs(runs - expected) / denominator;
  let pValue = erfc(zObs);
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;

  return {
    name: 'NIST Runs Test',
    statistic: parseFloat(zObs.toFixed(6)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: { totalRuns: runs, expectedRuns: parseFloat(expected.toFixed(2)), proportion: parseFloat(pi.toFixed(6)) }
  };
}

/**
 * Block Frequency Test (NIST SP 800-22 Section 2.2)
 * Checks frequency within M-bit blocks
 */
function blockFrequencyTest(outcomes, blockSize = 128) {
  const bits = outcomesToBits(outcomes);
  const n = bits.length;
  const numBlocks = Math.floor(n / blockSize);

  if (numBlocks < 10) {
    return {
      name: 'NIST Block Frequency',
      statistic: 0,
      pValue: 0,
      pass: false,
      details: { reason: `Insufficient blocks (${numBlocks}, need 10+)` }
    };
  }

  let chiSq = 0;
  for (let i = 0; i < numBlocks; i++) {
    const block = bits.slice(i * blockSize, (i + 1) * blockSize);
    const pi = block.filter(b => b === 1).length / blockSize;
    chiSq += Math.pow(pi - 0.5, 2);
  }
  chiSq *= 4 * blockSize;

  const pValue = 1 - chiSquareCDF(chiSq, numBlocks);

  return {
    name: 'NIST Block Frequency',
    statistic: parseFloat(chiSq.toFixed(4)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: { blocks: numBlocks, blockSize }
  };
}

/**
 * Cumulative Sums Test (NIST SP 800-22 Section 2.13)
 * Checks for drift in the bit sequence
 */
function cumulativeSumsTest(outcomes) {
  const bits = outcomesToBits(outcomes);
  const n = bits.length;

  // Forward
  let maxExcursion = 0;
  let sum = 0;
  for (const bit of bits) {
    sum += bit === 1 ? 1 : -1;
    maxExcursion = Math.max(maxExcursion, Math.abs(sum));
  }

  // Approximate p-value
  const z = maxExcursion;
  let pValue = 0;
  const sqrtN = Math.sqrt(n);
  for (let k = Math.floor((-n / z + 1) / 4); k <= Math.floor((n / z - 1) / 4); k++) {
    pValue += normalCDF((4 * k + 1) * z / sqrtN) - normalCDF((4 * k - 1) * z / sqrtN);
  }
  pValue = 1 - pValue;
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;
  pValue = Math.max(0, Math.min(1, pValue));

  return {
    name: 'NIST Cumulative Sums',
    statistic: maxExcursion,
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: { maxExcursion, totalBits: n }
  };
}

/**
 * Serial Correlation Test
 * Checks if consecutive outcomes are correlated
 */
function serialCorrelationTest(outcomes) {
  const n = outcomes.length;
  const mean = outcomes.reduce((s, v) => s + v, 0) / n;

  let numerator = 0;
  let denominator = 0;
  for (let i = 0; i < n - 1; i++) {
    numerator += (outcomes[i] - mean) * (outcomes[i + 1] - mean);
  }
  for (let i = 0; i < n; i++) {
    denominator += Math.pow(outcomes[i] - mean, 2);
  }

  const r = denominator === 0 ? 0 : numerator / denominator;
  const z = r * Math.sqrt(n - 1);
  let pValue = 2 * (1 - normalCDF(Math.abs(z)));
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;

  return {
    name: 'Serial Correlation',
    statistic: parseFloat(r.toFixed(6)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: { correlation: parseFloat(r.toFixed(6)), zScore: parseFloat(z.toFixed(4)) }
  };
}

/**
 * Runs Up/Down Test
 * Checks for trends in consecutive values
 */
function runsUpDownTest(outcomes) {
  const n = outcomes.length;
  let runs = 1;

  for (let i = 1; i < n - 1; i++) {
    const prev = outcomes[i] > outcomes[i - 1];
    const next = outcomes[i + 1] > outcomes[i];
    if (prev !== next) runs++;
  }

  const expectedRuns = (2 * n - 1) / 3;
  const variance = (16 * n - 29) / 90;
  const z = (runs - expectedRuns) / Math.sqrt(variance);
  let pValue = 2 * (1 - normalCDF(Math.abs(z)));
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;

  return {
    name: 'Runs Up/Down (Trend)',
    statistic: parseFloat(z.toFixed(4)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: { runs, expectedRuns: parseFloat(expectedRuns.toFixed(2)) }
  };
}

/**
 * Kolmogorov-Smirnov Test
 * Tests if outcomes follow uniform distribution [0, 1)
 */
function ksTest(outcomes) {
  const n = outcomes.length;
  const sorted = [...outcomes].sort((a, b) => a - b);

  let dPlus = 0;
  let dMinus = 0;
  for (let i = 0; i < n; i++) {
    const empirical = (i + 1) / n;
    const theoretical = sorted[i];
    dPlus = Math.max(dPlus, empirical - theoretical);
    dMinus = Math.max(dMinus, theoretical - (i / n));
  }

  const d = Math.max(dPlus, dMinus);
  // Approximate p-value using Kolmogorov distribution
  const sqrtN = Math.sqrt(n);
  const lambda = (sqrtN + 0.12 + 0.11 / sqrtN) * d;
  let pValue = 0;
  for (let k = 1; k <= 100; k++) {
    pValue += Math.pow(-1, k - 1) * Math.exp(-2 * k * k * lambda * lambda);
  }
  pValue = 2 * pValue;
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;
  pValue = Math.max(0, Math.min(1, pValue));

  return {
    name: 'Kolmogorov-Smirnov (Uniformity)',
    statistic: parseFloat(d.toFixed(6)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: { dPlus: parseFloat(dPlus.toFixed(6)), dMinus: parseFloat(dMinus.toFixed(6)), sampleSize: n }
  };
}

// ============================================================
// GAME-SPECIFIC TESTS
// ============================================================

/**
 * Dice-specific test: Each value 0-100 should be roughly uniform
 */
function diceDistributionTest(outcomes) {
  const bins = 100;
  return chiSquareTest(outcomes.map(v => v / 100), bins);
}

/**
 * Crash-specific test: Check instant crash rate (~3.03%)
 */
function crashInstantRateTest(outcomes) {
  const n = outcomes.length;
  const crashes1x = outcomes.filter(v => v === 1).length;
  const observedRate = crashes1x / n;
  // Result = 1.00 from two sources:
  // 1) h % 33 === 0 (instant crash, house edge) → P = 1/33
  // 2) Multiplier rounds to 1.00 when h < e/100  → P = 1/100
  // Combined: P = 1/33 + 1/100 - 1/3300 = 132/3300 ≈ 4.0%
  const expectedRate = 132 / 3300;

  const z = (observedRate - expectedRate) / Math.sqrt(expectedRate * (1 - expectedRate) / n);
  let pValue = 2 * (1 - normalCDF(Math.abs(z)));
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;

  return {
    name: 'Crash: 1.00x Rate (House Edge)',
    statistic: parseFloat(z.toFixed(4)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: {
      observedRate: (observedRate * 100).toFixed(2) + '%',
      expectedRate: (expectedRate * 100).toFixed(2) + '%',
      crashes1x,
      total: n
    }
  };
}

/**
 * Coin flip: Should be ~50/50
 */
function coinFairnessTest(outcomes) {
  const n = outcomes.length;
  const heads = outcomes.filter(v => v === 0).length;
  const proportion = heads / n;

  const z = (proportion - 0.5) / Math.sqrt(0.25 / n);
  let pValue = 2 * (1 - normalCDF(Math.abs(z)));
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;

  return {
    name: 'Coin Flip: Fairness (50/50)',
    statistic: parseFloat(z.toFixed(4)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: {
      heads,
      tails: n - heads,
      proportion: (proportion * 100).toFixed(2) + '%'
    }
  };
}

/**
 * Roobet Crash: instant crash rate (~5.95%)
 * House edge: 1/20 via hash % 20 === 0, plus rounding to 1.00
 * Combined expected: 1/20 + (19/20)(1/100) ≈ 5.95%
 */
function roobetCrashRateTest(outcomes) {
  const n = outcomes.length;
  const crashes1x = outcomes.filter(v => v === 1 || v === 1.00).length;
  const observedRate = crashes1x / n;
  const expectedRate = 1/20 + (19/20) * (1/100); // ~0.0595

  const z = (observedRate - expectedRate) / Math.sqrt(expectedRate * (1 - expectedRate) / n);
  let pValue = 2 * (1 - normalCDF(Math.abs(z)));
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;

  return {
    name: 'Crash: 1.00x Rate (Roobet House Edge)',
    statistic: parseFloat(z.toFixed(4)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: {
      observedRate: (observedRate * 100).toFixed(2) + '%',
      expectedRate: (expectedRate * 100).toFixed(2) + '%',
      crashes1x,
      total: n
    }
  };
}

/**
 * Roulette: Each number 0-36 should appear ~equally
 */
function rouletteDistributionTest(outcomes) {
  const n = outcomes.length;
  const observed = new Array(37).fill(0);
  for (const v of outcomes) observed[v]++;

  const expected = n / 37;
  let chiSq = 0;
  for (let i = 0; i < 37; i++) {
    chiSq += Math.pow(observed[i] - expected, 2) / expected;
  }

  let pValue = 1 - chiSquareCDF(chiSq, 36);
  if (isNaN(pValue) || !isFinite(pValue)) pValue = 0;

  return {
    name: 'Roulette: Number Distribution (0-36)',
    statistic: parseFloat(chiSq.toFixed(4)),
    pValue: parseFloat(pValue.toFixed(6)),
    pass: pValue >= 0.01,
    details: {
      expected: parseFloat(expected.toFixed(2)),
      minObserved: Math.min(...observed),
      maxObserved: Math.max(...observed)
    }
  };
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/** Convert float outcomes [0,1) to bit array */
function outcomesToBits(outcomes) {
  const bits = [];
  for (const val of outcomes) {
    // Use 8 bits per outcome for statistical power
    const byte = Math.floor(val * 256);
    for (let b = 7; b >= 0; b--) {
      bits.push((byte >> b) & 1);
    }
  }
  return bits;
}

/** Complementary error function approximation */
function erfc(x) {
  const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741;
  const a4 = -1.453152027, a5 = 1.061405429, p = 0.3275911;
  const sign = x < 0 ? -1 : 1;
  x = Math.abs(x);
  const t = 1 / (1 + p * x);
  const y = 1 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
  return 1 - sign * y;
}

/** Normal CDF approximation */
function normalCDF(x) {
  return (1 + erf(x / Math.sqrt(2))) / 2;
}

/** Error function */
function erf(x) {
  return 1 - erfc(x);
}

/** Chi-Square CDF (regularized incomplete gamma function) */
function chiSquareCDF(x, k) {
  return gammainc(k / 2, x / 2);
}

/** Regularized lower incomplete gamma function (series expansion) */
function gammainc(a, x) {
  if (x === 0) return 0;
  if (x < 0) return 0;
  if (!isFinite(x) || !isFinite(a) || a <= 0) return NaN;

  // For very large x relative to a, the CDF is essentially 1
  if (x > a + 200) return 1;

  let sum = 0;
  let term = 1 / a;
  sum = term;

  for (let n = 1; n < 200; n++) {
    term *= x / (a + n);
    sum += term;
    if (Math.abs(term) < 1e-12 * Math.abs(sum)) break;
  }

  const result = sum * Math.exp(-x + a * Math.log(x) - lgamma(a));

  // Clamp to [0, 1] — numerical edge cases can overshoot
  if (isNaN(result)) return 1;
  return Math.max(0, Math.min(1, result));
}

/** Log-gamma function (Lanczos approximation) */
function lgamma(x) {
  const g = 7;
  const coef = [
    0.99999999999980993, 676.5203681218851, -1259.1392167224028,
    771.32342877765313, -176.61502916214059, 12.507343278686905,
    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7
  ];

  if (x < 0.5) {
    return Math.log(Math.PI / Math.sin(Math.PI * x)) - lgamma(1 - x);
  }

  x -= 1;
  let a = coef[0];
  const t = x + g + 0.5;
  for (let i = 1; i < g + 2; i++) {
    a += coef[i] / (x + i);
  }

  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}

// ============================================================
// RUN ALL TESTS FOR A GAME
// ============================================================

// Minimum sample sizes for statistical validity
const MIN_SAMPLE_SIZE = 10000;          // Absolute minimum
const RECOMMENDED_SAMPLE_SIZE = 100000; // NIST-recommended for reliable results
const NIST_MIN_BITS = 100000;           // NIST SP 800-22 recommends 10^6 bits minimum

function runTestSuite(gameName, outcomes, rawFloats, casinoType = 'stake') {
  console.log(`\nRunning test suite for: ${gameName.toUpperCase()}`);
  console.log(`Sample size: ${outcomes.length.toLocaleString()}`);

  // Sample size validation
  if (outcomes.length < MIN_SAMPLE_SIZE) {
    console.log(`⚠️  WARNING: Sample size ${outcomes.length.toLocaleString()} is below minimum (${MIN_SAMPLE_SIZE.toLocaleString()}).`);
    console.log(`   Results may not be statistically significant.`);
  }
  if (outcomes.length < RECOMMENDED_SAMPLE_SIZE) {
    console.log(`ℹ️  NOTE: NIST recommends ${RECOMMENDED_SAMPLE_SIZE.toLocaleString()}+ outcomes for reliable results.`);
  }
  const bitsAvailable = outcomes.length * 8;
  if (bitsAvailable < NIST_MIN_BITS) {
    console.log(`⚠️  WARNING: Only ${bitsAvailable.toLocaleString()} bits available (NIST recommends ${NIST_MIN_BITS.toLocaleString()}+).`);
  }

  console.log('─'.repeat(60));

  // KEY INSIGHT: Test the UNDERLYING random floats [0,1), not the game results.
  // The raw floats from HMAC-SHA256 should be uniformly distributed.
  // Game results are deterministic transforms — if the source is fair, the game is fair.
  // This is what real auditors (GLI, eCOGRA) do: test the RNG output, not the game math.

  const uniform = rawFloats || outcomes;

  const results = [];

  // === RNG QUALITY TESTS (on raw uniform floats) ===
  results.push(chiSquareTest(uniform, 100));
  results.push(ksTest(uniform));
  results.push(monobitTest(uniform));
  results.push(runsTest(uniform));
  results.push(blockFrequencyTest(uniform, 128));
  results.push(cumulativeSumsTest(uniform));
  results.push(serialCorrelationTest(uniform));

  // Runs Up/Down requires continuous data — skip for binary games (coinFlip)
  if (gameName !== 'coinFlip') {
    results.push(runsUpDownTest(uniform));
  }

  // Game-specific tests
  switch (gameName) {
    case 'crash':
      if (casinoType === 'roobet') {
        results.push(roobetCrashRateTest(outcomes));
      } else {
        results.push(crashInstantRateTest(outcomes));
      }
      break;
    case 'coinFlip':
      results.push(coinFairnessTest(outcomes));
      break;
    case 'roulette':
      results.push(rouletteDistributionTest(outcomes));
      break;
  }

  // Print results
  let passed = 0;
  for (const r of results) {
    const icon = r.pass ? '✅' : '❌';
    console.log(`${icon} ${r.name}`);
    console.log(`   p-value: ${r.pValue}  |  statistic: ${r.statistic}`);
    if (r.pass) passed++;
  }

  const score = passed / results.length;
  console.log('─'.repeat(60));
  console.log(`Score: ${passed}/${results.length} tests passed (${(score * 100).toFixed(0)}%)`);

  return {
    game: gameName,
    sampleSize: outcomes.length,
    tests: results,
    passed,
    total: results.length,
    score: parseFloat(score.toFixed(4)),
    overallPass: score >= 0.75 // At least 75% of tests must pass
  };
}

// ============================================================
// MAIN — Load data and run tests
// ============================================================

function main() {
  const dataDir = join(__dirname, '..', 'data');
  const gameFiles = ['dice', 'limbo', 'crash', 'coinFlip', 'roulette'];
  const allResults = {};

  for (const gameName of gameFiles) {
    try {
      const filePath = join(dataDir, `${gameName}_outcomes.json`);
      const data = JSON.parse(readFileSync(filePath, 'utf-8'));

      // Use rawFloats if available (correct for NIST tests on uniform data)
      // Fall back to outcomes only if rawFloats not present (legacy data)
      const rawFloats = data.rawFloats || null;
      if (!rawFloats) {
        console.log(`⚠️  ${gameName}: No rawFloats in data file — NIST tests will run on game results.`);
        console.log(`   Re-collect with index.js for accurate results.`);
      }
      const result = runTestSuite(gameName, data.outcomes, rawFloats);
      allResults[gameName] = result;
    } catch (err) {
      console.error(`Error testing ${gameName}: ${err.message}`);
    }
  }

  // Overall summary
  console.log('\n' + '═'.repeat(60));
  console.log('OVERALL FAIRNESS ASSESSMENT');
  console.log('═'.repeat(60));

  let totalPassed = 0;
  let totalTests = 0;

  for (const [game, result] of Object.entries(allResults)) {
    const icon = result.overallPass ? '✅' : '❌';
    console.log(`${icon} ${game}: ${result.passed}/${result.total} (${(result.score * 100).toFixed(0)}%)`);
    totalPassed += result.passed;
    totalTests += result.total;
  }

  const overallScore = totalPassed / totalTests;
  console.log('─'.repeat(60));
  console.log(`Overall: ${totalPassed}/${totalTests} tests passed (${(overallScore * 100).toFixed(0)}%)`);
  console.log(`Rating: ${overallScore >= 0.9 ? 'EXCELLENT' : overallScore >= 0.75 ? 'GOOD' : overallScore >= 0.5 ? 'FAIR' : 'POOR'}`);

  // Save results
  const outputPath = join(dataDir, 'test_results.json');
  const output = {
    auditId: `KYC-TEST-${Date.now()}`,
    timestamp: new Date().toISOString(),
    methodology: 'NIST SP 800-22 + Custom Gaming Tests',
    significanceLevel: 0.01,
    results: allResults,
    overall: {
      totalPassed,
      totalTests,
      score: parseFloat(overallScore.toFixed(4)),
      rating: overallScore >= 0.9 ? 'EXCELLENT' : overallScore >= 0.75 ? 'GOOD' : overallScore >= 0.5 ? 'FAIR' : 'POOR'
    }
  };

  writeFileSync(outputPath, JSON.stringify(output, null, 2));
  console.log(`\nResults saved to: ${outputPath}`);

  return output;
}

export { runTestSuite, chiSquareTest, monobitTest, runsTest, ksTest, blockFrequencyTest, serialCorrelationTest, runsUpDownTest, cumulativeSumsTest, MIN_SAMPLE_SIZE, RECOMMENDED_SAMPLE_SIZE };

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'));
if (isMain) main();
