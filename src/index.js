/**
 * FairPlay Audit — Scorecard Generator (Main)
 *
 * Complete pipeline: Collect → Test → Report
 * NIST SP 800-22 compliant statistical fairness verification
 *
 * Usage:
 *   node src/index.js                    # Run with sample seeds
 *   node src/index.js --casino "Stake"   # Set casino name
 *   node src/index.js --count 500000     # Set sample size
 *
 * https://fairplayaudit.com
 */

import { createHmac, createHash } from 'crypto';
import { writeFileSync, readFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Import our modules
import { collectOutcomes, hashServerSeed, games, collectBcgameOutcomes, roobetCollectCrash, ROOBET_FIRST_GAME } from './collector.js';
import { runTestSuite } from './rng-tester.js';
import { generateReport } from './report-generator.js';

// ============================================================
// PARSE CLI ARGUMENTS
// ============================================================

function parseArgs() {
  const args = process.argv.slice(2);
  const config = {
    casino: 'Sample Casino',
    casinoType: 'stake',  // stake | bcgame | roobet
    serverSeed: 'a]V~d#W3t=+W5L$@gM4%ho6gm&!G^bSo',
    clientSeed: 'fairplayaudit-2026',
    startHash: ROOBET_FIRST_GAME,  // For Roobet hash chain
    count: 100000,
    games: null  // Will be set based on casinoType if not provided
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--casino': config.casino = args[++i]; break;
      case '--casino-type': config.casinoType = args[++i]; break;
      case '--server-seed': config.serverSeed = args[++i]; break;
      case '--client-seed': config.clientSeed = args[++i]; break;
      case '--start-hash': config.startHash = args[++i]; break;
      case '--count': config.count = parseInt(args[++i]); break;
      case '--games': config.games = args[++i].split(','); break;
    }
  }

  // Set default games per casino type if not explicitly provided
  if (!config.games) {
    switch (config.casinoType) {
      case 'bcgame': config.games = ['coinFlip']; break;
      case 'roobet': config.games = ['crash']; break;
      default: config.games = ['dice', 'limbo', 'crash', 'coinFlip', 'roulette']; break;
    }
  }

  return config;
}

// ============================================================
// MAIN PIPELINE
// ============================================================

async function main() {
  const config = parseArgs();

  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║        FAIRPLAY AUDIT — FAIRNESS SCORECARD GENERATOR     ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log();
  console.log(`Casino:      ${config.casino}`);
  console.log(`Type:        ${config.casinoType}`);
  if (config.casinoType === 'roobet') {
    console.log(`Start Hash:  ${config.startHash.slice(0, 32)}...`);
  } else {
    console.log(`Seed Hash:   ${hashServerSeed(config.serverSeed).slice(0, 32)}...`);
    console.log(`Client Seed: ${config.clientSeed}`);
  }
  console.log(`Sample Size: ${config.count.toLocaleString()} per game`);
  console.log(`Games:       ${config.games.join(', ')}`);
  console.log(`Total:       ${(config.count * config.games.length).toLocaleString()} outcomes`);
  console.log();

  // ---- AUDIT PROTOCOL ----
  // Document seed selection methodology for transparency
  const auditProtocol = {
    auditId: `FPA-${Date.now()}`,
    timestamp: new Date().toISOString(),
    casino: config.casino,
    methodology: {
      standard: 'NIST SP 800-22 Rev. 1a',
      significanceLevel: 0.01,
      passThreshold: '75% of tests',
      seedSelection: config.casinoType === 'roobet'
        ? 'Hash chain starting from casino-provided terminal hash. Chain verified via SHA256(current) = previous.'
        : 'Server seed revealed by casino after seed rotation. Client seed set by auditor before play. No cherry-picking: ALL outcomes from the seed pair are tested.',
      sampleSize: `${config.count.toLocaleString()} outcomes per game (${(config.count * 8).toLocaleString()} bits)`,
      minimumRequired: '100,000 outcomes (800,000 bits) per NIST recommendation',
      testsApplied: [
        'Chi-Square Goodness of Fit (100 bins)',
        'Kolmogorov-Smirnov Uniformity (Stephens correction)',
        'NIST Monobit / Frequency (SP 800-22 §2.1)',
        'NIST Runs Test (SP 800-22 §2.3)',
        'NIST Block Frequency (SP 800-22 §2.2, M=128)',
        'NIST Cumulative Sums (SP 800-22 §2.13)',
        'Serial Correlation (lag-1 autocorrelation)',
        'Runs Up/Down (Wald-Wolfowitz)',
        'Game-specific: House edge rate, fairness distribution'
      ],
      dataIntegrity: 'Raw HMAC outputs stored alongside game results. All computations reproducible from seed pair.',
      independence: 'FairPlay Audit receives no payment from audited casinos. Affiliate links are ONLY placed for casinos that pass the audit.'
    }
  };

  console.log('━'.repeat(60));
  console.log('AUDIT PROTOCOL');
  console.log('━'.repeat(60));
  console.log(`Audit ID:    ${auditProtocol.auditId}`);
  console.log(`Standard:    ${auditProtocol.methodology.standard}`);
  console.log(`Seed Policy: ${auditProtocol.methodology.seedSelection.slice(0, 80)}...`);
  console.log(`Sample:      ${auditProtocol.methodology.sampleSize}`);
  console.log();

  // ---- STEP 1: COLLECT ----
  console.log('━'.repeat(60));
  console.log('STEP 1/3: COLLECTING OUTCOMES');
  console.log('━'.repeat(60));

  const dataDir = join(__dirname, '..', 'data');
  mkdirSync(dataDir, { recursive: true });

  const allOutcomes = {};

  for (const gameName of config.games) {
    let outcomes;

    if (config.casinoType === 'roobet') {
      // Roobet uses hash chain, not seed pairs
      outcomes = roobetCollectCrash(config.startHash, config.count);
    } else if (config.casinoType === 'bcgame') {
      // BC.Game uses same HMAC structure but different game math
      outcomes = collectBcgameOutcomes({
        serverSeed: config.serverSeed,
        clientSeed: config.clientSeed,
        gameName,
        count: config.count
      });
    } else {
      // Stake (default)
      outcomes = collectOutcomes({
        serverSeed: config.serverSeed,
        clientSeed: config.clientSeed,
        gameName,
        count: config.count
      });
    }

    allOutcomes[gameName] = {
      results: outcomes.map(o => o.result),
      rawFloats: outcomes.map(o => o.raw)
    };

    // Build meta info based on casino type
    const meta = {
      casino: config.casino,
      game: gameName,
      sampleSize: outcomes.length,
      collectedAt: new Date().toISOString(),
      collector: 'FairPlay Audit Scorecard Tool v2.0'
    };

    if (config.casinoType === 'roobet') {
      meta.startHash = config.startHash;
      meta.salt = 'Roobet public salt (see report)';
      meta.method = 'Hash chain + HMAC-SHA256';
    } else {
      meta.serverSeedHash = hashServerSeed(config.serverSeed);
      meta.clientSeed = config.clientSeed;
      meta.method = 'HMAC-SHA256 seed pair';
    }

    writeFileSync(join(dataDir, `${gameName}_outcomes.json`), JSON.stringify({
      meta,
      outcomes: outcomes.map(o => o.result),
      rawFloats: outcomes.map(o => o.raw)
    }));
  }

  // ---- STEP 2: TEST ----
  console.log('\n' + '━'.repeat(60));
  console.log('STEP 2/3: RUNNING STATISTICAL TESTS');
  console.log('━'.repeat(60));

  const testResults = {};
  let totalPassed = 0;
  let totalTests = 0;

  for (const gameName of config.games) {
    const result = runTestSuite(gameName, allOutcomes[gameName].results, allOutcomes[gameName].rawFloats, config.casinoType);
    testResults[gameName] = result;
    totalPassed += result.passed;
    totalTests += result.total;
  }

  const overallScore = totalPassed / totalTests;
  const overall = {
    totalPassed,
    totalTests,
    score: parseFloat(overallScore.toFixed(4)),
    rating: overallScore >= 0.9 ? 'EXCELLENT' : overallScore >= 0.75 ? 'GOOD' : overallScore >= 0.5 ? 'FAIR' : 'POOR'
  };

  const fullResults = {
    auditId: auditProtocol.auditId,
    timestamp: auditProtocol.timestamp,
    auditProtocol: auditProtocol.methodology,
    methodology: 'NIST SP 800-22 + Custom Gaming Tests',
    significanceLevel: 0.01,
    casino: config.casino,
    config: {
      casinoType: config.casinoType,
      ...(config.casinoType === 'roobet'
        ? { startHash: config.startHash, salt: 'public' }
        : { serverSeedHash: hashServerSeed(config.serverSeed), clientSeed: config.clientSeed }),
      samplePerGame: config.count,
      totalOutcomes: config.count * config.games.length
    },
    results: testResults,
    overall
  };

  writeFileSync(join(dataDir, 'test_results.json'), JSON.stringify(fullResults, null, 2));

  // ---- STEP 3: GENERATE REPORT ----
  console.log('\n' + '━'.repeat(60));
  console.log('STEP 3/3: GENERATING SCORECARD');
  console.log('━'.repeat(60));

  const reportDir = join(__dirname, '..', 'reports');
  mkdirSync(reportDir, { recursive: true });

  const casinoInfo = {
    name: config.casino,
    url: '',
    games: config.games
  };

  const html = generateReport(fullResults, casinoInfo);
  const safeName = config.casino.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase();
  const filename = `scorecard_${safeName}_${new Date().toISOString().split('T')[0]}.html`;
  const reportPath = join(reportDir, filename);
  writeFileSync(reportPath, html);

  // ---- STEP 4: DATA INTEGRITY (SHA-256 + PGP) ----
  console.log('\n' + '━'.repeat(60));
  console.log('STEP 4/4: DATA INTEGRITY HASHING & SIGNING');
  console.log('━'.repeat(60));

  // SHA-256 hash of raw data (outcomes + test results)
  const rawDataJson = JSON.stringify(fullResults, null, 2);
  const dataHash = createHash('sha256').update(rawDataJson).digest('hex');

  // SHA-256 hash of the HTML report
  const reportHash = createHash('sha256').update(html).digest('hex');

  // Write integrity manifest
  const integrityManifest = {
    auditId: auditProtocol.auditId,
    timestamp: auditProtocol.timestamp,
    casino: config.casino,
    hashes: {
      algorithm: 'SHA-256',
      rawData: dataHash,
      htmlReport: reportHash,
      note: 'Hashes computed over the JSON test results and HTML scorecard. Verify with: sha256sum <file>'
    },
    verification: {
      pgpKey: 'pitboss@fairplayaudit.com',
      fingerprint: 'FC6C E2D2 A721 409A 1E94 EF07 1F1E F6DA 6A77 0EB9',
      publicKeyUrl: 'https://fairplayaudit.com/pgp/'
    }
  };

  const manifestPath = join(reportDir, `integrity_${safeName}_${new Date().toISOString().split('T')[0]}.json`);
  writeFileSync(manifestPath, JSON.stringify(integrityManifest, null, 2));

  // Attempt PGP signing (if gpg is available)
  let pgpSigned = false;
  try {
    execSync(`gpg --version`, { stdio: 'pipe' });
    const sigPath = manifestPath + '.sig';
    execSync(`gpg --batch --yes --local-user pitboss@fairplayaudit.com --detach-sign --armor --output "${sigPath}" "${manifestPath}"`, { stdio: 'pipe' });
    pgpSigned = true;
    console.log(`PGP Signature: ${sigPath}`);
  } catch (e) {
    console.log('PGP signing skipped (gpg not available or no key found)');
  }

  console.log(`Data Hash:     ${dataHash}`);
  console.log(`Report Hash:   ${reportHash}`);
  console.log(`Manifest:      ${manifestPath}`);
  console.log(`PGP Signed:    ${pgpSigned ? 'YES' : 'NO (sign manually on VPS)'}`);

  // Also append integrity info to the full results JSON
  fullResults.integrity = integrityManifest.hashes;
  fullResults.integrity.pgpFingerprint = integrityManifest.verification.fingerprint;
  writeFileSync(join(dataDir, 'test_results.json'), JSON.stringify(fullResults, null, 2));

  // ---- SUMMARY ----
  console.log('\n' + '═'.repeat(60));
  console.log('SCORECARD COMPLETE');
  console.log('═'.repeat(60));
  console.log(`Casino:        ${config.casino}`);
  console.log(`Score:         ${(overall.score * 10).toFixed(1)} / 10.0`);
  console.log(`Rating:        ${overall.rating}`);
  console.log(`Tests:         ${totalPassed}/${totalTests} passed`);
  console.log(`Outcomes:      ${(config.count * config.games.length).toLocaleString()}`);
  console.log(`Report:        ${reportPath}`);
  console.log(`Data SHA-256:  ${dataHash.slice(0, 16)}...`);
  console.log(`PGP Signed:    ${pgpSigned ? 'YES ✓' : 'NO (manual)'}`);
  console.log('═'.repeat(60));
}

main().catch(console.error);
