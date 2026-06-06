/**
 * FairPlay Audit — Outcome Collector
 *
 * Generates provably fair game outcomes from seed pairs using
 * the same HMAC-SHA256 algorithm that Stake.com / similar casinos use.
 *
 * This simulates what the casino's RNG produces — if we get the same
 * results as the casino shows, the hash verification passes.
 *
 * https://fairplayaudit.com
 * Licensed under BSL 1.1 — see LICENSE
 * Origin: FPA-0xA3B7F2-HMAC (integrity marker)
 */

import { createHmac, createHash } from 'crypto';
import { writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================
// STAKE.COM PROVABLY FAIR ALGORITHM (HMAC-SHA256)
// ============================================================

/**
 * Byte generator — exact replica of Stake.com's RNG
 * Creates a stream of pseudo-random bytes from seed combination
 */
function* byteGenerator(serverSeed, clientSeed, nonce, cursor = 0) {
  let currentRound = Math.floor(cursor / 32);
  let currentRoundCursor = cursor % 32;

  while (true) {
    const hmac = createHmac('sha256', serverSeed);
    hmac.update(`${clientSeed}:${nonce}:${currentRound}`);
    const buffer = hmac.digest();

    while (currentRoundCursor < 32) {
      yield buffer[currentRoundCursor];
      currentRoundCursor++;
    }
    currentRoundCursor = 0;
    currentRound++;
  }
}

/**
 * Get N random bytes from the generator
 */
function getBytes(serverSeed, clientSeed, nonce, count = 4) {
  const gen = byteGenerator(serverSeed, clientSeed, nonce);
  const bytes = [];
  for (let i = 0; i < count; i++) {
    bytes.push(gen.next().value);
  }
  return bytes;
}

/**
 * Convert bytes to a float [0, 1)
 */
function bytesToFloat(bytes) {
  return bytes.reduce((acc, byte, i) => acc + byte / Math.pow(256, i + 1), 0);
}

// ============================================================
// GAME RESULT CALCULATORS
// ============================================================

const games = {
  /**
   * Dice: Result 0.00 - 100.00
   */
  dice(serverSeed, clientSeed, nonce) {
    const bytes = getBytes(serverSeed, clientSeed, nonce, 4);
    const float = bytesToFloat(bytes);
    const result = Math.floor(float * 10001) / 100;
    return { game: 'dice', result, raw: float };
  },

  /**
   * Limbo: Multiplier 1.00+
   * Uses Stake.com's exact formula with 1% house edge
   */
  limbo(serverSeed, clientSeed, nonce) {
    const bytes = getBytes(serverSeed, clientSeed, nonce, 4);
    const float = bytesToFloat(bytes);
    const floatInt = Math.floor(float * 16777216);
    const result = Math.floor((16777216 / (floatInt + 1)) * (1 - 0.01) * 100) / 100;
    return { game: 'limbo', result: Math.max(1, result), raw: float };
  },

  /**
   * Crash: Multiplier 1.00+
   * House edge via instant crash at 1/33 rate
   */
  crash(serverSeed, clientSeed, nonce) {
    const hmac = createHmac('sha256', serverSeed);
    hmac.update(`${clientSeed}:${nonce}`);
    const hash = hmac.digest('hex');

    // Raw uniform float from hash (always computed for RNG testing)
    const h = parseInt(hash.slice(0, 13), 16);
    const e = Math.pow(2, 52);
    const raw = h / e;

    // 1 in 33 chance of instant crash (house edge ~3%)
    if (h % 33 === 0) {
      return { game: 'crash', result: 1.00, raw, instantCrash: true };
    }

    // Calculate crash point
    const result = Math.floor((100 * e - h) / (e - h)) / 100;
    return { game: 'crash', result: Math.max(1, result), raw, instantCrash: false };
  },

  /**
   * Coin Flip: 0 (heads) or 1 (tails)
   */
  coinFlip(serverSeed, clientSeed, nonce) {
    const bytes = getBytes(serverSeed, clientSeed, nonce, 1);
    const result = bytes[0] < 128 ? 0 : 1;
    return { game: 'coinFlip', result, raw: bytes[0] / 256 };
  },

  /**
   * Roulette: 0-36
   */
  roulette(serverSeed, clientSeed, nonce) {
    const bytes = getBytes(serverSeed, clientSeed, nonce, 4);
    const float = bytesToFloat(bytes);
    const result = Math.floor(float * 37);
    return { game: 'roulette', result, raw: float };
  }
};

// ============================================================
// BULK COLLECTION
// ============================================================

/**
 * Collect N outcomes for a specific game
 */
function collectOutcomes(config) {
  const {
    serverSeed,
    clientSeed,
    gameName = 'dice',
    startNonce = 1,
    count = 100000
  } = config;

  const gameFn = games[gameName];
  if (!gameFn) throw new Error(`Unknown game: ${gameName}`);

  console.log(`Collecting ${count.toLocaleString()} ${gameName} outcomes...`);
  console.log(`Server Seed: ${serverSeed.slice(0, 16)}...`);
  console.log(`Client Seed: ${clientSeed}`);

  const outcomes = [];
  const startTime = Date.now();

  for (let nonce = startNonce; nonce < startNonce + count; nonce++) {
    const outcome = gameFn(serverSeed, clientSeed, nonce);
    outcome.nonce = nonce;
    outcomes.push(outcome);

    if (nonce % 25000 === 0) {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`  ${nonce.toLocaleString()} / ${count.toLocaleString()} (${elapsed}s)`);
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`Done! ${count.toLocaleString()} outcomes in ${elapsed}s\n`);

  return outcomes;
}

/**
 * Verify a single outcome against casino's hash
 */
function verifyHash(serverSeed, clientSeed, nonce, expectedHash) {
  const hmac = createHmac('sha256', serverSeed);
  hmac.update(`${clientSeed}:${nonce}:0`);
  const hash = hmac.digest('hex');
  return hash === expectedHash;
}

/**
 * Get the server seed hash (what casino shows before revealing seed)
 */
function hashServerSeed(serverSeed) {
  return createHash('sha256').update(serverSeed).digest('hex');
}

// ============================================================
// MAIN — Run collection with sample seeds
// ============================================================

function main() {
  // Sample seeds for demonstration
  // In production, these come from the casino's revealed seed pairs
  const config = {
    serverSeed: 'a]V~d#W3t=+W5L$@gM4%ho6gm&!G^bSo',
    clientSeed: 'fairplayaudit-2026',
    count: 100000  // 100k outcomes per game
  };

  const outputDir = join(__dirname, '..', 'data');
  mkdirSync(outputDir, { recursive: true });

  // Collect outcomes for multiple games
  const gameNames = ['dice', 'limbo', 'crash', 'coinFlip', 'roulette'];
  const allResults = {};

  for (const gameName of gameNames) {
    const outcomes = collectOutcomes({ ...config, gameName });
    allResults[gameName] = outcomes;

    // Save raw data
    const filename = join(outputDir, `${gameName}_outcomes.json`);
    writeFileSync(filename, JSON.stringify({
      meta: {
        casino: 'sample-audit',
        game: gameName,
        serverSeedHash: hashServerSeed(config.serverSeed),
        clientSeed: config.clientSeed,
        sampleSize: outcomes.length,
        collectedAt: new Date().toISOString(),
        collector: 'FairPlay Audit Scorecard Tool v2.0'
      },
      outcomes: outcomes.map(o => o.result),
      rawFloats: outcomes.map(o => o.raw)
    }, null, 2));

    console.log(`Saved: ${filename}`);
  }

  // Also save combined summary
  const summary = {
    auditId: `FPA-${Date.now()}`,
    casino: 'Sample Audit',
    timestamp: new Date().toISOString(),
    config: {
      serverSeedHash: hashServerSeed(config.serverSeed),
      clientSeed: config.clientSeed,
      totalOutcomes: config.count * gameNames.length
    },
    games: Object.fromEntries(
      Object.entries(allResults).map(([name, outcomes]) => [
        name,
        {
          count: outcomes.length,
          min: Math.min(...outcomes.map(o => o.result)),
          max: Math.max(...outcomes.map(o => o.result)),
          mean: outcomes.reduce((s, o) => s + o.result, 0) / outcomes.length
        }
      ])
    )
  };

  writeFileSync(join(outputDir, 'collection_summary.json'), JSON.stringify(summary, null, 2));
  console.log('\nCollection complete! Summary saved.');
  console.log(`Total outcomes: ${(config.count * gameNames.length).toLocaleString()}`);

  return summary;
}

// ============================================================
// BC.GAME PROVABLY FAIR ALGORITHM
// Source: https://bcgame-project.github.io/verify/coinflip.html
// ============================================================

const bcgameGames = {
  /**
   * BC.Game CoinFlip
   * HMAC format: HMAC-SHA256(key=serverSeed, msg=clientSeed:nonce:round)
   * Result: floor(float * 2) → 0 (heads) or 1 (tails)
   */
  coinFlip(serverSeed, clientSeed, nonce) {
    const hmac = createHmac('sha256', serverSeed);
    hmac.update(`${clientSeed}:${nonce}:1`);
    const buffer = hmac.digest();

    const float = buffer[0] / Math.pow(256, 1)
               + buffer[1] / Math.pow(256, 2)
               + buffer[2] / Math.pow(256, 3)
               + buffer[3] / Math.pow(256, 4);

    const result = Math.floor(float * 2);
    return { game: 'coinFlip', result, raw: float };
  }
};

// ============================================================
// ROOBET PROVABLY FAIR ALGORITHM (Hash Chain + HMAC)
// Source: https://github.com/drewnicolette/roobet
// ============================================================

const ROOBET_SALT = '0000000000000000000fa3b65e43e4240d71762a5bf397d5304b2596d116859c';
const ROOBET_FIRST_GAME = '77b271fe12fca03c618f63dfb79d4105726ba9d4a25bb3f1964e435ccf9cb209';

/**
 * Collect Roobet Crash outcomes from hash chain.
 * Each game hash → HMAC-SHA256(key=gameHash, msg=salt) → multiplier
 * Next game = SHA256(currentHash)
 */
function roobetCollectCrash(startHash, count) {
  console.log(`Collecting ${count.toLocaleString()} Roobet crash outcomes...`);
  console.log(`Start Hash: ${startHash.slice(0, 16)}...`);
  console.log(`Salt: ${ROOBET_SALT.slice(0, 16)}...`);

  const outcomes = [];
  let gameHash = startHash;
  const startTime = Date.now();

  for (let i = 0; i < count; i++) {
    const hmacHex = createHmac('sha256', gameHash)
      .update(ROOBET_SALT)
      .digest('hex');

    const h = parseInt(hmacHex.slice(0, 13), 16);
    const e = Math.pow(2, 52);
    const raw = h / e;

    // House edge: 1/20 chance of instant crash
    const hashBigInt = BigInt('0x' + hmacHex);
    let result;
    let instantCrash = false;

    if (hashBigInt % 20n === 0n) {
      result = 1.00;
      instantCrash = true;
    } else {
      result = Math.floor((100 * e - h) / (e - h)) / 100;
      result = Math.max(1, result);
    }

    outcomes.push({ game: 'crash', result, raw, nonce: i + 1, instantCrash });

    // Next game in chain
    gameHash = createHash('sha256').update(gameHash).digest('hex');

    if ((i + 1) % 25000 === 0) {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`  ${(i + 1).toLocaleString()} / ${count.toLocaleString()} (${elapsed}s)`);
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`Done! ${count.toLocaleString()} outcomes in ${elapsed}s\n`);
  return outcomes;
}

/**
 * BC.Game outcome collector (uses seed pairs like Stake)
 */
function collectBcgameOutcomes(config) {
  const { serverSeed, clientSeed, gameName = 'coinFlip', startNonce = 1, count = 50000 } = config;
  const gameFn = bcgameGames[gameName];
  if (!gameFn) throw new Error(`Unknown BC.Game game: ${gameName}`);

  console.log(`Collecting ${count.toLocaleString()} BC.Game ${gameName} outcomes...`);
  console.log(`Server Seed: ${serverSeed.slice(0, 16)}...`);
  console.log(`Client Seed: ${clientSeed}`);

  const outcomes = [];
  const startTime = Date.now();

  for (let nonce = startNonce; nonce < startNonce + count; nonce++) {
    const outcome = gameFn(serverSeed, clientSeed, nonce);
    outcome.nonce = nonce;
    outcomes.push(outcome);

    if (nonce % 25000 === 0) {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`  ${nonce.toLocaleString()} / ${count.toLocaleString()} (${elapsed}s)`);
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`Done! ${count.toLocaleString()} outcomes in ${elapsed}s\n`);
  return outcomes;
}

export {
  collectOutcomes, verifyHash, hashServerSeed, games, byteGenerator,
  bcgameGames, collectBcgameOutcomes,
  roobetCollectCrash, ROOBET_SALT, ROOBET_FIRST_GAME
};

// Run if called directly
const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'));
if (isMain) main();
