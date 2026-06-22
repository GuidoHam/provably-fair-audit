/**
 * FairPlay Audit — Scorecard Report Generator
 *
 * Takes test results and generates a professional HTML scorecard
 * ready for fairplayaudit.com publication.
 *
 * https://fairplayaudit.com
 * Licensed under BSL 1.1 — see LICENSE
 * Origin: FPA-0xE4D91C-RPT (integrity marker)
 */

import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

function generateReport(testResults, casinoInfo) {
  const { overall, results, timestamp, methodology } = testResults;

  const casino = casinoInfo || {
    name: 'Sample Casino',
    url: 'https://example.com',
    games: Object.keys(results)
  };

  const scoreColor = overall.score >= 0.9 ? '#22c55e'
    : overall.score >= 0.75 ? '#84cc16'
    : overall.score >= 0.5 ? '#eab308'
    : '#ef4444';

  const ratingEmoji = overall.score >= 0.9 ? '🟢'
    : overall.score >= 0.75 ? '🟡'
    : overall.score >= 0.5 ? '🟠'
    : '🔴';

  const totalOutcomes = Object.values(results)
    .reduce((sum, r) => sum + r.sampleSize, 0);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FairPlay Audit Fairness Scorecard — ${casino.name}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a0a0a;
      color: #e5e5e5;
      line-height: 1.6;
    }
    .container { max-width: 900px; margin: 0 auto; padding: 20px; }

    /* Header */
    .header {
      text-align: center;
      padding: 40px 20px;
      border-bottom: 1px solid #333;
      margin-bottom: 30px;
    }
    .header .logo {
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 3px;
      color: #888;
      margin-bottom: 8px;
    }
    .header h1 {
      font-size: 32px;
      color: #fff;
      margin-bottom: 4px;
    }
    .header .subtitle {
      font-size: 16px;
      color: #888;
    }

    /* Score Card */
    .score-card {
      background: #141414;
      border: 1px solid #333;
      border-radius: 12px;
      padding: 30px;
      margin-bottom: 24px;
      text-align: center;
    }
    .score-big {
      font-size: 72px;
      font-weight: 800;
      color: ${scoreColor};
      line-height: 1;
    }
    .score-label {
      font-size: 18px;
      color: #888;
      margin-top: 8px;
    }
    .score-rating {
      display: inline-block;
      margin-top: 12px;
      padding: 6px 20px;
      border-radius: 20px;
      font-weight: 700;
      font-size: 14px;
      background: ${scoreColor}22;
      color: ${scoreColor};
      border: 1px solid ${scoreColor}44;
    }

    /* Meta Info */
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .meta-item {
      background: #141414;
      border: 1px solid #333;
      border-radius: 8px;
      padding: 16px;
    }
    .meta-item .label { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 1px; }
    .meta-item .value { font-size: 18px; color: #fff; font-weight: 600; margin-top: 4px; }

    /* Game Results */
    .game-section {
      background: #141414;
      border: 1px solid #333;
      border-radius: 12px;
      margin-bottom: 16px;
      overflow: hidden;
    }
    .game-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 20px;
      border-bottom: 1px solid #222;
      cursor: pointer;
    }
    .game-header h3 { font-size: 18px; color: #fff; }
    .game-score {
      padding: 4px 12px;
      border-radius: 12px;
      font-weight: 700;
      font-size: 14px;
    }
    .game-score.pass { background: #22c55e22; color: #22c55e; }
    .game-score.fail { background: #ef444422; color: #ef4444; }

    /* Test Table */
    .test-table {
      width: 100%;
      border-collapse: collapse;
    }
    .test-table th {
      text-align: left;
      padding: 10px 20px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #666;
      border-bottom: 1px solid #222;
    }
    .test-table td {
      padding: 10px 20px;
      border-bottom: 1px solid #1a1a1a;
      font-size: 14px;
    }
    .test-table tr:last-child td { border-bottom: none; }
    .test-pass { color: #22c55e; }
    .test-fail { color: #ef4444; }

    /* Methodology */
    .methodology {
      background: #141414;
      border: 1px solid #333;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }
    .methodology h2 { font-size: 20px; color: #fff; margin-bottom: 16px; }
    .methodology p { color: #999; font-size: 14px; margin-bottom: 12px; }
    .methodology ul { color: #999; font-size: 14px; padding-left: 20px; }
    .methodology li { margin-bottom: 6px; }

    /* Disclaimer */
    .disclaimer {
      background: #1a1000;
      border: 1px solid #333300;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .disclaimer h3 { color: #eab308; font-size: 14px; margin-bottom: 8px; }
    .disclaimer p { color: #888; font-size: 13px; }

    /* Footer */
    .footer {
      text-align: center;
      padding: 30px 20px;
      border-top: 1px solid #333;
      color: #555;
      font-size: 13px;
    }
    .footer a { color: #888; }

    @media (max-width: 640px) {
      .score-big { font-size: 48px; }
      .header h1 { font-size: 24px; }
      .meta-grid { grid-template-columns: 1fr 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">

    <div class="header">
      <div class="logo">FairPlay Audit</div>
      <h1>Fairness Scorecard</h1>
      <div class="subtitle">${casino.name}</div>
    </div>

    <div class="score-card">
      <div class="score-big">${(overall.score * 10).toFixed(1)}</div>
      <div class="score-label">out of 10.0</div>
      <div class="score-rating">${ratingEmoji} ${overall.rating}</div>
    </div>

    <div class="meta-grid">
      <div class="meta-item">
        <div class="label">Total Outcomes Analyzed</div>
        <div class="value">${totalOutcomes.toLocaleString()}</div>
      </div>
      <div class="meta-item">
        <div class="label">Tests Passed</div>
        <div class="value">${overall.totalPassed} / ${overall.totalTests}</div>
      </div>
      <div class="meta-item">
        <div class="label">Games Tested</div>
        <div class="value">${Object.keys(results).length}</div>
      </div>
      <div class="meta-item">
        <div class="label">Analysis Date</div>
        <div class="value">${new Date(timestamp).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}</div>
      </div>
      <div class="meta-item">
        <div class="label">Methodology</div>
        <div class="value">NIST SP 800-22</div>
      </div>
      <div class="meta-item">
        <div class="label">Significance Level</div>
        <div class="value">&alpha; = 0.01 (99%)</div>
      </div>
    </div>

    ${Object.entries(results).map(([game, result]) => `
    <div class="game-section">
      <div class="game-header">
        <h3>${game.charAt(0).toUpperCase() + game.slice(1)}</h3>
        <span class="game-score ${result.overallPass ? 'pass' : 'fail'}">
          ${result.passed}/${result.total} ${result.overallPass ? 'PASSED' : 'FAILED'}
        </span>
      </div>
      <table class="test-table">
        <thead>
          <tr>
            <th>Test</th>
            <th>p-value</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          ${result.tests.map(t => `
          <tr>
            <td>${t.name}</td>
            <td>${t.pValue != null && !isNaN(t.pValue) ? t.pValue.toFixed(4) : 'N/A'}</td>
            <td class="${t.pass ? 'test-pass' : 'test-fail'}">${t.pass ? 'PASS' : 'FAIL'}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`).join('')}

    <div class="methodology">
      <h2>Methodology</h2>
      <p>This analysis was conducted using the FairPlay Audit Fairness Testing Framework,
         based on the NIST SP 800-22 Statistical Test Suite for Random Number Generators.</p>
      <p><strong>Tests performed:</strong></p>
      <ul>
        <li><strong>NIST Monobit Test</strong> — Verifies equal distribution of 0s and 1s in the bit stream</li>
        <li><strong>NIST Runs Test</strong> — Detects patterns in consecutive identical values</li>
        <li><strong>NIST Block Frequency</strong> — Checks local balance within sub-sequences</li>
        <li><strong>NIST Cumulative Sums</strong> — Detects drift or bias over time</li>
        <li><strong>Chi-Square Goodness of Fit</strong> — Verifies uniform distribution of outcomes</li>
        <li><strong>Kolmogorov-Smirnov Test</strong> — Tests fit against theoretical distribution</li>
        <li><strong>Serial Correlation</strong> — Detects dependence between consecutive outcomes</li>
        <li><strong>Runs Up/Down</strong> — Identifies trends in outcome sequences</li>
        <li><strong>Game-specific tests</strong> — Custom tests per game type (crash rate, coin fairness, etc.)</li>
      </ul>
      <p style="margin-top: 16px;">All tests use a significance level of &alpha; = 0.01.
         A p-value &ge; 0.01 indicates the outcome sequence is consistent with true randomness.
         A p-value &lt; 0.01 suggests statistically significant deviation from expected behavior.</p>
      <p><strong>Hash Verification:</strong> All outcomes were generated using HMAC-SHA256 with
         the casino's published server seed, client seed, and nonce — the same algorithm used
         by the casino's provably fair system.</p>
    </div>

    <div class="disclaimer">
      <h3>Important Disclaimer</h3>
      <p>This Fairness Scorecard is an independent statistical analysis performed by FairPlay Audit.
         It is <strong>not a regulatory certification</strong> and does not constitute legal advice
         or a guarantee of future fairness. This analysis is based on a sample of game outcomes
         and evaluates statistical properties of the RNG at the time of testing.
         Past results do not guarantee future performance.
         Players should always gamble responsibly.</p>
      <p style="margin-top: 8px;">FairPlay Audit is not affiliated with, endorsed by, or connected to
         ${casino.name} or any regulatory body. For regulatory certification, consult
         licensed testing laboratories (GLI, eCOGRA, BMM Testlabs).</p>
    </div>

    <div class="footer">
      <p>&copy; ${new Date().getFullYear()} FairPlay Audit — Independent Crypto Casino Analysis</p>
      <p><a href="https://fairplayaudit.com">fairplayaudit.com</a></p>
    </div>

  </div>
</body>
</html>`;

  return html;
}

// ============================================================
// MAIN
// ============================================================

function main() {
  const dataDir = join(__dirname, '..', 'data');
  const outputDir = join(__dirname, '..', 'reports');
  mkdirSync(outputDir, { recursive: true });

  const testResults = JSON.parse(readFileSync(join(dataDir, 'test_results.json'), 'utf-8'));

  const casinoInfo = {
    name: 'Sample Casino Audit',
    url: 'https://example.com',
    games: Object.keys(testResults.results)
  };

  const html = generateReport(testResults, casinoInfo);

  const filename = `scorecard_${casinoInfo.name.replace(/\s+/g, '_').toLowerCase()}_${Date.now()}.html`;
  const outputPath = join(outputDir, filename);
  writeFileSync(outputPath, html);

  console.log(`\nScorecard generated: ${outputPath}`);
  console.log(`Open in browser to preview.`);

  return outputPath;
}

export { generateReport };

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'));
if (isMain) main();
