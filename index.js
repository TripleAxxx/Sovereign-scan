/**
 * Sovereign-Scan — Main Entry Point
 *
 * Automated LLM safety benchmarking tool. Orchestrates the full pipeline:
 * loads taxonomy entries → runs each through the Orchestrator →
 * Playwright-validates actionable responses → writes structured JSON report.
 *
 * @module index
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import chalk from 'chalk';
import OpenAI from 'openai';
import { Orchestrator } from './engine/orchestrator.js';
import { createValidator } from './validator.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Bootstrap and execute the full benchmark run.
 * @async
 * @returns {Promise<void>}
 */
async function main() {
  const isDryRun = process.argv.includes('--dry-run');
  const t0 = Date.now();

  console.log(chalk.cyan.bold('\n🔍  Sovereign-Scan v1.0.0-alpha'));
  console.log(chalk.cyan('    LLM Safety Benchmarking — ARCANUM PI Taxonomy Pipeline\n'));

  // ------------------------------------------------------------------
  // Directories
  // ------------------------------------------------------------------
  for (const dir of ['screenshots', 'logs']) {
    const p = join(__dirname, dir);
    if (!existsSync(p)) mkdirSync(p, { recursive: true });
  }

  // ------------------------------------------------------------------
  // Load taxonomy
  // ------------------------------------------------------------------
  /** @type {{entries: Array<object>}} */
  let taxonomy;
  try {
    const taxonomyPath = join(__dirname, 'data', 'taxonomy.json');
    taxonomy = JSON.parse(readFileSync(taxonomyPath, 'utf-8'));
    console.log(chalk.white(`Loaded ${taxonomy.entries.length} taxonomy entries from ARCANUM PI Taxonomy\n`));
  } catch (err) {
    console.error(chalk.red(`Failed to load data/taxonomy.json: ${err.message}`));
    process.exit(1);
  }

  // ------------------------------------------------------------------
  // LLM client
  // ------------------------------------------------------------------
  const useOllama = process.env.USE_OLLAMA === 'true';
  let llmClient = null;

  if (!useOllama) {
    if (!process.env.OPENAI_API_KEY) {
      console.error(chalk.red('OPENAI_API_KEY not set — create a .env file or set USE_OLLAMA=true'));
      process.exit(1);
    }
    llmClient = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
      baseURL: 'https://api.openai.com/v1',
      timeout: 30_000,
      maxRetries: 2
    });
  }

  const model = useOllama ? (process.env.OLLAMA_MODEL || 'llama3') : 'gpt-4o';
  const provider = useOllama ? 'ollama' : 'openai';

  console.log(chalk.white(`Provider: ${provider}  |  Model: ${model}`));
  if (isDryRun) console.log(chalk.yellow('DRY RUN — mock responses only\n'));

  // ------------------------------------------------------------------
  // Orchestrator + Validator
  // ------------------------------------------------------------------
  const orchestrator = new Orchestrator({
    llmClient,
    model,
    provider,
    dryRun: isDryRun,
    timeoutMs: 30_000
  });

  const validate = createValidator(join(__dirname, 'screenshots'));

  // Progress events
  orchestrator.on('phase', ({ id, phase }) => {
    const icons = { injection: '📤', evaluation: '📊', validation: '🌐' };
    console.log(chalk.gray(`  ${icons[phase] || '•'} [${id}] ${phase}`));
  });

  // ------------------------------------------------------------------
  // Run pipeline for each entry
  // ------------------------------------------------------------------
  const results = [];
  const counters = { Blocked: 0, 'Safe/Generic': 0, 'Actionable/Unsafe': 0, Error: 0 };

  for (const entry of taxonomy.entries) {
    console.log(chalk.white(`\n┌─ ${entry.id}  ${entry.category}`));
    console.log(chalk.gray(`│  Intent: ${entry.arcanumIntent}  |  Risk: ${entry.riskLevel}`));

    const result = await orchestrator.run(entry, { validatorFn: validate });

    results.push(result);

    const label = result.evaluation?.label ?? 'Error';
    counters[label] = (counters[label] ?? 0) + 1;

    const labelColour =
      label === 'Blocked' ? chalk.green :
      label === 'Safe/Generic' ? chalk.yellow :
      label === 'Actionable/Unsafe' ? chalk.red : chalk.gray;

    console.log(chalk.white(`└─ ${labelColour(label)}  (${result.evaluation?.confidence ?? 'n/a'})  ${result.durationMs}ms`));
  }

  // ------------------------------------------------------------------
  // Build & write report
  // ------------------------------------------------------------------
  const report = {
    meta: {
      tool: 'Sovereign-Scan',
      version: '1.0.0-alpha',
      runDate: new Date().toISOString(),
      llmProvider: provider,
      model,
      taxonomySource: 'ARCANUM Prompt Injection Taxonomy v1.5 (CC BY 4.0)',
      totalTests: taxonomy.entries.length,
      blocked: counters['Blocked'] ?? 0,
      safeGeneric: counters['Safe/Generic'] ?? 0,
      actionableUnsafe: counters['Actionable/Unsafe'] ?? 0,
      errors: counters['Error'] ?? 0,
      totalDurationMs: Date.now() - t0
    },
    results
  };

  const reportPath = join(__dirname, 'report.json');
  try {
    writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(chalk.green(`\n✅ Report → ${reportPath}`));
  } catch (err) {
    console.error(chalk.red(`Failed to write report: ${err.message}`));
  }

  // ------------------------------------------------------------------
  // Terminal summary
  // ------------------------------------------------------------------
  console.log(chalk.cyan.bold('\n📊  Scan Summary'));
  console.log(chalk.cyan('══════════════════════════════════'));
  console.log(chalk.white(`  Total:           ${report.meta.totalTests}`));
  console.log(chalk.green(`  Blocked:       ${report.meta.blocked}`));
  console.log(chalk.yellow(` Safe/Generic:  ${report.meta.safeGeneric}`));
  console.log(chalk.red(`    Actionable:    ${report.meta.actionableUnsafe}`));
  console.log(chalk.gray(`   Errors:        ${report.meta.errors}`));
  console.log(chalk.white(`  Total time:    ${report.meta.totalDurationMs}ms`));
  console.log(chalk.cyan('══════════════════════════════════\n'));

  if (report.meta.actionableUnsafe > 0) {
    console.log(chalk.red.bold('  WARNING: One or more models produced actionable/unsafe outputs.'));
    console.log(chalk.red('    Review report.json immediately and consider model redeployment.\n'));
  }
}

main().catch(err => {
  console.error(chalk.red(`Fatal: ${err.message}`));
  process.exit(1);
});
