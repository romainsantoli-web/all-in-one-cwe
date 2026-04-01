#!/usr/bin/env node
/**
 * MetaMask Recovery CLI — V2 VECTORIZED
 *
 * High-performance version using:
 * - Worker threads (1 per CPU core = 10 on M4)
 * - Concurrent PBKDF2 per worker (8 parallel calls)
 * - Total: 80 simultaneous PBKDF2 operations
 * - Pre-cached vault buffers (no re-parsing per attempt)
 * - Cascade: Profile → Dictionary → Brute-force fallback
 *
 * Commands:
 *   extract   — Extract vault from MetaMask LevelDB files
 *   crack     — Run password recovery against a vault (VECTORIZED)
 *   decrypt   — Decrypt a vault with a known password
 *   hashcat   — Export vault in hashcat-compatible format
 *   benchmark — Measure V1 vs V2 speed on this machine
 */
import os from 'node:os';
import { execFileSync } from 'node:child_process';
// ── CRITICAL: UV_THREADPOOL_SIZE must be set BEFORE libuv initializes ──
// If not set, re-exec this process with the correct env var.
const requiredPoolSize = Math.max(os.cpus().length * 16, 128);
if (!process.env.__MM_POOL_OK) {
    execFileSync(process.execPath, process.argv.slice(1), {
        stdio: 'inherit',
        env: {
            ...process.env,
            UV_THREADPOOL_SIZE: String(requiredPoolSize),
            __MM_POOL_OK: '1',
        },
    });
    process.exit(0);
}
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import path from 'node:path';
import fs from 'node:fs';
import { readFileSync, writeFileSync } from 'node:fs';
import { VaultExtractor, VaultDecryptor, PasswordGenerator, VectorizedCrackEngine, } from '@metamask-recovery/core';
import { SmartGenerator, } from '@metamask-recovery/intelligence';
const program = new Command();
const cpuCount = os.cpus().length;
function formatSize(bytes) {
    if (bytes === 0)
        return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}
// ---------- Legal disclaimer ----------
const DISCLAIMER = `
${chalk.red('╔══════════════════════════════════════════════════════════════╗')}
${chalk.red('║')}  ${chalk.bold.yellow('⚠  LEGAL DISCLAIMER')}                                        ${chalk.red('║')}
${chalk.red('║')}                                                              ${chalk.red('║')}
${chalk.red('║')}  This tool is designed EXCLUSIVELY for recovering YOUR OWN   ${chalk.red('║')}
${chalk.red('║')}  MetaMask wallet password.                                   ${chalk.red('║')}
${chalk.red('║')}                                                              ${chalk.red('║')}
${chalk.red('║')}  ${chalk.bold.cyan('V3 PASSWORD INTELLIGENCE')} — ${chalk.dim(`AI Profiler + ${cpuCount} cores`)}          ${chalk.red('║')}
${chalk.red('╚══════════════════════════════════════════════════════════════╝')}
`;
program
    .name('mm-recover-v4')
    .version('4.0.0')
    .description('MetaMask password recovery — V4 Password Intelligence Engine')
    .hook('preAction', () => {
    console.log(DISCLAIMER);
});
// ---------- extract command ----------
program
    .command('extract')
    .description('Extract encrypted vault from MetaMask local storage')
    .option('-p, --path <path>', 'Path to MetaMask LevelDB directory')
    .option('-o, --output <file>', 'Save vault JSON to file')
    .action(async (opts) => {
    const spinner = ora('Searching for MetaMask vault...').start();
    try {
        const vault = await VaultExtractor.extractFromLevelDB(opts.path);
        spinner.succeed('Vault found!');
        console.log(chalk.green('\n✓ Vault extracted successfully'));
        console.log(chalk.dim(`  Iterations: ${vault.iterations}`));
        console.log(chalk.dim(`  Legacy: ${vault.isLegacy}`));
        console.log(chalk.dim(`  Salt: ${vault.salt.substring(0, 20)}...`));
        const vaultJson = JSON.stringify({
            data: vault.data,
            iv: vault.iv,
            salt: vault.salt,
            iterations: vault.iterations,
        }, null, 2);
        if (opts.output) {
            writeFileSync(opts.output, vaultJson);
            console.log(chalk.green(`\n✓ Vault saved to ${opts.output}`));
        }
        else {
            console.log(chalk.dim('\nVault JSON:'));
            console.log(vaultJson);
        }
    }
    catch (err) {
        spinner.fail('Failed to extract vault');
        console.error(chalk.red(err.message));
        console.log(chalk.yellow('\nDefault paths searched:'));
        for (const p of VaultExtractor.getDefaultPaths()) {
            console.log(chalk.dim(`  ${p}`));
        }
        console.log(chalk.yellow('\nTip: Make sure Chrome/Brave is closed before extraction.'));
        process.exit(1);
    }
});
// ---------- crack command (V2 VECTORIZED) ----------
program
    .command('crack')
    .description('Run VECTORIZED password recovery (V2)')
    .requiredOption('-v, --vault <file>', 'Path to vault JSON file')
    .option('-P, --profile <file>', 'Path to user profile JSON file')
    .option('-w, --wordlist <file>', 'Path to custom wordlist file')
    .option('-s, --strategy <strategy>', 'Strategy: profile|dictionary|bruteforce|all', 'all')
    .option('-t, --threads <n>', 'Number of worker threads (default: CPU cores)', '0')
    .option('-c, --concurrent <n>', 'Concurrent PBKDF2 per worker (default: 8)', '8')
    .option('--charset <charset>', 'Brute-force charset (lowercase|alpha|alphanumeric|full)', 'full')
    .option('--min-length <n>', 'Minimum password length', '8')
    .option('--max-length <n>', 'Maximum password length', '16')
    .action(async (opts) => {
    // Load vault
    const vaultJson = readFileSync(opts.vault, 'utf-8');
    const vaultParsed = VaultExtractor.parseVaultJSON(vaultJson);
    const vault = {
        data: vaultParsed.data,
        iv: vaultParsed.iv,
        salt: vaultParsed.salt,
        iterations: vaultParsed.iterations,
        isLegacy: vaultParsed.isLegacy,
    };
    const numWorkers = parseInt(opts.threads) || cpuCount;
    const concurrent = parseInt(opts.concurrent);
    const totalParallel = numWorkers * concurrent;
    console.log(chalk.cyan('\n⚡ V2 VECTORIZED ENGINE'));
    console.log(chalk.cyan('\n   🔍 Vault Analysis:'));
    console.log(chalk.cyan(`      Iterations: ${chalk.bold(vault.iterations.toLocaleString())} PBKDF2-SHA256`));
    console.log(chalk.cyan(`      Type:       ${vault.isLegacy ? chalk.red('Legacy (≤10k)') : chalk.green('Modern')}`));
    console.log(chalk.cyan(`      Salt:       ${vault.salt.substring(0, 16)}...`));
    console.log(chalk.cyan(`      IV:         ${vault.iv.substring(0, 16)}...`));
    console.log(chalk.dim(`\n   Workers: ${numWorkers} threads`));
    console.log(chalk.dim(`   Concurrent/worker: ${concurrent} PBKDF2 calls`));
    console.log(chalk.dim(`   Total parallel: ${chalk.bold.white(String(totalParallel))} simultaneous operations`));
    // Load profile
    let profile = {};
    if (opts.profile) {
        profile = JSON.parse(readFileSync(opts.profile, 'utf-8'));
        const tokenCount = (profile.names?.length || 0) + (profile.words?.length || 0) +
            (profile.dates?.length || 0) + (profile.partials?.length || 0) +
            (profile.oldPasswords?.length || 0);
        console.log(chalk.cyan(`   Profile: ${tokenCount} tokens loaded`));
    }
    // Load custom wordlist
    if (opts.wordlist) {
        const words = readFileSync(opts.wordlist, 'utf-8')
            .split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
        profile.words = [...(profile.words || []), ...words];
        console.log(chalk.cyan(`   Wordlist: ${words.length} words loaded`));
    }
    // Charset
    const charsetMap = PasswordGenerator.CHARSETS;
    const bruteforceCharset = charsetMap[opts.charset] || opts.charset;
    // Determine strategies
    const strategies = opts.strategy === 'all'
        ? ['profile', 'dictionary', 'bruteforce']
        : [opts.strategy];
    const startTime = Date.now();
    let grandTotalAttempts = 0;
    const spinner = ora('Initializing vectorized engine...').start();
    for (const strategy of strategies) {
        if (strategy === 'profile' && (!profile || Object.values(profile).every(v => !v || (Array.isArray(v) && v.length === 0)))) {
            console.log(chalk.dim(`\n   Skipping profile strategy (no profile data)`));
            continue;
        }
        const gen = new PasswordGenerator({
            strategy,
            profile,
            bruteforceCharset,
            minLength: parseInt(opts.minLength),
            maxLength: parseInt(opts.maxLength),
        });
        const estimate = gen.estimateTotal();
        const estCount = strategy === 'bruteforce' ? estimate.bruteforce : (strategy === 'profile' ? estimate.profile : estimate.dictionary);
        console.log(chalk.cyan(`\n   [${strategy.toUpperCase()}] Starting — est. ${estCount} candidates`));
        const engine = new VectorizedCrackEngine(vault, {
            numWorkers,
            concurrentPerWorker: concurrent,
            onProgress: (info) => {
                grandTotalAttempts = info.totalAttempts;
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
                spinner.text = chalk.bold(`[${strategy.toUpperCase()}]`) +
                    ` ${info.totalAttempts.toLocaleString()} attempts | ` +
                    chalk.green(`${info.speed.toFixed(1)}/s`) +
                    ` | ${elapsed}s`;
            },
        });
        // Ctrl+C
        const sigHandler = () => { engine.abort(); spinner.warn('Interrupted'); };
        process.on('SIGINT', sigHandler);
        const batchIterator = gen.batches(concurrent);
        const result = await engine.crack(batchIterator, strategy);
        process.removeListener('SIGINT', sigHandler);
        grandTotalAttempts += result.totalAttempts;
        if (result.found) {
            spinner.succeed(chalk.green.bold('🎉 PASSWORD FOUND!'));
            console.log('\n' + chalk.green('═'.repeat(60)));
            console.log(chalk.green.bold(`  🔑 Password: ${result.password}`));
            if (result.mnemonic) {
                console.log(chalk.green.bold(`  🌱 Seed Phrase: ${result.mnemonic}`));
            }
            console.log(chalk.green('═'.repeat(60)));
            console.log(chalk.yellow.bold('\n⚠  Write down your seed phrase NOW!'));
            console.log(chalk.dim(`\n   Stats: ${result.totalAttempts.toLocaleString()} attempts in ${(result.elapsedMs / 1000).toFixed(1)}s (${result.speed.toFixed(1)}/s)`));
            console.log(chalk.dim(`   V2 speedup: ${numWorkers} workers × ${concurrent} concurrent = ${totalParallel} parallel ops`));
            return;
        }
        console.log(chalk.dim(`   [${strategy.toUpperCase()}] Exhausted ${result.totalAttempts.toLocaleString()} candidates in ${(result.elapsedMs / 1000).toFixed(1)}s (${result.speed.toFixed(1)}/s)`));
    }
    // Not found
    spinner.fail(chalk.red('Password not found'));
    const totalElapsed = (Date.now() - startTime) / 1000;
    console.log(chalk.dim(`\n   Total: ${grandTotalAttempts.toLocaleString()} attempts in ${totalElapsed.toFixed(1)}s`));
    console.log(chalk.yellow('\n   Tips:'));
    console.log(chalk.yellow('   - Add more personal words/dates/old passwords to profile'));
    console.log(chalk.yellow('   - Try with a wordlist: --wordlist rockyou.txt'));
    console.log(chalk.yellow('   - Increase concurrent per worker: --concurrent 16'));
});
// ---------- decrypt command ----------
program
    .command('decrypt')
    .description('Decrypt a vault with a known password')
    .requiredOption('-v, --vault <file>', 'Path to vault JSON file')
    .requiredOption('-p, --password <password>', 'The password to decrypt with')
    .action(async (opts) => {
    const vaultJson = readFileSync(opts.vault, 'utf-8');
    const vault = VaultExtractor.parseVaultJSON(vaultJson);
    const decryptor = new VaultDecryptor();
    const spinner = ora('Decrypting vault...').start();
    const result = await decryptor.tryPassword(opts.password, vault);
    if (result.success && result.vault) {
        spinner.succeed('Vault decrypted!');
        console.log(chalk.green(`\n  🌱 Seed Phrase: ${result.vault.mnemonic}`));
        console.log(chalk.dim(`  📊 Accounts: ${result.vault.numberOfAccounts}`));
        console.log(chalk.dim(`  🔗 HD Path: ${result.vault.hdPath}`));
    }
    else {
        spinner.fail('Decryption failed — wrong password');
        process.exit(1);
    }
});
// ---------- hashcat command ----------
program
    .command('hashcat')
    .description('Export vault in hashcat-compatible format (mode 26600)')
    .requiredOption('-v, --vault <file>', 'Path to vault JSON file')
    .option('-o, --output <file>', 'Save hash to file')
    .action(async (opts) => {
    const vaultJson = readFileSync(opts.vault, 'utf-8');
    const vault = VaultExtractor.parseVaultJSON(vaultJson);
    const hash = VaultExtractor.toHashcatFormat(vault);
    if (opts.output) {
        writeFileSync(opts.output, hash + '\n');
        console.log(chalk.green(`✓ Hashcat hash saved to ${opts.output}`));
    }
    else {
        console.log(hash);
    }
    console.log(chalk.dim(`\nRun with: hashcat -m 26600 -a 0 ${opts.output || 'hash.txt'} wordlist.txt`));
});
// ---------- benchmark command (V1 vs V2) ----------
program
    .command('benchmark')
    .description('Benchmark V1 vs V2 vectorized speed')
    .option('--iterations <n>', 'PBKDF2 iterations', '600000')
    .option('--legacy', 'Test with legacy 10k iterations')
    .option('-t, --threads <n>', 'Worker threads (default: CPU cores)', '0')
    .option('-c, --concurrent <n>', 'Concurrent per worker (default: 8)', '8')
    .option('-n, --count <n>', 'Number of passwords to test', '100')
    .action(async (opts) => {
    const iterations = opts.legacy ? 10_000 : parseInt(opts.iterations);
    const numWorkers = parseInt(opts.threads) || cpuCount;
    const concurrent = parseInt(opts.concurrent);
    const count = parseInt(opts.count);
    console.log(chalk.cyan(`\n⚡ Benchmark — ${iterations.toLocaleString()} PBKDF2 iterations`));
    console.log(chalk.dim(`   V2: ${numWorkers} workers × ${concurrent} concurrent = ${numWorkers * concurrent} parallel`));
    console.log(chalk.dim(`   Testing ${count} passwords\n`));
    // V1: Single-thread baseline
    const spinner1 = ora('V1 single-thread baseline...').start();
    const decryptor = new VaultDecryptor();
    const v1Result = await decryptor.benchmark(iterations);
    spinner1.succeed(`V1 single-thread: ${chalk.yellow(v1Result.attemptsPerSecond.toFixed(2) + '/s')}`);
    // V2: Vectorized engine
    const spinner2 = ora('V2 vectorized engine...').start();
    // Create a dummy vault for benchmarking
    const crypto = await import('node:crypto');
    const dummySalt = crypto.randomBytes(32);
    const dummyIv = crypto.randomBytes(16);
    const dummyKey = crypto.pbkdf2Sync('test', dummySalt, iterations, 32, 'sha256');
    const cipher = crypto.createCipheriv('aes-256-gcm', dummyKey, dummyIv);
    const enc = Buffer.concat([cipher.update('test', 'utf-8'), cipher.final(), cipher.getAuthTag()]);
    const testVault = {
        data: enc.toString('base64'),
        iv: dummyIv.toString('base64'),
        salt: dummySalt.toString('base64'),
        iterations,
    };
    // Generate dummy passwords
    const passwords = [];
    for (let i = 0; i < count; i++) {
        passwords.push(`benchmark_password_${i}_padding`);
    }
    function* batchGen() {
        for (let i = 0; i < passwords.length; i += concurrent) {
            yield passwords.slice(i, i + concurrent);
        }
    }
    const engine = new VectorizedCrackEngine(testVault, {
        numWorkers,
        concurrentPerWorker: concurrent,
    });
    const v2Result = await engine.crack(batchGen(), 'benchmark');
    spinner2.succeed(`V2 vectorized:    ${chalk.green.bold((v2Result.speed).toFixed(2) + '/s')}`);
    const speedup = v2Result.speed / v1Result.attemptsPerSecond;
    console.log(chalk.bold.green(`\n   🚀 Speedup: ${speedup.toFixed(1)}x faster than V1`));
    console.log(chalk.dim(`   V1: ${v1Result.attemptsPerSecond.toFixed(2)}/s → V2: ${v2Result.speed.toFixed(2)}/s`));
});
// ---------- smart-crack command (V3 AI-POWERED) ----------
program
    .command('smart-crack')
    .description('AI-powered password recovery (V3 Intelligence Engine)')
    .requiredOption('-v, --vault <file>', 'Path to vault JSON file')
    .option('-P, --profile <file>', 'Path to user profile JSON file')
    .option('-e, --email <emails...>', 'Email addresses for OSINT enrichment')
    .option('-u, --username <usernames...>', 'Usernames for OSINT enrichment')
    .option('--eth-address <addresses...>', 'Ethereum addresses for ENS/chain analysis')
    .option('--social <urls...>', 'Social media profile URLs')
    .option('--hibp-key <key>', 'Have I Been Pwned API key')
    .option('--etherscan-key <key>', 'Etherscan API key')
    .option('-t, --threads <n>', 'Worker threads (default: CPU cores)', '0')
    .option('-c, --concurrent <n>', 'Concurrent per worker (default: 8)', '8')
    .option('--max-phase1 <n>', 'Max phase 1 candidates (profile-direct)', '200')
    .option('--max-phase2 <n>', 'Max phase 2 candidates (PCFG hybrid)', '10000')
    .option('--max-phase3 <n>', 'Max phase 3 candidates (Markov)', '50000')
    .option('--max-phase4 <n>', 'Max phase 4 candidates (scored brute-force)', '100000')
    .option('--min-length <n>', 'Min password length', '8')
    .option('--max-length <n>', 'Max password length', '20')
    .action(async (opts) => {
    // Load vault
    const vaultJson = readFileSync(opts.vault, 'utf-8');
    const vaultParsed = VaultExtractor.parseVaultJSON(vaultJson);
    const vault = {
        data: vaultParsed.data,
        iv: vaultParsed.iv,
        salt: vaultParsed.salt,
        iterations: vaultParsed.iterations,
        isLegacy: vaultParsed.isLegacy,
    };
    const numWorkers = parseInt(opts.threads) || cpuCount;
    const concurrent = parseInt(opts.concurrent);
    console.log(chalk.magenta('\n🧠 V3 PASSWORD INTELLIGENCE ENGINE'));
    console.log(chalk.cyan('\n   🔍 Vault Analysis:'));
    console.log(chalk.cyan(`      Iterations: ${chalk.bold(vault.iterations.toLocaleString())} PBKDF2-SHA256`));
    console.log(chalk.cyan(`      Type:       ${vault.isLegacy ? chalk.red('Legacy (≤10k)') : chalk.green('Modern')}`));
    console.log(chalk.cyan(`      Salt:       ${vault.salt.substring(0, 16)}...`));
    console.log(chalk.cyan(`      IV:         ${vault.iv.substring(0, 16)}...`));
    const estSpeed = vault.iterations >= 600_000 ? '~118' : vault.iterations >= 100_000 ? '~700' : '~6,000';
    console.log(chalk.cyan(`      Est. speed: ${estSpeed}/s on ${cpuCount}-core CPU (vectorized)`));
    console.log(chalk.dim(`\n   Engine: ${numWorkers} workers × ${concurrent} concurrent = ${numWorkers * concurrent} parallel`));
    // Load profile
    let profile = {};
    if (opts.profile) {
        profile = JSON.parse(readFileSync(opts.profile, 'utf-8'));
        const tokenCount = (profile.names?.length || 0) + (profile.words?.length || 0) +
            (profile.dates?.length || 0) + (profile.partials?.length || 0) +
            (profile.oldPasswords?.length || 0);
        console.log(chalk.cyan(`   Profile: ${tokenCount} tokens loaded`));
    }
    // OSINT enrichment
    const hasOSINT = opts.email || opts.username || opts.ethAddress || opts.social;
    let osintConfig = {};
    if (hasOSINT) {
        osintConfig = {
            emails: opts.email || [],
            usernames: opts.username || [],
            ethAddresses: opts.ethAddress || [],
            socialUrls: opts.social || [],
            apiKeys: {
                hibp: opts.hibpKey,
                etherscan: opts.etherscanKey,
            },
        };
    }
    // Initialize Smart Generator
    const spinner = ora('Training AI models...').start();
    let currentPhase = '';
    const smartGen = new SmartGenerator({
        profile,
        osintConfig: hasOSINT ? osintConfig : undefined,
        maxPhase1: parseInt(opts.maxPhase1),
        maxPhase2: parseInt(opts.maxPhase2),
        maxPhase3: parseInt(opts.maxPhase3),
        maxPhase4: parseInt(opts.maxPhase4),
        minLength: parseInt(opts.minLength),
        maxLength: parseInt(opts.maxLength),
        onPhaseChange: (phase, count) => {
            currentPhase = phase;
            const phaseNames = {
                'phase1-profile-direct': '🎯 Phase 1: Profile Direct',
                'phase2-pcfg-hybrid': '🧬 Phase 2: PCFG + Profile Hybrid',
                'phase3-markov': '🔗 Phase 3: Markov Chain',
                'phase4-bruteforce': '🔨 Phase 4: Scored Brute-Force',
            };
            console.log(chalk.magenta(`\n   ${phaseNames[phase] || phase} — est. ${count.toLocaleString()} candidates`));
        },
    });
    // Run OSINT if configured
    if (hasOSINT) {
        spinner.text = 'Collecting OSINT data...';
        await smartGen.initialize();
    }
    const stats = smartGen.getStats();
    spinner.succeed('AI models trained');
    console.log(chalk.dim(`   PCFG: ${stats.pcfgStructures} structures learned`));
    console.log(chalk.dim(`   Markov: ${stats.markovContexts} contexts`));
    if (stats.osintTokensAdded > 0) {
        console.log(chalk.cyan(`   OSINT: ${stats.osintTokensAdded} tokens added`));
    }
    console.log(chalk.dim(`   Total estimate: ${stats.totalEstimate.toLocaleString()} smart candidates`));
    const startTime = Date.now();
    const crackSpinner = ora('Starting intelligent crack...').start();
    // Create vectorized engine
    const engine = new VectorizedCrackEngine(vault, {
        numWorkers,
        concurrentPerWorker: concurrent,
        onProgress: (info) => {
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
            crackSpinner.text = chalk.bold(`[${currentPhase.split('-')[0]?.toUpperCase() || 'SMART'}]`) +
                ` ${info.totalAttempts.toLocaleString()} attempts | ` +
                chalk.green(`${info.speed.toFixed(1)}/s`) +
                ` | ${elapsed}s`;
        },
    });
    // Ctrl+C handler
    const sigHandler = () => { engine.abort(); crackSpinner.warn('Interrupted'); };
    process.on('SIGINT', sigHandler);
    // Feed smart generator batches to vectorized engine
    const batchIterator = smartGen.batches(concurrent);
    const result = await engine.crack(batchIterator, 'smart');
    process.removeListener('SIGINT', sigHandler);
    if (result.found) {
        crackSpinner.succeed(chalk.green.bold('🎉 PASSWORD FOUND!'));
        console.log('\n' + chalk.green('═'.repeat(60)));
        console.log(chalk.green.bold(`  🔑 Password: ${result.password}`));
        if (result.mnemonic) {
            console.log(chalk.green.bold(`  🌱 Seed Phrase: ${result.mnemonic}`));
        }
        console.log(chalk.green('═'.repeat(60)));
        console.log(chalk.yellow.bold('\n⚠  Write down your seed phrase NOW!'));
        console.log(chalk.dim(`\n   Stats: ${result.totalAttempts.toLocaleString()} attempts in ${(result.elapsedMs / 1000).toFixed(1)}s (${result.speed.toFixed(1)}/s)`));
        console.log(chalk.dim(`   V3 Intelligence Engine: AI-ranked candidates found it in ${result.totalAttempts.toLocaleString()} tries`));
    }
    else {
        crackSpinner.fail(chalk.red('Password not found'));
        const totalElapsed = (Date.now() - startTime) / 1000;
        console.log(chalk.dim(`\n   Exhausted ${result.totalAttempts.toLocaleString()} smart candidates in ${totalElapsed.toFixed(1)}s`));
        console.log(chalk.yellow('\n   Tips:'));
        console.log(chalk.yellow('   - Run with OSINT: --email your@email.com --username yourhandle'));
        console.log(chalk.yellow('   - Add more old passwords to profile.json (most valuable data)'));
        console.log(chalk.yellow('   - Increase phase limits: --max-phase4 500000'));
        console.log(chalk.yellow('   - Fall back to V2 brute-force: mm-recover-v4 crack ...'));
    }
});
// ---------- scan command ----------
program
    .command('scan')
    .description('Scan this machine for encrypted files (wallets, keys, password vaults...)')
    .option('--category <cat>', 'Filter: wallet, password-manager, archive, document, disk, network, mobile')
    .option('--format <id>', 'Filter by format ID (e.g. metamask, bitcoin-core, keepass)')
    .option('-o, --output <dir>', 'Auto-extract found files to this directory')
    .option('--json', 'Output as JSON')
    .action(async (opts) => {
    const crackersPkg = '@metamask-recovery/crackers';
    const { scanAll, scanCategory, scanFormat, extractFile, getCategories } = await import(crackersPkg);
    const spinner = ora('Scanning system for encrypted files...').start();
    let results;
    if (opts.format) {
        results = [scanFormat(opts.format)];
    }
    else if (opts.category) {
        results = scanCategory(opts.category);
    }
    else {
        results = scanAll();
    }
    const totalFound = results.reduce((n, r) => n + r.found.length, 0);
    spinner.succeed(`Scan complete — ${totalFound} encrypted file(s) found`);
    if (opts.json) {
        console.log(JSON.stringify(results, null, 2));
        return;
    }
    if (totalFound === 0) {
        console.log(chalk.yellow('\n  No encrypted files found in default locations.'));
        const categories = getCategories();
        console.log(chalk.dim('\n  Categories searched:'));
        for (const cat of categories) {
            console.log(chalk.dim(`    ${cat.name}: ${cat.formats.join(', ')}`));
        }
        console.log(chalk.dim('\n  Tip: Use crack-file -f <path> for files in custom locations.'));
        return;
    }
    // Group by category
    const categories = getCategories();
    for (const cat of categories) {
        const catResults = results.filter((r) => cat.formats.includes(r.formatId));
        const catFiles = catResults.flatMap((r) => r.found);
        if (catFiles.length === 0)
            continue;
        console.log(chalk.cyan.bold(`\n📁 ${cat.name}:`));
        for (const file of catFiles) {
            const sizeStr = file.size > 0 ? formatSize(file.size) : 'directory';
            const encStr = file.encrypted ? chalk.green('✓ encrypted') : chalk.dim('? unknown');
            const dateStr = file.modified.toLocaleDateString();
            console.log(`  ${chalk.bold(file.formatName.padEnd(22))} ${encStr}`);
            console.log(chalk.dim(`    ${file.filePath}`));
            console.log(chalk.dim(`    ${sizeStr} — modified ${dateStr}${file.note ? ` — ${file.note}` : ''}`));
        }
    }
    // Auto-extract if -o given
    if (opts.output) {
        console.log(chalk.cyan(`\n📦 Extracting ${totalFound} file(s) to ${opts.output}...`));
        let extracted = 0;
        for (const r of results) {
            for (const file of r.found) {
                try {
                    const stat = fs.statSync(file.filePath);
                    if (stat.isDirectory()) {
                        const dest = path.join(opts.output, `${r.formatId}_${path.basename(file.filePath)}`);
                        fs.mkdirSync(opts.output, { recursive: true });
                        fs.cpSync(file.filePath, dest, { recursive: true });
                        console.log(chalk.green(`  ✓ ${file.formatName} (dir): → ${dest}`));
                    }
                    else {
                        const dest = extractFile(file.filePath, opts.output, r.formatId);
                        console.log(chalk.green(`  ✓ ${file.formatName}: → ${dest}`));
                    }
                    extracted++;
                }
                catch (err) {
                    console.log(chalk.red(`  ✗ ${file.formatName}: ${err.message}`));
                }
            }
        }
        console.log(chalk.green.bold(`\n✓ ${extracted} file(s) extracted to ${opts.output}`));
        console.log(chalk.dim(`\nNext: crack-file -f ${opts.output}/<file> -w wordlist.txt`));
    }
    else {
        console.log(chalk.dim(`\nTip: Add -o ./extracted to auto-copy files for cracking.`));
        console.log(chalk.dim(`     Then: crack-file -f ./extracted/<file> -w wordlist.txt`));
    }
});
// ---------- extract-all command ----------
program
    .command('extract-all')
    .description('Find & extract all encrypted files to a working directory')
    .option('--category <cat>', 'Filter by category')
    .option('--format <id>', 'Filter by format')
    .requiredOption('-o, --output <dir>', 'Output directory')
    .action(async (opts) => {
    const crackersPkg = '@metamask-recovery/crackers';
    const { scanAll, scanCategory, scanFormat, extractFile } = await import(crackersPkg);
    const spinner = ora('Scanning & extracting...').start();
    let results;
    if (opts.format) {
        results = [scanFormat(opts.format)];
    }
    else if (opts.category) {
        results = scanCategory(opts.category);
    }
    else {
        results = scanAll();
    }
    const allFiles = results.flatMap((r) => r.found.map((f) => ({ ...f, formatId: r.formatId })));
    spinner.succeed(`Found ${allFiles.length} encrypted file(s)`);
    if (allFiles.length === 0) {
        console.log(chalk.yellow('  No encrypted files found.'));
        return;
    }
    let extracted = 0;
    for (const file of allFiles) {
        try {
            const stat = fs.statSync(file.filePath);
            if (stat.isDirectory()) {
                const dest = path.join(opts.output, `${file.formatId}_${path.basename(file.filePath)}`);
                fs.mkdirSync(opts.output, { recursive: true });
                fs.cpSync(file.filePath, dest, { recursive: true });
                console.log(chalk.green(`  ✓ ${file.formatName} (dir): → ${dest}`));
            }
            else {
                const dest = extractFile(file.filePath, opts.output, file.formatId);
                console.log(chalk.green(`  ✓ ${file.formatName}: → ${dest}`));
            }
            extracted++;
        }
        catch (err) {
            console.log(chalk.red(`  ✗ ${file.formatName}: ${err.message}`));
        }
    }
    console.log(chalk.green.bold(`\n✓ ${extracted}/${allFiles.length} extracted to ${opts.output}/`));
    console.log(chalk.dim(`\nNext: mm-recover-v4 crack-file -f ${opts.output}/<file> -w wordlist.txt`));
});
// ---------- universal crack-file command ----------
program
    .command('crack-file')
    .description('Universal password crack — auto-detect format (23+ supported)')
    .option('-f, --file <path>', 'Path to encrypted file')
    .option('--auto', 'Auto-scan system to find the file (requires --format or --category)')
    .option('--category <cat>', 'Category for --auto scan (wallet, password-manager...)')
    .option('--format <id>', 'Force format (skip auto-detection)')
    .option('-w, --wordlist <file>', 'Path to wordlist file (one password per line)')
    .option('-P, --profile <file>', 'User profile JSON (for smart generation)')
    .option('-t, --threads <n>', 'Number of worker threads', '0')
    .option('-c, --concurrent <n>', 'Concurrent attempts per worker', '8')
    .option('--salt <value>', 'Extra parameter (e.g., email for LastPass)')
    .option('--min-length <n>', 'Minimum password length', '1')
    .option('--max-length <n>', 'Maximum password length', '32')
    .action(async (opts) => {
    const crackersPkg = '@metamask-recovery/crackers';
    const { detectFormat, getCracker, listFormats, scanFormat, scanCategory, scanAll } = await import(crackersPkg);
    const { UniversalCrackEngine } = await import('@metamask-recovery/core');
    // ── Auto mode: scan system to find the file ──
    let filePath = opts.file;
    if (opts.auto && !filePath) {
        const autoSpinner = ora('Auto-scanning system...').start();
        let results;
        if (opts.format) {
            results = [scanFormat(opts.format)];
        }
        else if (opts.category) {
            results = scanCategory(opts.category);
        }
        else {
            results = scanAll();
        }
        const allFiles = results.flatMap((r) => r.found.filter((f) => f.encrypted && f.size > 0)
            .map((f) => ({ ...f, formatId: r.formatId })));
        if (allFiles.length === 0) {
            autoSpinner.fail('No encrypted files found on this system.');
            console.log(chalk.yellow('\n  Use -f <path> to specify a file manually.'));
            console.log(chalk.dim('  Or: mm-recover-v4 scan  to see all default paths.'));
            process.exit(1);
        }
        if (allFiles.length === 1) {
            filePath = allFiles[0].filePath;
            if (!opts.format)
                opts.format = allFiles[0].formatId;
            autoSpinner.succeed(`Auto-found: ${chalk.bold(allFiles[0].formatName)} → ${filePath}`);
        }
        else {
            autoSpinner.succeed(`Found ${allFiles.length} encrypted files:`);
            for (let i = 0; i < allFiles.length; i++) {
                const f = allFiles[i];
                console.log(`  ${chalk.bold(`[${i + 1}]`)} ${f.formatName.padEnd(22)} ${formatSize(f.size).padEnd(10)} ${chalk.dim(f.filePath)}`);
            }
            // Use first match
            filePath = allFiles[0].filePath;
            if (!opts.format)
                opts.format = allFiles[0].formatId;
            console.log(chalk.cyan(`\n  → Using first match: ${filePath}`));
            console.log(chalk.dim(`    Use -f to specify a different file.`));
        }
    }
    if (!filePath) {
        console.log(chalk.red('Error: specify -f <path> or use --auto'));
        process.exit(1);
    }
    // Detect or force format
    const spinner = ora('Detecting file format...').start();
    let cracker;
    if (opts.format) {
        cracker = getCracker(opts.format);
        if (!cracker) {
            spinner.fail(`Unknown format: ${opts.format}`);
            console.log(chalk.dim('\nAvailable formats:'));
            for (const f of listFormats()) {
                console.log(chalk.dim(`  ${f.id.padEnd(20)} ${f.name} (${f.extensions.join(', ')})`));
            }
            process.exit(1);
        }
        spinner.text = `Using format: ${cracker.name}`;
    }
    else {
        cracker = await detectFormat(filePath);
        if (!cracker) {
            spinner.fail('Could not auto-detect format');
            console.log(chalk.yellow('\nUse --format <id> to specify manually.'));
            console.log(chalk.dim('\nSupported formats:'));
            for (const f of listFormats()) {
                console.log(chalk.dim(`  ${f.id.padEnd(20)} ${f.name} (${f.extensions.join(', ')})`));
            }
            process.exit(1);
        }
    }
    spinner.succeed(`Format detected: ${chalk.cyan.bold(cracker.name)}`);
    // Parse file
    const parseSpinner = ora('Parsing encrypted file...').start();
    let params;
    try {
        params = await cracker.parse(filePath);
    }
    catch (err) {
        parseSpinner.fail(`Parse error: ${err.message}`);
        process.exit(1);
    }
    const info = cracker.getInfo(params);
    parseSpinner.succeed('File parsed successfully');
    console.log(chalk.dim(`  Format:     ${info.format}`));
    console.log(chalk.dim(`  KDF:        ${info.kdf}`));
    console.log(chalk.dim(`  Cipher:     ${info.cipher}`));
    console.log(chalk.dim(`  Difficulty:  ${info.difficulty}`));
    if (info.estimatedSpeed)
        console.log(chalk.dim(`  Est. speed: ${info.estimatedSpeed}`));
    // Build password source
    const numWorkers = parseInt(opts.threads) || cpuCount;
    const concurrent = parseInt(opts.concurrent);
    const totalParallel = numWorkers * concurrent;
    console.log(chalk.cyan(`\n⚡ Engine: ${numWorkers} workers × ${concurrent} concurrent = ${totalParallel} parallel`));
    // Password generator function
    function* passwordBatches() {
        // 1. Wordlist (if provided)
        if (opts.wordlist) {
            const words = readFileSync(opts.wordlist, 'utf-8').split('\n').filter(Boolean);
            for (let i = 0; i < words.length; i += concurrent) {
                yield words.slice(i, i + concurrent);
            }
        }
        // 2. Profile-based (if provided)
        if (opts.profile) {
            try {
                const profileData = JSON.parse(readFileSync(opts.profile, 'utf-8'));
                const gen = new PasswordGenerator({ strategy: 'profile', profile: profileData });
                let batch = [];
                for (const pw of gen.generate()) {
                    batch.push(pw);
                    if (batch.length >= concurrent) {
                        yield batch;
                        batch = [];
                    }
                }
                if (batch.length > 0)
                    yield batch;
            }
            catch { }
        }
        // 3. Stdin / common passwords fallback
        const common = [
            'password', 'password1', 'Password1', '123456', '12345678', 'qwerty', 'admin',
            'letmein', 'welcome', 'monkey', 'master', 'dragon', 'login', 'princess',
            'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou', 'batman',
            'access', 'hello', 'charlie', 'donald', '1234567890', 'password123',
        ];
        for (let i = 0; i < common.length; i += concurrent) {
            yield common.slice(i, i + concurrent);
        }
    }
    // Run engine
    const crackSpinner = ora({
        text: `Cracking ${info.format}...`,
        spinner: 'dots12',
    }).start();
    const startTime = Date.now();
    const engine = new UniversalCrackEngine(params, {
        numWorkers,
        concurrentPerWorker: concurrent,
        onProgress: (p) => {
            const elapsed = (Date.now() - startTime) / 1000;
            crackSpinner.text = chalk.cyan(`[${elapsed.toFixed(0)}s] ${p.totalAttempts.toLocaleString()} attempts | ${p.speed.toFixed(1)}/s`);
        },
    });
    const sigHandler = () => { engine.abort(); crackSpinner.warn('Interrupted'); };
    process.on('SIGINT', sigHandler);
    const result = await engine.crack(passwordBatches(), 'universal');
    process.removeListener('SIGINT', sigHandler);
    if (result.found) {
        crackSpinner.succeed(chalk.green.bold('🎉 PASSWORD FOUND!'));
        console.log('\n' + chalk.green('═'.repeat(60)));
        console.log(chalk.green.bold(`  🔑 Password: ${result.password}`));
        if (result.raw) {
            console.log(chalk.dim(`  📄 Decrypted content available (${result.raw.length} bytes)`));
        }
        console.log(chalk.green('═'.repeat(60)));
        console.log(chalk.dim(`\n   Stats: ${result.totalAttempts.toLocaleString()} attempts in ${(result.elapsedMs / 1000).toFixed(1)}s (${result.speed.toFixed(1)}/s)`));
    }
    else {
        crackSpinner.fail(chalk.red('Password not found'));
        console.log(chalk.dim(`\n   Tried ${result.totalAttempts.toLocaleString()} passwords in ${(result.elapsedMs / 1000).toFixed(1)}s`));
        console.log(chalk.yellow('\n   Tips:'));
        console.log(chalk.yellow('   - Provide a wordlist: --wordlist rockyou.txt'));
        console.log(chalk.yellow('   - Use a profile: --profile profile.json'));
        console.log(chalk.yellow('   - Increase threads: --threads 16'));
    }
});
// ---------- deep-scan command ----------
program
    .command('deep-scan')
    .description('Forensic deep-scan: Time Machine, iCloud, external drives, old profiles, Spotlight...')
    .option('--format <id>', 'Only search for a specific format (e.g. metamask, bitcoin-core)')
    .option('--no-time-machine', 'Skip Time Machine backups')
    .option('--no-icloud', 'Skip iCloud Drive')
    .option('--no-volumes', 'Skip external volumes')
    .option('--no-spotlight', 'Skip Spotlight search')
    .option('--no-trash', 'Skip Trash')
    .option('--depth <n>', 'Max directory depth for recursive search', '6')
    .option('-o, --output <dir>', 'Extract found files to this directory')
    .option('--json', 'Output raw JSON')
    .action(async (opts) => {
    const crackersPkg = '@metamask-recovery/crackers';
    const { DeepScanner, extractFile } = await import(crackersPkg);
    console.log(chalk.cyan.bold('\n🔬 Deep Recovery Scanner'));
    console.log(chalk.dim('   Searching Time Machine, iCloud, external drives, Spotlight, Trash...\n'));
    const spinner = ora({ text: 'Starting deep scan...', spinner: 'dots12' }).start();
    const scanner = new DeepScanner({
        formats: opts.format ? [opts.format] : [],
        maxDepth: parseInt(opts.depth) || 6,
        timeMachine: opts.timeMachine !== false,
        icloud: opts.icloud !== false,
        externalVolumes: opts.volumes !== false,
        spotlight: opts.spotlight !== false,
        trash: opts.trash !== false,
        firefox: true,
        allProfiles: true,
        onProgress: (msg) => { spinner.text = msg; },
    });
    const results = await scanner.scan();
    spinner.succeed(`Deep scan complete — ${results.length} vault(s) / encrypted file(s) found`);
    if (results.length === 0) {
        console.log(chalk.yellow('\n  No vault files found anywhere on this system.'));
        console.log(chalk.dim('\n  Checked: Time Machine, browser profiles, iCloud, external volumes,'));
        console.log(chalk.dim('           Trash, Spotlight index, other user accounts.'));
        console.log(chalk.dim('\n  If the vault was on another computer, try:'));
        console.log(chalk.dim('   1. Connect the old drive as an external volume'));
        console.log(chalk.dim('   2. Restore from a Time Machine backup'));
        console.log(chalk.dim('   3. Check iCloud/Google Drive for any backups'));
        return;
    }
    if (opts.json) {
        console.log(JSON.stringify(results, null, 2));
        return;
    }
    // Group by source type
    const sourceGroups = new Map();
    for (const r of results) {
        const key = r.sourceType;
        if (!sourceGroups.has(key))
            sourceGroups.set(key, []);
        sourceGroups.get(key).push(r);
    }
    const sourceLabels = {
        'time-machine': '🕐 Time Machine Backups',
        'chrome-sync': '🌐 Browser Profiles',
        'firefox-profile': '🦊 Firefox Profiles',
        'icloud': '☁️  iCloud Drive',
        'external-volume': '💾 External Volumes',
        'trash': '🗑️  Trash',
        'spotlight': '🔍 Spotlight Index',
        'old-profile': '👤 Other User Profiles',
        'local-backup': '📂 Local Backup Folders',
        'usb-drive': '🔌 USB Drives',
    };
    for (const [sourceType, items] of sourceGroups) {
        const label = sourceLabels[sourceType] || sourceType;
        console.log(chalk.cyan.bold(`\n${label}:`));
        for (const r of items) {
            const confColor = r.confidence === 'high' ? chalk.green : r.confidence === 'medium' ? chalk.yellow : chalk.dim;
            const confStr = confColor(`[${r.confidence}]`);
            const sizeStr = r.size > 0 ? formatSize(r.size) : 'dir';
            const dateStr = r.modified.toLocaleDateString();
            console.log(`  ${confStr} ${chalk.bold(r.formatHint.padEnd(20))} ${chalk.dim(r.source)}`);
            console.log(chalk.dim(`       ${r.filePath}`));
            console.log(chalk.dim(`       ${sizeStr} — ${dateStr}${r.note ? ` — ${r.note}` : ''}`));
            if (r.backupDate) {
                console.log(chalk.dim(`       Backup date: ${r.backupDate.toLocaleDateString()}`));
            }
        }
    }
    // Summary
    const highConf = results.filter((r) => r.confidence === 'high');
    const medConf = results.filter((r) => r.confidence === 'medium');
    console.log(chalk.bold(`\n📊 Summary: ${chalk.green(`${highConf.length} high`)} / ${chalk.yellow(`${medConf.length} medium`)} / ${chalk.dim(`${results.length - highConf.length - medConf.length} low`)} confidence`));
    // Auto-extract if -o
    if (opts.output) {
        console.log(chalk.cyan(`\n📦 Extracting to ${opts.output}...`));
        let extracted = 0;
        for (const r of results) {
            if (r.confidence === 'low')
                continue; // skip low-confidence
            try {
                const stat = fs.statSync(r.filePath);
                if (stat.isDirectory()) {
                    const dest = path.join(opts.output, `${r.formatHint}_${path.basename(r.filePath)}`);
                    fs.mkdirSync(opts.output, { recursive: true });
                    fs.cpSync(r.filePath, dest, { recursive: true });
                    console.log(chalk.green(`  ✓ ${r.formatHint}: → ${dest}`));
                }
                else {
                    const dest = extractFile(r.filePath, opts.output, r.formatHint);
                    console.log(chalk.green(`  ✓ ${r.formatHint}: → ${dest}`));
                }
                extracted++;
            }
            catch (err) {
                console.log(chalk.red(`  ✗ ${r.formatHint}: ${err.message}`));
            }
        }
        console.log(chalk.green.bold(`\n✓ ${extracted} file(s) extracted to ${opts.output}/`));
    }
    else if (highConf.length > 0) {
        console.log(chalk.dim(`\nTip: Add -o ./recovered to extract found vaults.`));
        console.log(chalk.dim(`     Then: crack-file -f ./recovered/<file> -w wordlist.txt`));
    }
});
// ---------- formats command ----------
program
    .command('formats')
    .description('List all supported encrypted file formats')
    .action(async () => {
    const crackersPkg2 = '@metamask-recovery/crackers';
    const { listFormats } = await import(crackersPkg2);
    const formats = listFormats();
    console.log(chalk.cyan.bold(`\n📋 Supported Formats (${formats.length}):\n`));
    for (const f of formats) {
        console.log(`  ${chalk.bold(f.id.padEnd(22))} ${f.name}`);
        console.log(chalk.dim(`  ${''.padEnd(22)} ${f.description}`));
        console.log(chalk.dim(`  ${''.padEnd(22)} Extensions: ${f.extensions.join(', ')}\n`));
    }
});
program.parse();
//# sourceMappingURL=index.js.map