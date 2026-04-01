/**
 * Smart Password Generator — V3 Password Intelligence Engine
 *
 * Combines all intelligence sources to generate password candidates
 * in probability-descending order:
 *
 * Phase 1: Profile-based (old passwords, exact patterns) — ~100 candidates
 * Phase 2: PCFG + Profile hybrid (learned structures × personal tokens) — ~10,000
 * Phase 3: Markov-generated (character-level patterns) — ~50,000
 * Phase 4: Scored brute-force (standard candidates ranked by scorer) — ~100,000+
 *
 * The key insight: instead of blindly iterating 10^15 candidates,
 * we test 10^4 smart candidates first. At 118/s (V2 engine @ 600k iter),
 * 10,000 candidates = 85 seconds.
 */
import { PasswordGenerator } from '@metamask-recovery/core';
import { PCFGEngine } from './pcfg-engine.js';
import { MarkovModel } from './markov-model.js';
import { PasswordScorer } from './password-scorer.js';
import { OSINTCollector } from './osint-collector.js';
// ---------- Pre-built training data ----------
/**
 * Common password patterns from public research.
 * These are NOT real leaked passwords — they are synthetic examples
 * that represent the most common structural patterns.
 */
const COMMON_TRAINING_PASSWORDS = [
    // Name + digits patterns (most common)
    'Michael123', 'Jennifer1990', 'David2024!', 'Jessica12345',
    'Robert1234', 'Sarah2020', 'James123!', 'Ashley1988',
    'Thomas2023', 'Amanda92!', 'Daniel1995', 'Stephanie123',
    'Matthew2021!', 'Nicole1987', 'Christopher99', 'Elizabeth2024',
    'Andrew123!', 'Michelle1994', 'Joshua2019', 'Samantha!123',
    // Lowercase + numbers
    'password123', 'letmein2024', 'welcome123!', 'admin12345',
    'monkey123', 'dragon2024!', 'master1234', 'shadow123!',
    'sunshine99', 'football123', 'baseball2024', 'soccer2023',
    // Crypto-specific
    'Metamask2024!', 'Bitcoin123!', 'Ethereum2024', 'Crypto1234!',
    'Hodl2024!', 'DeFi2023!', 'Wallet123!', 'Blockchain99',
    'ToTheMoon!', 'LamboSoon!', 'DiamondHands1', 'Satoshi2024',
    // Two words
    'SunShine', 'BlueSky', 'RedDragon', 'GreenDay',
    'BlackCat', 'WhiteWolf', 'DarkKnight', 'IronMan',
    // French patterns
    'Bonjour123', 'Soleil2024!', 'Amour1234', 'France2024',
    'Paris2023!', 'Marseille13', 'Lyon2024!', 'Toulouse31',
    // Location + postcode
    'Paris75000', 'London2024', 'NewYork123', 'Berlin2024!',
    // Mixed patterns
    'P@ssw0rd123', 'Qwerty123!', 'Azerty2024!', 'Abc12345!',
    'Test1234!', 'Hello2024!', 'World1234', 'Admin2024!',
    // Repeated suffixes
    'Romain123!!', 'Thomas2024!!', 'Julie99!!', 'Pierre13540!',
];
// ---------- Smart Generator ----------
export class SmartGenerator {
    profile;
    pcfg;
    markov;
    scorer;
    options;
    osintResult = null;
    constructor(options) {
        this.options = {
            profile: options.profile,
            osintConfig: options.osintConfig || {},
            maxPhase1: options.maxPhase1 ?? 200,
            maxPhase2: options.maxPhase2 ?? 10_000,
            maxPhase3: options.maxPhase3 ?? 50_000,
            maxPhase4: options.maxPhase4 ?? 100_000,
            minLength: options.minLength ?? 8,
            maxLength: options.maxLength ?? 20,
            bruteforceCharset: options.bruteforceCharset ?? '',
            onPhaseChange: options.onPhaseChange ?? (() => { }),
        };
        this.profile = { ...options.profile };
        this.pcfg = new PCFGEngine();
        this.markov = new MarkovModel({ order: 3 });
        // Train models
        this.trainModels();
        this.scorer = new PasswordScorer(this.pcfg, this.markov, this.profile);
    }
    /**
     * Initialize: run OSINT collection and retrain models with enriched data.
     */
    async initialize() {
        if (this.options.osintConfig && Object.keys(this.options.osintConfig).length > 0) {
            const collector = new OSINTCollector(this.options.osintConfig);
            const osintData = await collector.collect();
            this.osintResult = osintData;
            this.profile = collector.enrichProfile(this.profile);
            // Retrain with enriched profile
            this.trainModels();
            this.scorer = new PasswordScorer(this.pcfg, this.markov, this.profile);
        }
    }
    trainModels() {
        // Train on common patterns first
        this.pcfg.train(COMMON_TRAINING_PASSWORDS);
        this.markov.train(COMMON_TRAINING_PASSWORDS);
        // Train on user's old passwords (most valuable data)
        if (this.profile.oldPasswords?.length) {
            this.pcfg.train(this.profile.oldPasswords);
            this.markov.train(this.profile.oldPasswords);
        }
        // Train PCFG on profile tokens (generates synthetic structures)
        this.pcfg.trainOnProfile(this.profile);
    }
    /**
     * Generate ALL candidates in priority order across all 4 phases.
     * This is the main entry point — yields password strings ready for cracking.
     */
    *generateAll() {
        const seen = new Set();
        const minLen = this.options.minLength;
        const maxLen = this.options.maxLength;
        const emit = function* (pw) {
            if (pw.length >= minLen && pw.length <= maxLen && !seen.has(pw)) {
                seen.add(pw);
                yield pw;
            }
        };
        // ── Phase 1: Direct profile candidates ──
        this.options.onPhaseChange('phase1-profile-direct', this.options.maxPhase1);
        yield* this.generatePhase1(seen);
        // ── Phase 2: PCFG + Profile hybrid ──
        this.options.onPhaseChange('phase2-pcfg-hybrid', this.options.maxPhase2);
        yield* this.generatePhase2(seen);
        // ── Phase 3: Markov-generated candidates ──
        this.options.onPhaseChange('phase3-markov', this.options.maxPhase3);
        yield* this.generatePhase3(seen);
        // ── Phase 4: Scored brute-force fallback ──
        this.options.onPhaseChange('phase4-bruteforce', this.options.maxPhase4);
        yield* this.generatePhase4(seen);
    }
    /**
     * Get candidates in batches (for V2 vectorized engine integration).
     */
    *batches(batchSize = 8) {
        let batch = [];
        for (const pw of this.generateAll()) {
            batch.push(pw);
            if (batch.length >= batchSize) {
                yield batch;
                batch = [];
            }
        }
        if (batch.length > 0) {
            yield batch;
        }
    }
    /**
     * Get statistics about the generator.
     */
    getStats() {
        const pcfgStats = this.pcfg.getStats();
        const markovStats = this.markov.getStats();
        return {
            phase1Count: this.options.maxPhase1,
            phase2Count: this.options.maxPhase2,
            phase3Count: this.options.maxPhase3,
            phase4Count: this.options.maxPhase4,
            osintTokensAdded: this.osintResult
                ? this.osintResult.names.length + this.osintResult.dates.length +
                    this.osintResult.words.length + this.osintResult.partials.length
                : 0,
            pcfgStructures: pcfgStats.structureCount,
            markovContexts: markovStats.contextCount,
            totalEstimate: this.options.maxPhase1 + this.options.maxPhase2 +
                this.options.maxPhase3 + this.options.maxPhase4,
        };
    }
    // ---------- Phase 1: Profile-Direct ----------
    *generatePhase1(seen) {
        const minLen = this.options.minLength;
        const maxLen = this.options.maxLength;
        let count = 0;
        // 1a. Old passwords (highest priority — user might reuse with small variations)
        for (const pw of this.profile.oldPasswords || []) {
            if (this.emitCheck(pw, seen, minLen, maxLen)) {
                yield pw;
                count++;
            }
            // Variations of old passwords
            for (const v of this.generateVariations(pw)) {
                if (count >= this.options.maxPhase1)
                    return;
                if (this.emitCheck(v, seen, minLen, maxLen)) {
                    yield v;
                    count++;
                }
            }
        }
        // 1b. Direct profile combinations (CUPP-style)
        const gen = new PasswordGenerator({
            strategy: 'profile',
            profile: this.profile,
            minLength: minLen,
            maxLength: maxLen,
        });
        for (const pw of gen.generate()) {
            if (count >= this.options.maxPhase1)
                return;
            if (this.emitCheck(pw, seen, minLen, maxLen)) {
                yield pw;
                count++;
            }
        }
    }
    // ---------- Phase 2: PCFG + Profile Hybrid ----------
    *generatePhase2(seen) {
        const minLen = this.options.minLength;
        const maxLen = this.options.maxLength;
        let count = 0;
        // Generate from PCFG in probability order
        for (const candidate of this.pcfg.generate(this.options.maxPhase2 * 2)) {
            if (count >= this.options.maxPhase2)
                return;
            const pw = candidate.password;
            if (this.emitCheck(pw, seen, minLen, maxLen)) {
                yield pw;
                count++;
            }
            // Also generate profile-augmented variants
            for (const v of this.augmentWithProfile(pw)) {
                if (count >= this.options.maxPhase2)
                    return;
                if (this.emitCheck(v, seen, minLen, maxLen)) {
                    yield v;
                    count++;
                }
            }
        }
    }
    // ---------- Phase 3: Markov-Generated ----------
    *generatePhase3(seen) {
        const minLen = this.options.minLength;
        const maxLen = this.options.maxLength;
        let count = 0;
        // Generate from Markov model with varying temperatures
        for (const temp of [0.5, 0.7, 0.9, 1.0, 1.2]) {
            for (const { password } of this.markov.generateCandidates(Math.floor(this.options.maxPhase3 / 5), temp)) {
                if (count >= this.options.maxPhase3)
                    return;
                if (this.emitCheck(password, seen, minLen, maxLen)) {
                    yield password;
                    count++;
                }
            }
        }
    }
    // ---------- Phase 4: Scored Brute-Force ----------
    *generatePhase4(seen) {
        const minLen = this.options.minLength;
        const maxLen = this.options.maxLength;
        let count = 0;
        // Use the standard dictionary + brute-force generators
        // but score and re-rank in batches
        const batchSize = 1000;
        const gen = new PasswordGenerator({
            strategy: 'dictionary',
            profile: this.profile,
            minLength: minLen,
            maxLength: maxLen,
        });
        let batch = [];
        for (const pw of gen.generate()) {
            if (count >= this.options.maxPhase4)
                return;
            batch.push(pw);
            if (batch.length >= batchSize) {
                // Score and rank the batch
                const ranked = this.scorer.rankBatch(batch);
                for (const scored of ranked) {
                    if (count >= this.options.maxPhase4)
                        return;
                    if (this.emitCheck(scored.password, seen, minLen, maxLen)) {
                        yield scored.password;
                        count++;
                    }
                }
                batch = [];
            }
        }
        // Flush remaining
        if (batch.length > 0) {
            const ranked = this.scorer.rankBatch(batch);
            for (const scored of ranked) {
                if (count >= this.options.maxPhase4)
                    return;
                if (this.emitCheck(scored.password, seen, minLen, maxLen)) {
                    yield scored.password;
                    count++;
                }
            }
        }
    }
    // ---------- Helpers ----------
    emitCheck(pw, seen, minLen, maxLen) {
        if (pw.length < minLen || pw.length > maxLen)
            return false;
        if (seen.has(pw))
            return false;
        seen.add(pw);
        return true;
    }
    /**
     * Generate common variations of a password.
     */
    *generateVariations(password) {
        // Case variations
        yield password.toLowerCase();
        yield password.toUpperCase();
        yield password.charAt(0).toUpperCase() + password.slice(1).toLowerCase();
        // Add/remove trailing symbols
        const symbols = ['!', '!!', '@', '#', '$', '1', '12', '123'];
        for (const s of symbols) {
            yield password + s;
            if (password.endsWith(s)) {
                yield password.slice(0, -s.length);
            }
        }
        // Increment/decrement numbers
        const numMatch = password.match(/(\d+)$/);
        if (numMatch) {
            const base = password.slice(0, -numMatch[0].length);
            const num = parseInt(numMatch[0]);
            yield base + String(num + 1);
            yield base + String(num - 1);
            yield base + String(num + 1) + '!';
        }
        // Leet speak conversions
        const leetMap = { a: '@', e: '3', i: '1', o: '0', s: '$', t: '7' };
        let leet = '';
        for (const c of password) {
            leet += leetMap[c.toLowerCase()] || c;
        }
        if (leet !== password)
            yield leet;
        // Reverse leet
        const revLeet = { '@': 'a', '3': 'e', '1': 'i', '0': 'o', '$': 's', '7': 't' };
        let unleet = '';
        for (const c of password) {
            unleet += revLeet[c] || c;
        }
        if (unleet !== password)
            yield unleet;
    }
    /**
     * Augment a PCFG-generated password with profile tokens.
     * Replace generic terminals with personal data.
     */
    *augmentWithProfile(password) {
        const names = this.profile.names || [];
        const partials = this.profile.partials || [];
        // Try replacing the lowercase/uppercase portion with profile names
        for (const name of [...names, ...partials]) {
            if (name.length < 3)
                continue;
            // Replace first word-like segment
            const replaced = password.replace(/^[A-Za-z]+/, name);
            if (replaced !== password)
                yield replaced;
            // Prepend profile token to numeric portion
            const numPart = password.match(/\d+[!@#$%]*$/);
            if (numPart)
                yield name + numPart[0];
        }
    }
}
//# sourceMappingURL=smart-generator.js.map