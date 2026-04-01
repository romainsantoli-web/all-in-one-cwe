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
import { type UserProfile } from '@metamask-recovery/core';
import { type OSINTConfig } from './osint-collector.js';
export interface SmartGeneratorOptions {
    /** User profile */
    profile: UserProfile;
    /** OSINT configuration (optional) */
    osintConfig?: OSINTConfig;
    /** Maximum candidates per phase */
    maxPhase1?: number;
    maxPhase2?: number;
    maxPhase3?: number;
    maxPhase4?: number;
    /** Minimum password length (default: 8, MetaMask minimum) */
    minLength?: number;
    /** Maximum password length (default: 20) */
    maxLength?: number;
    /** Brute-force charset */
    bruteforceCharset?: string;
    /** Progress callback */
    onPhaseChange?: (phase: string, estimatedCount: number) => void;
}
export interface SmartGeneratorStats {
    phase1Count: number;
    phase2Count: number;
    phase3Count: number;
    phase4Count: number;
    osintTokensAdded: number;
    pcfgStructures: number;
    markovContexts: number;
    totalEstimate: number;
}
export declare class SmartGenerator {
    private profile;
    private pcfg;
    private markov;
    private scorer;
    private options;
    private osintResult;
    constructor(options: SmartGeneratorOptions);
    /**
     * Initialize: run OSINT collection and retrain models with enriched data.
     */
    initialize(): Promise<void>;
    private trainModels;
    /**
     * Generate ALL candidates in priority order across all 4 phases.
     * This is the main entry point — yields password strings ready for cracking.
     */
    generateAll(): Generator<string>;
    /**
     * Get candidates in batches (for V2 vectorized engine integration).
     */
    batches(batchSize?: number): Generator<string[]>;
    /**
     * Get statistics about the generator.
     */
    getStats(): SmartGeneratorStats;
    private generatePhase1;
    private generatePhase2;
    private generatePhase3;
    private generatePhase4;
    private emitCheck;
    /**
     * Generate common variations of a password.
     */
    private generateVariations;
    /**
     * Augment a PCFG-generated password with profile tokens.
     * Replace generic terminals with personal data.
     */
    private augmentWithProfile;
}
//# sourceMappingURL=smart-generator.d.ts.map