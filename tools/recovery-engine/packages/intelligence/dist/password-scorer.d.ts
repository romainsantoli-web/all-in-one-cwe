/**
 * Password Scorer & Ranker
 *
 * Combines multiple scoring signals to rank password candidates
 * by probability of being correct:
 *
 * 1. PCFG structural probability (how common is this password structure?)
 * 2. Markov transition score (do the character sequences look natural?)
 * 3. Profile affinity (does it contain the user's personal tokens?)
 * 4. Pattern frequency (common patterns like Name+Year+Symbol)
 * 5. Length penalty/bonus (MetaMask requires 8+ chars)
 *
 * Final score = weighted combination → priority queue → candidates in order.
 */
import { type UserProfile } from '@metamask-recovery/core';
import { PCFGEngine } from './pcfg-engine.js';
import { MarkovModel } from './markov-model.js';
export interface ScoredCandidate {
    password: string;
    score: number;
    breakdown: {
        pcfg: number;
        markov: number;
        profileAffinity: number;
        patternBonus: number;
        lengthFactor: number;
    };
}
export interface ScorerOptions {
    /** Weight for PCFG score (default: 0.30) */
    pcfgWeight?: number;
    /** Weight for Markov score (default: 0.25) */
    markovWeight?: number;
    /** Weight for profile affinity (default: 0.30) */
    profileWeight?: number;
    /** Weight for known pattern bonus (default: 0.10) */
    patternWeight?: number;
    /** Weight for length factor (default: 0.05) */
    lengthWeight?: number;
}
export declare class PasswordScorer {
    private pcfg;
    private markov;
    private profile;
    private profileTokens;
    private profileTokensLower;
    private weights;
    constructor(pcfg: PCFGEngine, markov: MarkovModel, profile: UserProfile, options?: ScorerOptions);
    /**
     * Score a single password candidate.
     */
    score(password: string): ScoredCandidate;
    /**
     * Score and rank a batch of candidates.
     * Returns sorted by score descending.
     */
    rankBatch(passwords: string[]): ScoredCandidate[];
    /**
     * Score using PCFG model.
     * We check the structure probability from the PCFG.
     */
    private scorePCFG;
    /**
     * Score based on how many profile tokens appear in the password.
     */
    private scoreProfileAffinity;
    /**
     * Score based on known password patterns (especially crypto-related).
     */
    private scorePatterns;
    /**
     * Length factor: passwords between 8-14 chars are most common.
     */
    private scoreLengthFactor;
}
//# sourceMappingURL=password-scorer.d.ts.map