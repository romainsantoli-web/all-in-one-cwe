/**
 * Probabilistic Context-Free Grammar (PCFG) Engine
 *
 * Learns password structures from training data and generates candidates
 * in probability-descending order.
 *
 * Grammar example:
 *   S → L4 D4 Y1    p=0.12   (4 lowercase + 4 digits + 1 symbol)
 *   S → U1 L5 D2    p=0.08   (1 upper + 5 lower + 2 digits)
 *
 * Each terminal class:
 *   L4 → "roma" p=0.3, "pass" p=0.2, "love" p=0.1, ...
 *   D4 → "2024" p=0.15, "1990" p=0.1, "1234" p=0.08, ...
 *   Y1 → "!" p=0.4, "@" p=0.15, "#" p=0.1, ...
 *
 * Reference: Weir et al. "Password Cracking Using Probabilistic CFGs" (2009)
 */
/** A complete candidate: structure + fills for each segment */
interface Candidate {
    password: string;
    probability: number;
    structure: string;
}
export declare class PCFGEngine {
    /** Structure rules: key → { structure, probability, count } */
    private structures;
    /** Terminal fills: "L4" → [{ value: "roma", probability, count }, ...] */
    private terminals;
    /** Total training samples */
    private totalSamples;
    /**
     * Train the PCFG model on a set of passwords.
     * Can be called multiple times to add more training data.
     */
    train(passwords: string[]): void;
    /**
     * Train on user profile data — generates synthetic passwords from profile tokens.
     */
    trainOnProfile(profile: {
        names?: string[];
        dates?: string[];
        words?: string[];
        partials?: string[];
        oldPasswords?: string[];
    }): void;
    private recomputeProbabilities;
    /**
     * Generate password candidates in probability-descending order.
     * Uses a priority queue to efficiently enumerate the cross-product
     * of structures × terminal fills.
     */
    generate(maxCandidates?: number): Generator<Candidate>;
    private computeCandidateProbability;
    private buildPassword;
    /** Get statistics about the trained model */
    getStats(): {
        totalSamples: number;
        structureCount: number;
        topStructures: Array<{
            key: string;
            probability: number;
        }>;
        terminalGroups: number;
    };
    /** Serialize model to JSON */
    toJSON(): string;
    /** Load model from JSON */
    static fromJSON(json: string): PCFGEngine;
}
export {};
//# sourceMappingURL=pcfg-engine.d.ts.map