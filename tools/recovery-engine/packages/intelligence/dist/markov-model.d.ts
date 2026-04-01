/**
 * Markov Chain Password Model
 *
 * Learns character-level transition probabilities from training passwords.
 * Used to score how "natural" a password looks and to generate candidates
 * that follow realistic character patterns.
 *
 * Example: After seeing "ro", the probability of "m" is high (romain)
 *          while the probability of "z" is low.
 *
 * Uses N-gram chains (default: 3-gram) for better context.
 */
export interface MarkovOptions {
    /** N-gram order (default: 3) */
    order?: number;
    /** Smoothing factor for unseen transitions (default: 0.001) */
    smoothing?: number;
}
export declare class MarkovModel {
    private order;
    private smoothing;
    /** Transition counts: context → { nextChar → count } */
    private transitions;
    /** All observed characters */
    private alphabet;
    private totalSamples;
    constructor(options?: MarkovOptions);
    /**
     * Train on a list of passwords.
     */
    train(passwords: string[]): void;
    /**
     * Score a password: log-probability under the Markov model.
     * Higher score = more likely password pattern.
     * Returns a value between 0 and 1 (normalized).
     */
    score(password: string): number;
    /**
     * Get the transition probability P(nextChar | context).
     * Uses Laplace smoothing for unseen transitions.
     */
    private getTransitionProbability;
    /**
     * Generate a password by sampling from the Markov chain.
     * Optionally use temperature to control randomness.
     */
    generate(maxLength?: number, temperature?: number): string;
    /**
     * Generate multiple candidate passwords, sorted by probability.
     */
    generateCandidates(count?: number, temperature?: number): Generator<{
        password: string;
        score: number;
    }>;
    private sampleNext;
    /** Get model statistics */
    getStats(): {
        totalSamples: number;
        alphabetSize: number;
        contextCount: number;
        order: number;
    };
    /** Serialize model */
    toJSON(): string;
    /** Deserialize model */
    static fromJSON(json: string): MarkovModel;
}
//# sourceMappingURL=markov-model.d.ts.map