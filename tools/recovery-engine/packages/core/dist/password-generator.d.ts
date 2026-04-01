/**
 * Password Generator — Produces password candidates in 3 cascading levels:
 *
 * Level 1: Profile-based (user's personal info → targeted combinations)
 * Level 2: Dictionary + smart mutations
 * Level 3: Brute-force (exhaustive, charset-based)
 *
 * All generators are lazy iterables to keep memory constant.
 */
/** Strategy for password generation */
export type Strategy = 'profile' | 'dictionary' | 'bruteforce' | 'all';
/** User's personal profile for targeted candidate generation */
export interface UserProfile {
    /** First names, last names, nicknames */
    names?: string[];
    /** Dates important to user (birthdays, etc.) — formats like "1990", "19900315", "15/03/1990" */
    dates?: string[];
    /** Pet names, favorite words, hobbies */
    words?: string[];
    /** Known partial passwords or password patterns the user remembers */
    partials?: string[];
    /** Previous passwords the user has used in the past */
    oldPasswords?: string[];
    /** Custom wordlist file path (one word per line) */
    wordlistPath?: string;
}
/** Configuration for the generator */
export interface GeneratorOptions {
    strategy: Strategy;
    profile?: UserProfile;
    /** Charset for brute-force (default: alphanumeric + symbols) */
    bruteforceCharset?: string;
    /** Minimum password length (default: 8, MetaMask minimum) */
    minLength?: number;
    /** Maximum password length for brute-force (default: 16) */
    maxLength?: number;
    /** Resume brute-force from this position index */
    resumeFrom?: bigint;
}
export declare class PasswordGenerator {
    private options;
    constructor(options: GeneratorOptions);
    /**
     * Generate password candidates as a lazy iterable.
     * Cascades through strategies: profile → dictionary → brute-force.
     */
    generate(): Generator<string>;
    /**
     * Get batches of N candidates at a time.
     */
    batches(batchSize?: number): Generator<string[]>;
    /**
     * Estimate the total number of candidates for the current configuration.
     */
    estimateTotal(): {
        profile: number;
        dictionary: number;
        bruteforce: string;
        total: string;
    };
    /** Available charset presets */
    static readonly CHARSETS: {
        lowercase: string;
        alpha: string;
        alphanumeric: string;
        full: string;
    };
}
//# sourceMappingURL=password-generator.d.ts.map