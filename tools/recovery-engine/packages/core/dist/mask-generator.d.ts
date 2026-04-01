/**
 * Mask Attack Generator
 *
 * Generates password candidates from mask patterns (hashcat-compatible).
 *
 * Built-in charsets:
 *   ?l = lowercase (a-z)
 *   ?u = uppercase (A-Z)
 *   ?d = digit (0-9)
 *   ?s = special (!@#$%^&*…)
 *   ?a = all printable ASCII
 *   ?b = byte (0x00-0xFF)
 *   ?h = hex lowercase (0-9a-f)
 *   ?H = hex uppercase (0-9A-F)
 *
 * Custom charsets: ?1 ?2 ?3 ?4 (user-defined)
 *
 * Examples:
 *   "?u?l?l?l?l?d?d?d"          → Password123 style
 *   "pass?d?d?d?d"               → pass0000–pass9999
 *   "?1?1?1?1?d?d" --custom1 "aeiou"  → vowels + digits
 */
export interface MaskOptions {
    /** Custom charset 1 (?1) */
    custom1?: string;
    /** Custom charset 2 (?2) */
    custom2?: string;
    /** Custom charset 3 (?3) */
    custom3?: string;
    /** Custom charset 4 (?4) */
    custom4?: string;
    /** Resume from this index (0-based) */
    resumeFrom?: bigint;
    /** Maximum candidates to generate (0 = unlimited) */
    maxCandidates?: bigint;
}
export interface MaskPosition {
    charset: string;
    isFixed: boolean;
    fixedChar?: string;
}
/**
 * Parse a mask string into an array of position descriptors.
 */
export declare function parseMask(mask: string, options?: MaskOptions): MaskPosition[];
/**
 * Calculate total keyspace for a parsed mask.
 */
export declare function maskKeyspace(positions: MaskPosition[]): bigint;
/**
 * Generate all candidates from a mask pattern.
 * Yields one password at a time (lazy iterator).
 */
export declare function maskGenerator(mask: string, options?: MaskOptions): Generator<string>;
/**
 * Generate candidates in batches for multi-threaded consumption.
 */
export declare function maskBatchGenerator(mask: string, batchSize?: number, options?: MaskOptions): Generator<string[]>;
/**
 * Incremental mask attack: try progressively longer masks.
 * Example: ?d?d?d?d?d?d?d?d → ?d?d?d?d?d?d?d?d?d → ?d?d?d?d?d?d?d?d?d?d
 */
export declare function incrementalMaskGenerator(charsetCode?: string, minLength?: number, maxLength?: number, options?: MaskOptions): Generator<string>;
/**
 * Hybrid attack: prepend/append wordlist entries with mask-generated parts.
 * Mode 6: wordlist + mask (word + maskPattern)
 * Mode 7: mask + wordlist (maskPattern + word)
 */
export declare function hybridGenerator(words: Iterable<string>, mask: string, mode?: 'append' | 'prepend', options?: MaskOptions): Generator<string>;
/**
 * Combinatory attack: word1 + word2 from two wordlists.
 */
export declare function combinatoryGenerator(words1: string[], words2: string[]): Generator<string>;
export interface MaskInfo {
    mask: string;
    length: number;
    keyspace: bigint;
    keyspaceStr: string;
    positions: string[];
}
export declare function getMaskInfo(mask: string, options?: MaskOptions): MaskInfo;
//# sourceMappingURL=mask-generator.d.ts.map