/**
 * Universal Cracker Types
 *
 * Common interface for all format-specific password crackers.
 * Each format implements CrackerPlugin to enable auto-detection,
 * parameter extraction, and password verification.
 */
export interface CrackerParams {
    /** Format identifier (e.g., 'metamask', 'zip', 'pdf') */
    type: string;
    /** All other fields are format-specific */
    [key: string]: unknown;
}
export interface FormatInfo {
    format: string;
    description: string;
    kdf: string;
    cipher: string;
    iterations?: number;
    difficulty: 'easy' | 'medium' | 'hard' | 'extreme';
    estimatedSpeed?: string;
}
export interface CrackerPlugin {
    /** Unique identifier */
    readonly id: string;
    /** Human-readable name */
    readonly name: string;
    /** Short description */
    readonly description: string;
    /** Supported file extensions (lowercase with dot) */
    readonly fileExtensions: string[];
    /**
     * Detect if a file matches this format.
     * Should be fast — check magic bytes and/or extension.
     */
    detect(filePath: string): Promise<boolean>;
    /**
     * Parse the file and extract crypto parameters needed for cracking.
     * Returns JSON-serializable params that can be sent to workers.
     */
    parse(filePath: string): Promise<CrackerParams>;
    /**
     * Try a single password against the extracted parameters.
     * Returns true if the password is correct.
     */
    tryPassword(password: string, params: CrackerParams): Promise<boolean>;
    /**
     * Get human-readable info about the parsed parameters.
     */
    getInfo(params: CrackerParams): FormatInfo;
}
export interface TryResult {
    success: boolean;
    /** Decrypted content (if applicable, e.g., seed phrase) */
    raw?: string;
}
//# sourceMappingURL=types.d.ts.map