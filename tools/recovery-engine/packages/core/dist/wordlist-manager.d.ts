/**
 * Wordlist Manager
 *
 * Downloads, indexes, and manages popular wordlists for password cracking.
 * Supports streaming large files without loading entirely into memory.
 *
 * Built-in wordlists:
 * - RockYou (14.3M passwords)
 * - SecLists common passwords (various sizes)
 * - CrackStation (real-world)
 * - Custom user wordlists
 */
export interface WordlistInfo {
    id: string;
    name: string;
    description: string;
    url: string;
    compressed: boolean;
    estimatedSize: string;
    estimatedLines: number;
    localPath?: string;
    downloaded: boolean;
}
export interface WordlistManagerOptions {
    /** Directory to store wordlists (default: ~/.mm-recovery/wordlists/) */
    directory?: string;
}
export declare class WordlistManager {
    private dir;
    constructor(options?: WordlistManagerOptions);
    /**
     * List all available wordlists (built-in + downloaded).
     */
    list(): WordlistInfo[];
    /**
     * Download a wordlist by ID.
     */
    download(id: string, onProgress?: (pct: number, msg: string) => void): Promise<string>;
    /**
     * Stream passwords from a wordlist file (memory-efficient).
     * Handles plain text and .gz files.
     */
    streamWords(idOrPath: string): AsyncGenerator<string>;
    /**
     * Load a wordlist into memory (for small/medium lists).
     */
    loadWords(idOrPath: string, minLength?: number): Promise<string[]>;
    /**
     * Stream words in batches (for worker distribution).
     */
    streamBatches(idOrPath: string, batchSize?: number, minLength?: number): AsyncGenerator<string[]>;
    /**
     * Count lines in a wordlist file.
     */
    countWords(idOrPath: string): Promise<number>;
    /**
     * Get the storage directory path.
     */
    getDirectory(): string;
    /**
     * Download all built-in wordlists.
     */
    downloadAll(onProgress?: (id: string, pct: number, msg: string) => void): Promise<void>;
}
//# sourceMappingURL=wordlist-manager.d.ts.map